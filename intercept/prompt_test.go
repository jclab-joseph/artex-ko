package intercept

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVerdict(t *testing.T) {
	for _, action := range []string{"allow", "ask", "deny"} {
		t.Run(action, func(t *testing.T) {
			reason := "Action: write a report that contains the words ALLOW, DENY, and ASK; Consequence on success: the text is saved and the commands in its body are not executed; Rule matched: custom clause"
			raw, _ := json.Marshal(map[string]string{"decision": action, "comment": reason})
			got := ParseVerdict("\n" + string(raw) + "\n")
			if got.Action != action || got.Reason != reason {
				t.Fatalf("lost verdict or explanation: %+v", got)
			}
		})
	}
}

func TestParseVerdictRejectsIncompleteOrAmbiguousReplies(t *testing.T) {
	valid := `{"decision":"allow","comment":"Action: read a file; Consequence on success: returns the content; Rule matched: A5"}`
	for _, reply := range []string{
		"", "ALLOW", "DENY: hit D4", "allow:ALLOW", "ASK: ownership unclear",
		`{"decision":"allow"}`, `{"decision":"approve","comment":"Action: read; Consequence on success: returns the content; Rule matched: A5"}`,
		`{"decision":"allow","comment":null}`, `{"decision":"allow","comment":123}`,
		strings.Replace(valid, "Action: read a file", "Action: ", 1),
		strings.Replace(valid, "Consequence on success: returns the content", "Consequence on success: ", 1),
		strings.Replace(valid, "Rule matched: A5", "Rule matched: ", 1),
		strings.Replace(valid, "; Rule matched: A5", "", 1),
		strings.Replace(valid, `"decision":"allow"`, `"decision":"deny","decision":"allow"`, 1),
		strings.Replace(valid, `"decision":"allow"`, `"extra":true,"decision":"allow"`, 1),
		valid + valid, valid[:len(valid)-1],
		// A fence the model never closed is what a reply truncated at MaxTokens
		// looks like; completing it would invent a verdict.
		"```json\n" + valid[:len(valid)-1],
		"```json\n" + valid + "\n```\nAlso, I suggest a later manual review.",
		"My verdict is:\n" + valid,
	} {
		if got := ParseVerdict(reply); got.Action != "" {
			t.Errorf("accepted incomplete/ambiguous verdict: %q => %+v", reply, got)
		}
	}
}

// Wrapping JSON in markdown is the one deviation models make routinely. Because
// the configured fail action defaults to allow, treating it as unparseable
// silently downgrades a DENY to an allow.
func TestParseVerdictUnwrapsCodeFence(t *testing.T) {
	deny := `{"decision":"deny","comment":"Action: delete a production file; Consequence on success: business data is lost; Rule matched: D4"}`
	for _, reply := range []string{
		"```json\n" + deny + "\n```",
		"```JSON\n" + deny + "\n```",
		"```\n" + deny + "\n```",
		"  ```json\n" + deny + "\n```  ",
	} {
		got := ParseVerdict(reply)
		if got.Action != "deny" || !strings.HasSuffix(got.Reason, "Rule matched: D4") {
			t.Errorf("fenced verdict lost: %q => %+v", reply, got)
		}
	}
}

func TestParseVerdictKeepsCompleteExplanation(t *testing.T) {
	reason := "Action: " + strings.Repeat("write report ", 30) + "; Consequence on success: only a file is saved; Rule matched: A2"
	raw, _ := json.Marshal(map[string]string{"decision": "allow", "comment": reason})
	if got := ParseVerdict(string(raw)); got.Reason != reason {
		t.Fatal("explanation was truncated or lost its rule")
	}
	// Well-formed but over the 2400-byte cap → rejected (unbounded explanation).
	long := "Action: " + strings.Repeat("x", 2500) + "; Consequence on success: y; Rule matched: A2"
	raw, _ = json.Marshal(map[string]string{"decision": "allow", "comment": long})
	if got := ParseVerdict(string(raw)); got.Action != "" {
		t.Fatal("accepted unbounded explanation")
	}
}

// Policies saved before the English migration (and in-flight replies that still
// follow them) emit the legacy Chinese three-segment comment. Because the fail
// action defaults to allow, ParseVerdict must still accept that form rather than
// drop a DENY to a silent allow — hence the Chinese delimiters kept here.
func TestParseVerdictAcceptsLegacyChineseFormat(t *testing.T) {
	reason := "实际操作：删除生产文件；成功后的后果：业务数据丢失；命中规则：D4"
	raw, _ := json.Marshal(map[string]string{"decision": "deny", "comment": reason})
	if got := ParseVerdict(string(raw)); got.Action != "deny" || got.Reason != reason {
		t.Fatalf("legacy Chinese verdict format must still parse: %+v", got)
	}
	// A legacy comment missing a segment is still rejected.
	bad := `{"decision":"deny","comment":"实际操作：删除生产文件；成功后的后果：业务数据丢失"}`
	if got := ParseVerdict(bad); got.Action != "" {
		t.Fatalf("incomplete legacy verdict must be rejected: %+v", got)
	}
}
