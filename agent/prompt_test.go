package agent

import (
	"strings"
	"testing"
)

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "goal:{{.Goal}} scope:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "pwnX", Scope: "*.x.com"}); got != "goal:pwnX scope:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (intermediate-artifact output spec) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("pwnX", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER pwnX") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "Intermediate-artifact output spec") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}via-proxy {{.ProxyAddr}}{{else}}manual{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data", false)
	if !strings.HasPrefix(recording, "via-proxy 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "Intermediate-artifact output spec") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data", false)
	if !strings.HasPrefix(egressOnly, "via-proxy 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	// Split mode: no local MITM CA, but the sandbox Agent hosts the recorder and the
	// traffic_* tools are injected — the explicit recording flag must surface the note.
	splitRecording := workerSystem("", "", "/data", "/data", true)
	if !strings.Contains(splitRecording, "traffic_search") {
		t.Fatalf("worker recording in split mode must inject trafficTool: %q", splitRecording)
	}
	noProxy := workerSystem("", "", "/data", "/data", false)
	if !strings.HasPrefix(noProxy, "manual") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}

// langMarker is the unambiguous substring that proves langDirective selected a
// given display language. These are the native-script tokens embedded in the
// directive, so finding one means the output-language mandate names that language.
// Used by the directive and role-append tests below.
var langMarker = map[string]string{
	"ko": "한국어",
	"en": "English",
	"zh": "简体中文",
	"es": "Español",
	"ja": "日本語",
}

// TestLangDirectiveLocalized pins the output-language tail across all
// supported display languages: each language's directive names that language, preserves
// raw technical strings, forbids mirroring the target/material language, and names
// the planner situation summary. For every non-Chinese display language the "never
// emit another language to the user" clause is present; for Chinese it is absent (Chinese
// output is the goal there).
func TestLangDirectiveLocalized(t *testing.T) {
	for _, code := range SupportedOutputLangs {
		dir := langDirective(code)
		if !strings.Contains(dir, langMarker[code]) {
			t.Fatalf("%s: langDirective must name the display language (%q), got %q", code, langMarker[code], dir)
		}
		if !strings.Contains(dir, "payload") || !strings.Contains(dir, "kept verbatim") {
			t.Fatalf("%s: langDirective must keep commands/payloads verbatim, got %q", code, dir)
		}
		if !strings.Contains(dir, "do not mirror or copy the target") {
			t.Fatalf("%s: langDirective must forbid mirroring the target/material language, got %q", code, dir)
		}
		if !strings.Contains(dir, "situation summary") {
			t.Fatalf("%s: langDirective must name the planner situation summary as user-facing, got %q", code, dir)
		}
		// The anti-leak clause (forbidding any other language in user-visible text)
		// applies to every non-Chinese display language (planner situation-summary
		// drift). When the display language IS Chinese, Chinese output is correct, so
		// the clause must be absent.
		hasNoOtherLangClause := strings.Contains(dir, "do not let text in any other language appear")
		if code == "zh" && hasNoOtherLangClause {
			t.Fatalf("zh: directive must NOT forbid Chinese output when the display language is Chinese, got %q", dir)
		}
		if code != "zh" && !hasNoOtherLangClause {
			t.Fatalf("%s: langDirective must forbid leaking another language to the user, got %q", code, dir)
		}
	}
}

// TestLangDirectiveAppendedToUserFacingRoles pins the localization tail wiring:
// every user-facing role's system prompt must end with the code-owned
// output-language directive in the configured language, and a DB-edited body must
// NOT be able to drop it. Exercised for each supported display language by driving
// the OutputLanguage hook the roles resolve through.
func TestLangDirectiveAppendedToUserFacingRoles(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil; OutputLanguage = nil })

	// Even with a DB body that is pure non-directive text, the code-owned tail is
	// still appended for each user-facing builder — identical guarantee to the
	// artifact tail. A custom body can never translate away the output-language mandate.
	PromptOverride = func(string) (string, bool) { return "BODY-ONLY", true }

	for _, code := range SupportedOutputLangs {
		OutputLanguage = func() string { return code }
		marker := langMarker[code]
		cases := map[string]string{
			"worker":    workerSystem("", "", "/data", "/data", false),
			"planner":   plannerSystem("g", "/data", "/data"),
			"mainagent": mainAgentSystem("g", "/data", "/data"),
			"chat":      chatSystem("chat", "/data", "/data"),
			// goals is user-facing too: set_goals/set_constraints persist goal and
			// constraint nodes shown in the UI graph/plan tab. withScope=true exercises
			// the longer assembly (body + scope tail), so the language tail must still
			// land last — after both the body and the code-owned scope tail.
			"goals": goalsSystem("/data", true),
		}
		for role, sys := range cases {
			if !strings.HasPrefix(sys, "BODY-ONLY") {
				t.Fatalf("%s/%s: DB body not honored: %q", code, role, sys)
			}
			if !strings.Contains(sys, marker) {
				t.Fatalf("%s/%s: missing output-language tail (%q): %q", code, role, marker, sys)
			}
			// The directive is the tail — it must come AFTER the body (recency).
			if strings.Index(sys, marker) <= strings.Index(sys, "BODY-ONLY") {
				t.Fatalf("%s/%s: langDirective must be appended after the body: %q", code, role, sys)
			}
		}
	}
}
