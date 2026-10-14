package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateBytesKeepsValidUTF8(t *testing.T) {
	// This is the most important invariant in the package. WeCom limits by **byte**, and a Korean syllable is 3 bytes,
	// so any implementation that cuts hard by byte would cut a syllable in half, producing invalid UTF-8 that the platform rejects.
	// Use various Korean-English mixed inputs of coprime lengths to hit every possible cut point.
	inputs := []string{
		"한국어가나다",
		"혼합 mixed 내용 content",
		"a한b글c다d라e",
		"🔴🟠🟡🔵", // 4-byte emoji, a wrong cut is more obvious
		strings.Repeat("한글", 100),
	}
	for _, in := range inputs {
		for max := 1; max <= len(in)+2; max++ {
			got := TruncateBytes(in, max)
			if !utf8.ValidString(got) {
				t.Fatalf("input %q max=%d: produced invalid UTF-8 %q", in, max, got)
			}
			if len(got) > max {
				t.Fatalf("input %q max=%d: result %d bytes exceeds the limit", in, max, len(got))
			}
			// When not truncated, the content must not be altered.
			if len(in) <= max && got != in {
				t.Fatalf("input %q max=%d: not over the limit yet content changed -> %q", in, max, got)
			}
		}
	}
}

func TestTruncateBytesZeroMeansUnlimited(t *testing.T) {
	long := strings.Repeat("x", 10000)
	if got := TruncateBytes(long, 0); got != long {
		t.Fatal("max=0 should mean unlimited")
	}
	if got := TruncateBytes(long, -5); got != long {
		t.Fatal("max<0 should mean unlimited")
	}
}

func TestTruncateBytesEllipsisBudget(t *testing.T) {
	// When max is smaller than the ellipsis itself, appending the ellipsis must not push it over the limit.
	got := TruncateBytes("abcdefgh", 1)
	if len(got) > 1 {
		t.Fatalf("at max=1 the result %q is %d long, over the limit", got, len(got))
	}
	// In the normal case an ellipsis should be present.
	if got := TruncateBytes("abcdefgh", 5); !strings.HasSuffix(got, ellipsis) {
		t.Fatalf("expected an ellipsis, got %q", got)
	}
}

func TestTruncateRunesCountsCharactersNotBytes(t *testing.T) {
	// The unit difference from TruncateBytes must be preserved: Telegram limits by character,
	// and a byte-based unit would cut a Korean message down to a third.
	s := "일이삼사오육칠팔구십"
	got := TruncateRunes(s, 5)
	if n := utf8.RuneCountInString(got); n != 5 {
		t.Fatalf("expected 5 characters, got %d (%q)", n, got)
	}
	// The same string under the byte unit should be noticeably shorter.
	if utf8.RuneCountInString(TruncateBytes(s, 5)) >= 5 {
		t.Fatal("the byte unit should not produce the same character count as the rune unit")
	}
}

func TestOneLineCollapsesWhitespace(t *testing.T) {
	got := OneLine("line one\n\nline two\twith-tab   multi-space", 0)
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("all whitespace should be folded, got %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Fatalf("consecutive spaces should not be kept, got %q", got)
	}
	// After truncation it must still be readable and valid.
	got = OneLine("일이삼사오육칠팔구십", 4)
	if n := utf8.RuneCountInString(got); n != 4 {
		t.Fatalf("expected 4 characters, got %d (%q)", n, got)
	}
}

func TestTruncateHTMLNeverCutsTagInHalf(t *testing.T) {
	// Truncating HTML directly can cut out a fragment like `<a href="htt`, and the platform rejects the whole message.
	s := `<b>Title</b>bodybodybody<a href="https://example.com/very/long/path">View details</a>`
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		if n := utf8.RuneCountInString(got); max > 0 && n > max {
			t.Fatalf("max=%d: result %d characters over the limit", max, n)
		}
		// The tail must not have an unclosed `<` (i.e. a `<` with no `>` in the last segment).
		if lt := strings.LastIndex(got, "<"); lt >= 0 && !strings.Contains(got[lt:], ">") {
			t.Fatalf("max=%d: tail tag was cut off -> %q", max, got)
		}
	}
}

func TestAssetLineOmitsExcess(t *testing.T) {
	if got := assetLine(nil, 3); got != "" {
		t.Fatalf("no assets should return an empty string, got %q", got)
	}
	if got := assetLine([]string{"a", "b"}, 3); got != "a, b" {
		t.Fatalf("under the limit everything should be listed, got %q", got)
	}
	// When over the limit the total must be noted, otherwise the reader does not know how many assets were not listed.
	got := assetLine([]string{"a", "b", "c", "d", "e"}, 2)
	if !strings.Contains(got, "등 5개") {
		t.Fatalf("should note the total 5, got %q", got)
	}
}

func TestSeverityAndStatusLabels(t *testing.T) {
	if AtLeast("", "low") {
		t.Fatal("an empty severity has ordinal 0 and should be blocked by any threshold")
	}
	if !AtLeast("critical", "") {
		t.Fatal("an empty threshold should let everything through")
	}
	if got := StatusLabel("fixed"); got != "수정됨" {
		t.Fatalf("status label mapping is wrong, got %q", got)
	}
	// An unknown status is echoed back as-is, no fabricated label.
	if got := StatusLabel("weird_status"); got != "weird_status" {
		t.Fatalf("an unknown status should be echoed back as-is, got %q", got)
	}
}

// TestTruncateHTMLNeverCutsEntity covers an omission the audit pointed out: truncation must not only avoid
// a half-cut tag, but also a cut-off HTML entity.
//
// After `&amp;` is cut to `&amp`, a strict entity-only parser may reject the **whole** message —
// and an overly long digest message is common anyway, so the cost is too high.
func TestTruncateHTMLNeverCutsEntity(t *testing.T) {
	s := "aaaa&amp;bbbb&lt;cccc&quot;dddd"
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		// The tail must not contain an entity fragment with "a & but no matching ;".
		if amp := strings.LastIndex(got, "&"); amp >= 0 && !strings.Contains(got[amp:], ";") {
			t.Fatalf("max=%d: an entity fragment %q was left at the tail", max, got[amp:])
		}
		if strings.Contains(got, "&amp\x00") {
			t.Fatalf("max=%d: a malformed entity appeared", max)
		}
	}
}
