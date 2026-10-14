package notify

import (
	"fmt"
	"strings"
)

// This file is the shared message rendering for the "Markdown family" channels (DingTalk, WeCom).
// Feishu uses card JSON, Telegram uses HTML, and email uses HTML, each rendered in its own adapter.

// maxAssetsShown is the maximum number of assets listed in a message. A finding may anchor dozens of assets,
// and listing them all would overflow the message with no informational value — no one reads domains past the fourth in an IM.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. An IM message is a "prompt to go check the details",
// not the report itself; the full content is on the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message header (digest line + severity distribution + possible truncation notice)
// and footer (platform link). When packing whole items, this amount is deducted from the budget so the header and footer are never cut off —
// once they are cut, the reader cannot even tell "which batch this is, or how many items are not shown".
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why it is required: the finding title, summary, type, and asset display names all come from **untrusted sources** —
// the title and summary come from model output (the model reads the responses of the target under test), while the asset url is the full URL obtained
// by scanning (including a query string the target controls). Without escaping, a finding with the title
//
//	Login SQLi\n[URGENT: click here to verify your account](http://attacker.tld)
//
// would render as a **clickable external link** in a security engineer's DingTalk/Feishu; and
// `![](http://attacker.tld/beacon)` would be fetched by the client at render time, which amounts to signaling
// "this finding has already been seen" and leaking the reader's IP. Even with non-malicious content, an injected bold or
// quote block can push the critical finding below out past the fold.
//
// The escape set covers the categories — heading/link/emphasis/list/quote/strikethrough — that change structure or produce clickable
// elements. `\` must be handled first, otherwise it would re-escape the backslashes added afterwards.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText collapses untrusted text into a single line and escapes it, for use in markdown body.
// Single-lining is the other half besides escaping: a newline itself can forge a new list item or quote block,
// which escaping characters cannot stop.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (the IM platform's title bar / card title), whose content is the **unescaped raw text**.
//
// Escaping is deliberately not done here: this title is shared by renderers in four contexts — markdown body, Telegram's
// HTML, the Feishu card's plain_text, and the generic Webhook's JSON and email subject. Each context's
// escaping rules differ (markdown escaping stuffed into HTML leaves visible backslashes, stuffed into JSON it pollutes
// the data), so escaping must be the responsibility of each output end, see writeItem / feishuItemLines /
// telegramEscape. Markdown escaping was once added in the shared function, and as a result Telegram messages
// showed visible backslashes like `\(1\)`.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("취약점 요약 · 총 %d건", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "취약점 알림"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody renders the message body, returning the body and the **number of items actually written**.
//
// The return value kept is the number of items this delivery actually sent, so the caller marks only the first kept items as
// delivered — items kept out by the channel's length limit must wait for the next batch, not be marked
// as successful along with the rest. This is exactly the source of "silent loss": the message was truncated, but the delivery record shows everything delivered,
// with nowhere to notice that the latter half was never sent.
//
// maxBytes<=0 means no limit.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single message is sent even if oversized (backstopped by the final truncation): partial information about one finding
		// is better than sending nothing at all.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[플랫폼에서 전체 보기](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders the start of a digest message: time window, count, and severity distribution.
// With these, whoever receives the digest can judge whether this batch needs immediate attention without clicking into the platform.
//
// items are the items **actually packed**, and total is the total this batch should have. When they differ it must say explicitly
// "how many more items are in the next message" — otherwise the reader assumes the number in the message header is the whole lot,
// while those items that were never sent simply do not exist in the UI.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**최근 %d분간 신규 취약점 %d건**", m.WindowMinutes, total)
	} else {
		fmt.Fprintf(&b, "**신규 취약점 %d건**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, "(이 메시지에는 앞 %d건만 표시하며, 나머지 %d건은 다음 메시지에서 이어서 보냅니다)", len(items), extra)
	}
	// Give the distribution by severity so the reader sees at a glance whether there are critical items. It counts only the items **actually included in this message**,
	// guaranteeing "Critical 3" matches the items countable below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single finding item.
//
// prefix is used for the sequence number in the digest list; when single=true it renders the full version (with summary and back-link),
// while the digest list renders only a one-line summary — otherwise a 50-item digest would become a long document.
//
// All externally sourced content (title/type/asset/summary) goes through markdownText:
// single-lining + escaping. The back-link is built from the admin-configured public_base_url, which is not untrusted content,
// and must be a clickable link, so it is output as-is.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Digest mode: presented on a single line, with the asset and summary compressed and appended.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**상태 변경**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**유형**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**자산**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**개요**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[상세 보기](%s)\n", it.DetailURL)
	}
}
