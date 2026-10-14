package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes truncates s to at most max bytes, guaranteeing the result is valid UTF-8 and does not cut a character in half.
//
// Why it must cut on a character boundary: the WeCom group bot's markdown has a hard limit of 4096 **bytes** (not
// characters), while a Chinese character is 3 bytes. Slicing directly by byte would cut a Han character in half, producing invalid
// UTF-8 — the platform either rejects the whole message or shows garbled boxes. The approach here is to back off from the budget position
// to the nearest rune start byte (utf8.RuneStart detects continuation bytes 0b10xxxxxx).
//
// max<=0 means no limit. An ellipsis is appended after truncation, unless max is too small to hold the ellipsis.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max is shorter than the ellipsis: drop the ellipsis and truncate plainly, to avoid the result exceeding max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine collapses multi-line text into a single line: it folds all whitespace, then truncates by character count.
// Used for the title line of IM messages — summaries often contain newlines, which would break the layout of a table/title if inserted directly.
// max<=0 means no length limit.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes truncates s to at most max characters (not bytes), appending an ellipsis when it exceeds.
// max<=0 means no limit.
//
// The difference from TruncateBytes is the platform's unit: WeCom limits by byte, Telegram limits by character count.
// Using the wrong unit does not error; it just cuts the message far shorter than expected (a Chinese character = 3 bytes,
// so a 4096-byte cut leaves only about 1365 characters), so both functions must be kept and chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count while guaranteeing it does not produce a half-cut tag.
//
// Truncating HTML by character directly can cut out a broken tag like `<a href="htt`; the platform parser either
// errors and rejects the whole message, or swallows the following body as an attribute value. The approach here: truncate by character first,
// then check whether the tail has an unclosed `<`, and if so back off to before it.
//
// It does not balance tags (completing things like </b>): Telegram's HTML parser auto-closes unclosed tags,
// whereas implementing balancing ourselves would have to handle quotes in attributes, comments, and self-closing tags — complexity out of proportion to the benefit.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a fragment starting with `<` (no `>` after the last `<`), back off to before the `<`.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// If the tail is a cut-off HTML entity (e.g. `&amp;` cut to `&amp`), back off as well.
	// An entity fragment can cause the **whole message** to be rejected by a strict entity-only parser — a digest message exceeding
	// the length limit is common anyway, and it is not worth dropping the entire notification over.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount computes how many items fit **completely** within the budget, so a digest message packs whole items.
//
// Why pack whole items instead of rendering everything and then truncating: truncation makes the latter items vanish into thin air,
// while their delivery records are still marked as delivered — invisible in the message, invisible in the delivery history,
// and the findings are just gone. After packing whole items, the ones that do not fit stay in the database as the next batch,
// and the kept the caller receives is the number of items this message actually delivered.
//
// Parameters: maxSize<=0 means no limit; reserve is the amount reserved for the message header/footer;
// size does the measuring (platforms differ: WeCom/DingTalk by byte, Telegram by character count —
// using the wrong unit does not error, it just compresses a Chinese message to far below the limit);
// render turns item idx into its actual text — the length varies by content and cannot be estimated.
//
// Returns at least 1 (as long as there are items). An extremely long single item must still be sent, backstopped by the caller's
// final truncation, otherwise one oversized finding would permanently jam the whole batch in place.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are the two measuring units for packItemCount, named out to avoid
// a bare func(s string) int closure at the call site, which would make the unit hard to tell at a glance.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list into a single display line, omitting the rest and noting the total when it exceeds limit.
// A finding may anchor dozens of assets, and listing them all would overflow the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " 등 " + itoa(len(assets)) + "개"
}

// itoa is a short alias for strconv.Itoa, used only to build display text, avoiding importing strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
