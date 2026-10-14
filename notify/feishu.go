package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// feishuChannel implements the Feishu (incl. Lark) custom bot, using interactive cards.
//
// Platform traits:
//   - The signing algorithm **differs** from DingTalk's and is extremely easy to get wrong, see the feishuSign comment.
//   - Like DingTalk, it stuffs business errors into the body of an HTTP 200 (code != 0).
//   - The card header supports a color template, mapping severity to color so severity is visible at a glance in the message list.
type feishuChannel struct{}

func (feishuChannel) Kind() string { return KindFeishu }

// A Feishu custom bot allows about 5 requests/second, which is 100 requests/minute.
func (feishuChannel) DefaultRatePerMin() int { return 100 }

// The last segment of the Webhook address is the bot's unique identifier, which is a credential.
func (feishuChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// Likewise: changing the Webhook address requires re-declaring the signing secret for the new address.
func (feishuChannel) DestinationKeys() []string { return []string{"webhook"} }

func (feishuChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook 주소가 없습니다")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 주소가 올바르지 않습니다: %w", err)
	}
	return nil
}

func (c feishuChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	card, kept := feishuCard(m)
	payload := map[string]any{
		"msg_type": "interactive",
		"card":     card,
	}
	// The signing parameters are at the same level as the message, and appear only when a secret is configured.
	if secret := cfgString(cfg, "secret"); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		// Some versions of the Feishu hook use this set of field names, supported here as well.
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Feishu 응답을 해석하지 못했습니다: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return 0, Permanent(fmt.Errorf("Feishu에서 오류가 발생했습니다 (%d): %s", res.Code, res.Msg))
	}
	if res.StatusCode != 0 {
		return 0, Permanent(fmt.Errorf("Feishu에서 오류가 발생했습니다 (%d): %s", res.StatusCode, res.StatusMessage))
	}
	return kept, nil
}

// feishuSign computes the signature per Feishu's official rules.
//
// This is especially easy to trip over: the official sample is
//
//	hmac.new(string_to_sign.encode(), digestmod=sha256)
//
// that is, **key = timestamp + "\n" + secret, and message is empty**, rather than the intuitive
// "key=secret, message=stringToSign" — which is exactly DingTalk's algorithm. The two algorithms are precisely reversed,
// so copying the other's implementation inevitably fails signature verification (reporting 19021).
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// feishuSeverityTemplate maps a finding severity to the card header's color template.
// An unknown severity uses grey — not blue, to avoid confusion with low.
func feishuSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "grey"
	}
}

// feishuMaxCardBytes is a conservative cap on card content. Feishu has a size limit on cards, and exceeding it rejects the whole message;
// a value clearly below the official limit is chosen, also accounting for the JSON wrapper overhead.
const feishuMaxCardBytes = 24000

// feishuCard builds the interactive card, returning the card and the **number of items actually written**.
// kept serves the same purpose as in markdownBody: only items that actually made it into the card should be marked as delivered.
func feishuCard(m Message) (map[string]any, int) {
	elements := []any{}
	kept := 0
	if m.Batch {
		// Pack whole items first, then assemble the header: the header must say "the remaining N items continue in the next message",
		// where N must come from the count actually packed.
		kept = packItemCount(m.Items, feishuMaxCardBytes, markdownReservedBytes, "", byteSize, func(it Item, idx int) string {
			return feishuBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		elements = append(elements, feishuMarkdownDiv(markdownBatchIntro(m, items, len(m.Items))))
		for i, it := range items {
			elements = append(elements, feishuMarkdownDiv(feishuBatchLine(it, i+1)))
		}
		if m.HomeURL != "" {
			elements = append(elements, feishuButton("플랫폼에서 전체 보기", m.HomeURL))
		}
	} else if len(m.Items) > 0 {
		kept = 1
		it := m.Items[0]
		elements = append(elements, feishuMarkdownDiv(feishuItemLines(it)))
		if it.DetailURL != "" {
			elements = append(elements, feishuButton("상세 보기", it.DetailURL))
		}
	}

	card := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"title": map[string]any{"tag": "plain_text", "content": markdownTitle(m)}},
		"elements": elements,
	}
	if len(m.Items) > 0 {
		card["header"].(map[string]any)["template"] = feishuSeverityTemplate(m.Items[0].Severity)
	}
	return card, kept
}

func feishuMarkdownDiv(content string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": content}}
}

func feishuButton(label, url string) map[string]any {
	return map[string]any{
		"tag": "action",
		"actions": []any{map[string]any{
			"tag":  "button",
			"text": map[string]any{"tag": "lark_md", "content": label},
			"url":  url,
			"type": "primary",
		}},
	}
}

// feishuItemLines renders the lark_md body for a single finding.
//
// lark_md and markdown are same-family text formats that also parse links and emphasis, so externally sourced
// fields all go through markdownText (single-lining + escaping) — otherwise a single finding title could become
// a clickable external link in Feishu.
func feishuItemLines(it Item) string {
	out := fmt.Sprintf("**%s · %s**", SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if it.IsStatusChange() {
		out += fmt.Sprintf("\n**상태 변경**: %s → %s",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		out += fmt.Sprintf("\n**유형**: %s", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		out += fmt.Sprintf("\n**자산**: %s", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			out += fmt.Sprintf("\n**개요**: %s", s)
		}
	}
	return out
}

// feishuBatchLine renders one item in the digest card.
func feishuBatchLine(it Item, index int) string {
	line := fmt.Sprintf("**%d. %s · %s**", index, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		line += " — " + markdownText(a, 0)
	}
	return line
}
