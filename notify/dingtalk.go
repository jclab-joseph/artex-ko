package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom bot.
//
// Platform traits (which drive the implementation trade-offs here):
//   - A single bot is rate-limited to 20 messages/minute; over-sending is silently dropped (HTTP may still be 200),
//     so rate limiting must be done on the client, see DefaultRatePerMin.
//   - Security setting is one of three: signing / custom keyword / IP whitelist. Signing is the only one that does not depend
//     on message content, so only signing is supported (a bare webhook with none of the three enabled is also supported).
//   - Both success and failure return HTTP 200, distinguished by the errcode in the body — not checking errcode
//     records a delivery failure as a success.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// DingTalk's Webhook address carries an access_token and is itself a credential, so it is masked as a whole.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The destination is DingTalk's Webhook address itself; changing the address requires re-declaring the signing secret for the new address.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook 주소가 없습니다")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 주소가 올바르지 않습니다: %w", err)
	}
	return nil
}

// Send delivers one message. For a single item with a back-link it uses an ActionCard (with a button), otherwise markdown.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// DingTalk's markdown body has no explicit byte limit, but a cap is still applied to prevent evidence fields from ballooning abnormally.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "상세 보기",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk hides business errors inside a 200 response.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("DingTalk 응답을 해석하지 못했습니다: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 is a signature verification failure, 310000 is a keyword mismatch — both are config errors,
		// which retrying will not heal.
		return 0, Permanent(fmt.Errorf("DingTalk에서 오류가 발생했습니다 (%d): %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends timestamp and sign parameters to the webhook per the official signing rules.
//
// Rule: the string to sign = timestamp + "\n" + secret, and the HMAC-SHA256 **key is also secret**,
// with the result base64-encoded then URL-encoded. timestamp is in milliseconds. When secret is empty it is returned as-is,
// to support a bot without signing enabled.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Do not pass err through: url.Parse's error text carries the full address (including access_token).
		return "", fmt.Errorf("Webhook 주소를 해석하지 못했습니다: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks the address is usable, the scheme is supported, and performs an internal-network check for a literal IP target.
//
// Two points of care:
//
//  1. **Error messages must be redacted**. url.Parse itself returns a *url.Error whose Error() carries
//     the **full original address**, and the addresses of these platforms embed credentials (DingTalk access_token,
//     WeCom key, Telegram bot token, Feishu hook id). This once did `return err` directly,
//     so the "invalid address format" error carried credentials out, flowing to the test endpoint's 400 response,
//     the last_error persisted on each delivery, the server logs, and the delivery-history endpoint.
//
//  2. **A literal IP is judged internal directly**, while domains are left to the dial stage (blockInternalDial is the final
//     enforcement point, and also covers DNS rebinding). Doing it once here is to give feedback at config-save time,
//     rather than waiting for the first delivery to fail.
//
// Restricting the scheme is defensive: things like file:///gopher:// would make http.Client behave unexpectedly
// (already blocked by the scheme check, but there is no reason to open up this surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("주소를 해석할 수 없습니다 (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("http 또는 https 만 지원합니다. 받은 값: %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("호스트 이름이 없습니다")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("로컬 또는 링크 로컬 주소 %s 로는 전송하지 않습니다 (로컬 서비스로 보내야 하면 %s=1 로 설정하세요)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
