package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets decides whether messages may be delivered to loopback / link-local addresses.
//
// Denied by default. These address ranges are not where IM bots or public mail servers appear, yet what they can
// reach is sensitive: the admin port of another service on the same host, and the cloud metadata endpoint
// (169.254.169.254, from which instance credentials can be read). The delivery address is set by an admin, but an admin session hijacked by XSS/CSRF,
// or a second person sharing the same JWT, could read response content back by editing the config
// — doJSON writes the first 200 bytes of a 4xx/5xx response body into last_error, and the delivery-history endpoint
// echoes it back, which is a semi-blind read primitive.
//
// But a "local SMTP relay" (postfix on 127.0.0.1:25) is a common self-hosted-mail setup,
// and a blanket ban would get in the way. So an explicit escape hatch is left instead of a hardcoded allow:
// setting ARTEX_NOTIFY_ALLOW_LOCAL=1 allows it.
//
// It is exported as AllowLocalTargetsEnv so tests can explicitly turn it on — the tests in this package and the server package
// make heavy use of httptest fake receivers on 127.0.0.1, which the guard would otherwise block entirely.
const AllowLocalTargetsEnv = "ARTEX_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether the target IP belongs to the "disallowed by default" address ranges.
//
// It only rejects loopback, link-local (including the cloud metadata 169.254.169.254), unspecified, and multicast.
// It does **not** reject RFC1918 private networks: an in-network self-hosted Mattermost / SMTP relay is a very common legitimate use,
// and blocking those too would make the feature outright unusable in real environments. This trade-off is deliberate —
// the protection must block genuinely sensitive targets without also killing normal deployments.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// An IPv4-mapped IPv6 (::ffff:127.0.0.1) must be restored to IPv4 before checking, otherwise it bypasses the check.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the Control hook of the http.Transport dialer, which checks the target address
// **when the connection is established**.
//
// Why it is placed at the dial stage rather than only validating at config-save time: this is the final enforcement point.
// It covers two ways of bypassing config validation at once — DNS rebinding (resolving to a public IP at validation time,
// but to an internal one at actual connection) and redirects (although we already reject cross-host hops, a same-host hop
// can still point the path elsewhere).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("대상 주소를 해석할 수 없습니다: %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("로컬 또는 링크 로컬 주소 %s 로는 전송하지 않습니다 (로컬 서비스로 보내야 하면 %s=1 로 설정하세요)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds only a single dial guard on top of the default Transport.
// It uses Clone to retain all the default tuning (connection pool, HTTP/2, timeouts, proxy, etc.),
// avoiding changes to other behavior just to add one check.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is the client shared by all channel deliveries.
//
// It deliberately does **not** reuse the project's global egress proxy (GlobalProxy on the server side): that proxy is for pentest
// target traffic, often an unstable tunnel, and notification availability should not be held hostage to the target network's jitter.
// IM push can connect directly. The timeout is set to 15 seconds — a peer slower than that is effectively already in a failed state.
//
// Reject cross-host redirects: this feature's delivery addresses are all of the "one fixed endpoint" form and normally do not
// redirect to another host; and these platforms' credentials (DingTalk's access_token, WeCom's key, Telegram's
// bot token) are **right in the URL**, so following a cross-host hop hands the credentials to the redirect target. A same-host
// hop (such as appending a trailing slash) is still allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("리다이렉트가 너무 많습니다")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("다른 호스트로의 리다이렉트는 허용하지 않습니다 (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit caps the size of the response body read. A misbehaving peer may spew back huge content, while we only need
// the error code and a short error description to show in the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the response body (length-limited).
//
// When payload is nil it sends an empty body (for GET or platforms that do not require a body).
// The key-values in headers are attached as-is, for the generic Webhook's custom headers.
//
// Error classification is this function's core responsibility: network-layer failures and 5xx/408/429 are classified as "retryable",
// the other 4xx as "permanent failures" — retrying a 403 only prints the same error to the log three times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A serialization failure is a local bug (wrong config field type) and will not improve on retry.
			return nil, Permanent(fmt.Errorf("요청 본문을 만들지 못했습니다: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// An invalid URL — most likely the user mistyped the address, so it is a permanent failure.
		// Here too err must not be passed through: url.Parse's error text contains the full address.
		return nil, Permanent(fmt.Errorf("요청 주소가 올바르지 않습니다: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, timeout — mostly transient faults, left to backoff retry.
		//
		// The error text must be redacted before being passed out. Reason: http.Client.Do returns a *url.Error,
		// whose Error() is `Op "full-URL": underlying error`, and these platforms' credentials are **right in the URL**
		// (DingTalk access_token, WeCom key, Feishu hook id, Telegram /bot<token>/).
		// Without redaction, credentials would flow along this error string to four places: notification_deliveries'
		// last_error (persisted in plaintext), the delivery-history endpoint's response (**bypassing the channel-config masking**),
		// the server logs, and the 502 text the test-send endpoint returns to the frontend.
		return nil, fmt.Errorf("요청에 실패했습니다: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("응답을 읽지 못했습니다: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limit) and 408 (timeout) are worth retrying; the other 4xx are config or permission problems where retrying is pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("상대 서버가 요청을 제한하거나 응답이 지연되었습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("상대 서버에 오류가 발생했습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("상대 서버가 요청을 거부했습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet collapses the response body into a short single line, for error messages. The response may contain newlines and lots of whitespace,
// which stuffed directly into last_error would break the delivery-history page's layout.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget collapses a delivery address into "scheme://host/…", for error messages.
//
// This is the package's only address-redaction convention, and is deliberately made **brutal enough**: apart from scheme and host,
// everything else is discarded. The reason is that there is no "general and safe" way to tell which part of a URL is a credential:
//
//	DingTalk   credential in query                 /robot/send?access_token=xxx
//	WeCom      credential in query                 /cgi-bin/webhook/send?key=xxx
//	Feishu     credential in the **last path segment** /open-apis/bot/v2/hook/<hook_id>
//	Telegram   credential in the **middle of the path** /bot<token>/sendMessage
//
// Trying to "keep only the useful part" would require per-channel patching, and missing any one of them is a credential leak.
// Keeping the host is already enough for troubleshooting (DNS resolution failures, connection failures, and bad certificates can all be pinned down),
// and which specific bot it is can be identified from the masked trailing digits hinted in the channel config.
//
// On parse failure it returns a fixed placeholder — never echoing the raw string.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(주소를 해석할 수 없음)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the address from a transport-layer error, keeping only the underlying cause.
//
// *url.Error's structure is {Op, URL, Err}, and Error() prints the URL along with it.
// Here the Err field is taken explicitly, bypassing its Error() — more reliable than doing string replacement afterwards,
// because replacement would have to correctly handle all the URL-encoded/escaped variants and is easy to miss.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: 알 수 없는 오류", uerr.Op, host)
	}
	// A non-*url.Error (such as an error returned by the redirect policy) may also carry an address, so it is uniformly redacted.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces http(s) addresses appearing in a piece of text with their redacted form.
//
// A fallback for errors where structured fields are unavailable (redirect-policy errors, third-party libraries' custom errors).
// It recognizes only the http/https prefix and splits on whitespace and quotes — an address will not contain those two kinds of characters.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
