package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This file is an invariant test: **no** error text emerging from a channel implementation may carry credentials.
//
// Why a separate file: the original channel tests only covered the success path and platform business errors,
// and never looked at transport-layer failures. Yet transport-layer errors (connection refused / DNS failure / timeout) are exactly the most dangerous —
// the *url.Error returned by http.Client.Do prints the **full URL** into the error text, and these
// platforms' credentials are right in the URL. Credentials flow along this string to four exits:
//
//	notification_deliveries.last_error  → persisted in plaintext
//	GET /api/notify/deliveries response → bypasses the channel-config masking, echoed to the browser
//	server logs                         → often shipped off and retained
//	the test-send endpoint's 502 response → shown directly in the frontend
//
// So this does not just test one function; it actually sends a request destined to fail for each channel and asserts the error text
// contains no such credential.

// credentialCases covers all channel shapes where "the credential is in the URL":
// DingTalk/WeCom in the query, Feishu in the last path segment, Telegram in the middle of the path.
var credentialCases = []struct {
	name   string
	ch     Channel
	cfg    map[string]any
	secret string
}{
	{
		name:   "DingTalk access_token in query",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send?access_token=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "WeCom key in query",
		ch:     weComChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/cgi-bin/webhook/send?key=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "Feishu hook id in last path segment",
		ch:     feishuChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/open-apis/bot/v2/hook/" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "Telegram bot token in middle of path",
		ch:     telegramChannel{},
		cfg:    map[string]any{"bot_token": leakProbeToken, "chat_id": "1", "base_url": "http://127.0.0.1:1"},
		secret: leakProbeToken,
	},
	{
		name:   "DingTalk signing secret",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send", "secret": leakProbeToken},
		secret: leakProbeToken,
	},
}

// leakProbeToken is a sentinel value that could never be a real credential, used to search for it in error text.
const leakProbeToken = "LEAKPROBE0123456789abcdef"

// TestChannelErrorsNeverLeakCredentials is the core invariant.
func TestChannelErrorsNeverLeakCredentials(t *testing.T) {
	for _, tc := range credentialCases {
		t.Run(tc.name, func(t *testing.T) {
			// A peer destined to fail: nothing listens on 127.0.0.1:1, so it takes the connection-refused path.
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{
				Items: []Item{{FindingID: 1, Severity: "high", Name: "leak probe"}},
			})
			if err == nil {
				t.Fatal("an unreachable address should error")
			}
			assertNoSecret(t, err.Error(), tc.secret)
		})
	}
}

// TestChannelErrorsNeverLeakCredentialsInPermanentPath covers the permanent-failure branch:
// URL validation failures, platform business errors, etc. also pass error text out, and likewise must not carry credentials.
func TestChannelErrorsNeverLeakCredentialsInPermanentPath(t *testing.T) {
	cases := []struct {
		name string
		ch   Channel
		cfg  map[string]any
	}{
		// An address with a credential but an invalid format → triggers the validateHTTPURL / url.Parse branch.
		{"DingTalk invalid address", dingTalkChannel{}, map[string]any{"webhook": "file:///" + leakProbeToken}},
		{"WeCom invalid address", weComChannel{}, map[string]any{"webhook": "gopher://" + leakProbeToken}},
		{"Feishu invalid address", feishuChannel{}, map[string]any{"webhook": "ftp://" + leakProbeToken + "/hook"}},
		{"Telegram invalid API address", telegramChannel{}, map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": "file://" + leakProbeToken}},
		{"generic Webhook invalid address", webhookChannel{}, map[string]any{"url": "javascript:" + leakProbeToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{Items: []Item{{Severity: "high"}}})
			if err == nil {
				t.Fatal("an invalid config should error")
			}
			assertNoSecret(t, err.Error(), leakProbeToken)
		})
	}
}

func assertNoSecret(t *testing.T, text, secret string) {
	t.Helper()
	if strings.Contains(text, secret) {
		t.Fatalf("the error text leaked the credential %q:\n    %s", secret, text)
	}
}

func TestRedactRequestTargetKeepsOnlySchemeAndHost(t *testing.T) {
	cases := map[string]string{
		"https://oapi.dingtalk.com/robot/send?access_token=S1":    "https://oapi.dingtalk.com/…",
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=S2": "https://qyapi.weixin.qq.com/…",
		"https://open.feishu.cn/open-apis/bot/v2/hook/S3":         "https://open.feishu.cn/…",
		"https://api.telegram.org/botS4/sendMessage":              "https://api.telegram.org/…",
		"http://10.0.0.5:8080/hook":                               "http://10.0.0.5:8080/…",
	}
	for in, want := range cases {
		got := redactRequestTarget(in)
		if got != want {
			t.Errorf("redactRequestTarget(%q) = %q, expected %q", in, got, want)
		}
		// The redacted result itself must not contain any path/query fragment of the original address.
		if parts := strings.SplitN(in, "://", 2); len(parts) == 2 {
			if hostAndRest := strings.SplitN(parts[1], "/", 2); len(hostAndRest) == 2 && hostAndRest[1] != "" {
				if strings.Contains(got, hostAndRest[1]) {
					t.Errorf("still contains a path/query fragment %q after redaction: %q", hostAndRest[1], got)
				}
			}
		}
	}
	// Unparseable input must never echo the original string.
	for _, bad := range []string{"", "://", "not a url", "http://"} {
		if got := redactRequestTarget(bad); strings.Contains(got, bad) && bad != "" {
			t.Errorf("unparseable input %q was echoed as %q", bad, got)
		}
	}
}

// TestRedactTransportErrorStripsURL targets the concrete *url.Error type directly:
// it is http.Client.Do's return type and the first scene of the leak.
func TestRedactTransportErrorStripsURL(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + leakProbeToken + "/sendMessage",
		Err: inner,
	}
	got := redactTransportError(uerr)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "api.telegram.org") {
		t.Errorf("should keep the host for troubleshooting, got %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("should keep the underlying cause for troubleshooting, got %q", got)
	}
	// Op must also be kept (whether it is POST or GET matters for troubleshooting).
	if !strings.Contains(got, "Post") {
		t.Errorf("should keep the operation name, got %q", got)
	}
}

// TestRedactURLsInTextHandlesFallback is the fallback path: a custom error that is not a *url.Error
// (such as an error returned by the redirect policy) must also have its address stripped.
func TestRedactURLsInTextHandlesFallback(t *testing.T) {
	in := fmt.Sprintf("cross-host redirect refused (a.example → http://b.example/bot%s/send)", leakProbeToken)
	got := redactURLsInText(in)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "http://b.example/…") {
		t.Errorf("should replace the address with its redacted form, got %q", got)
	}
	// Text with no address is kept as-is.
	if plain := "dial tcp: connection refused"; redactURLsInText(plain) != plain {
		t.Error("text with no address should not be altered")
	}
}

// TestCrossHostRedirectRefused covers "credential in the URL + following a cross-host hop = handing over the credential".
// The two httptest servers listen on different ports of 127.0.0.1, and a different port means a different Host,
// which is exactly a cross-host hop.
func TestCrossHostRedirectRefused(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/robot/send?access_token="+leakProbeToken, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": redirector.URL + "/robot/send?access_token=" + leakProbeToken},
		Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("a cross-host redirect should be rejected")
	}
	if hit {
		t.Fatal("the redirect target was accessed — the credential leaked along with the redirect")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestSameHostRedirectAllowed is the reverse case: a same-host hop (such as appending a trailing slash) must still work,
// otherwise normal workflows would be blocked too.
func TestSameHostRedirectAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robot/send" {
			// A same-host, same-port hop.
			http.Redirect(w, r, "/robot/send/", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"},
		Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("a same-host redirect should not be rejected: %v", err)
	}
}
