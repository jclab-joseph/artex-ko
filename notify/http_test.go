package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// This file covers doJSON's HTTP-layer error classification.
//
// Why test it separately: each channel adapter only handles its platform's own business error codes (DingTalk errcode,
// Feishu code, Telegram ok field), whereas the **HTTP-layer** classification is done uniformly by doJSON,
// the two being independent lines of defense. Without this one, a relay gateway returning 503 would be treated as a permanent failure
// and retry abandoned outright; while a 403 would be treated as retryable and waste three backoff rounds.

func replyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesHTTPStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"200 success is not an error", 200, false},
		{"429 rate limit is retryable", 429, false},
		{"408 request timeout is retryable", 408, false},
		{"500 server error is retryable", 500, false},
		{"502 gateway error is retryable", 502, false},
		{"503 service unavailable is retryable", 503, false},
		{"400 bad parameter is a permanent failure", 400, true},
		{"401 auth failure is a permanent failure", 401, true},
		{"403 forbidden is a permanent failure", 403, true},
		{"404 address not found is a permanent failure", 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := replyServer(t, tc.status, `{"detail":"upstream says no"}`)
			_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("2xx should not error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("non-2xx should error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("permanent verdict for HTTP %d is wrong: expected %v got %v (%v)",
					tc.status, tc.permanent, got, err)
			}
			// The status code must appear in the error, otherwise the user cannot tell whether they misconfigured it or the peer is down.
			// Assert the number rather than Go's English StatusText: this package's messages are localized
			// (consistent with the rest of the project), and the number is the language-independent, stably assertable part.
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("the error message should carry the HTTP status code %d, got %v", tc.status, err)
			}
		})
	}
}

// TestDoJSONIncludesResponseSnippet covers snippet: the peer's returned error description must be carried back,
// otherwise the user only knows "it failed" without knowing why the peer rejected it.
func TestDoJSONIncludesResponseSnippet(t *testing.T) {
	srv := replyServer(t, 400, `{"error":"invalid webhook token"}`)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	if !strings.Contains(err.Error(), "invalid webhook token") {
		t.Errorf("the error message should carry back the peer's description, got %v", err)
	}
}

// TestDoJSONSnippetIsSingleLineAndBounded constrains the shape of snippet:
// the peer response goes verbatim into the last_error column and the frontend table, and multi-line/oversized content breaks the layout and the payload.
func TestDoJSONSnippetIsSingleLineAndBounded(t *testing.T) {
	// A response with newlines, tabs, and 5000 characters of oversized content.
	long := strings.Repeat("x", 5000)
	srv := replyServer(t, 500, "line1\nline2\r\n\tline3 "+long)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("the error message should be collapsed to a single line, got %q", msg)
	}
	// snippet caps at 200 characters + a fixed prefix, so the total must be far smaller than the original response.
	if len(msg) > 400 {
		t.Errorf("the error message is too long (%d bytes) and should be truncated by snippet: %q", len(msg), msg)
	}
}

// TestDoJSONRejectsOversizedResponse confirms the read is capped: when a peer abnormally returns huge content
// it must not read the whole response into memory (every delivery-history row stores a copy of last_error).
func TestDoJSONRejectsOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB
	srv := replyServer(t, 400, huge)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("an oversized response should be read with a length limit and truncated, error message length %d", len(err.Error()))
	}
}
