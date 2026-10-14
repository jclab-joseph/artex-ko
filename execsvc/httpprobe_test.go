package execsvc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func callProbe(t *testing.T, url string) actool.Result {
	t.Helper()
	in, _ := json.Marshal(map[string]string{"url": url})
	res, err := HTTPProbeTool("", "").Call(context.Background(), in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("probe transport error: %v", err)
	}
	return res
}

// TestHTTPProbeDoesNotFollowRedirects: the sandbox probe must behave like the in-process
// enrich prober and report a 30x response as-is instead of chasing it to another target —
// otherwise it probes a host the caller never asked about and records the final hop's
// status against the original URL (보안 리뷰: 원격 프로브가 리다이렉트를 따라가 다른 표적을 조회).
func TestHTTPProbeDoesNotFollowRedirects(t *testing.T) {
	var secondHit atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHit.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>second</title>"))
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL, http.StatusFound) // 302 → a different target
	}))
	defer first.Close()

	res := callProbe(t, first.URL)
	if res.IsError {
		t.Fatalf("probe errored on a 302: %s", res.Flatten())
	}
	var out ProbeResult
	if e := json.Unmarshal([]byte(res.Flatten()), &out); e != nil {
		t.Fatalf("decode probe result: %v (%q)", e, res.Flatten())
	}
	if out.Status != http.StatusFound {
		t.Fatalf("probe followed the redirect: status=%d, want 302 (the requested target's own response)", out.Status)
	}
	if secondHit.Load() != 0 {
		t.Fatalf("probe chased the redirect to a different target (%d hit(s))", secondHit.Load())
	}
}

// TestHTTPProbeConnectionFailureIsError: a connection-level failure (nothing listening) is
// not an HTTP status — it must come back as an error result, so the control-plane prober
// skips the asset update instead of recording "status 0" as the monolith never did
// (보안 리뷰: 연결 실패를 status:0·IsError:false 성공으로 반환).
func TestHTTPProbeConnectionFailureIsError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free the port — now nothing is listening there

	res := callProbe(t, "http://"+addr)
	if !res.IsError {
		t.Fatalf("a connection failure must be an error result (so the asset is not updated with status 0); got success: %q", res.Flatten())
	}
}
