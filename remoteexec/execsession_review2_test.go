package remoteexec

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveConn drives one call through a per-connection dispatcher (the networked path),
// so tests can exercise connection-epoch gating.
func serveConn(t *testing.T, c *connDispatcher, name, sid string, in json.RawMessage) *WireResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.ServeCall(ctx, name, in, &WireToolCtx{SessionID: sid, WorkingDir: "w"}, nil)
	if err != nil {
		t.Fatalf("ServeCall(%s) transport error: %v", name, err)
	}
	return res
}

// mustServe is a goroutine-safe ServeCall (no t.Fatal) for concurrency tests.
func mustServe(exec *Executor, name, sid string, in json.RawMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = exec.ServeCall(ctx, name, in, &WireToolCtx{SessionID: sid, WorkingDir: "w"}, nil)
}

// TestReviewLateCallAfterCloseRefused: a call whose goroutine runs after its connection
// was torn down is refused — it neither executes nor recreates session state on the dead
// connection (보안 리뷰: 연결 종료 후 지연 호출이 세션을 재생성).
func TestReviewLateCallAfterCloseRefused(t *testing.T) {
	exec := newBgExecutor(t)
	conn := exec.NewConn()
	if res := serveConn(t, conn, "Bash", "sid-1", bashInput(t, "echo ok")); res.IsError {
		t.Fatalf("pre-close Bash should run: %s", flat(res))
	}
	conn.close() // connection dropped: its sessions reclaimed, epoch marked dead

	res := serveConn(t, conn, "Bash", "sid-2", bashInput(t, "echo late"))
	if !res.IsError {
		t.Fatalf("a late call on a closed connection must be refused, got: %q", flat(res))
	}
	if strings.Contains(flat(res), "late") {
		t.Fatalf("a late call must NOT execute on a closed connection, got: %q", flat(res))
	}
	exec.mu.Lock()
	n := len(exec.sessions)
	exec.mu.Unlock()
	if n != 0 {
		t.Fatalf("a closed connection must leave no sessions behind, got %d", n)
	}
}

// TestReviewConcurrentManagerMaterializationRace reproduces the reviewer's race: a
// stateless tool (no Manager) and a session tool (materializes the Manager) running
// concurrently on the SAME session. The Manager pointer must be read/written under one
// lock. Run with -race (보안 리뷰: Manager 생성·조회 데이터 경쟁).
func TestReviewConcurrentManagerMaterializationRace(t *testing.T) {
	exec := newBgExecutor(t)
	const sid = "race-mgr"
	bash := bashInput(t, "echo hi")
	list := json.RawMessage(`{}`)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); mustServe(exec, "Bash", sid, bash) }()
		go func() { defer wg.Done(); mustServe(exec, "TaskList", sid, list) }()
	}
	wg.Wait()
}

// TestReviewDuplicateEndWaitsForCleanup: while one teardown is draining in-flight calls,
// a duplicate end does NOT return early — it waits until cleanup actually completes, so a
// duplicate end-session RPC never reports success before the Manager is gone (보안 리뷰:
// 중복 종료 RPC가 정리 완료 전 성공 반환).
func TestReviewDuplicateEndWaitsForCleanup(t *testing.T) {
	exec := NewExecutor(nil, t.TempDir(), nil)
	es := &execSession{state: sessActive, done: make(chan struct{})}
	es.ctx, es.cancel = context.WithCancel(context.Background())
	es.gate.RLock() // stand in for an in-flight call holding the session gate

	first := make(chan struct{})
	go func() { exec.terminate(es); close(first) }()
	waitState(t, exec, es, sessTerminating) // first is now blocked on gate.Lock

	second := make(chan struct{})
	go func() { exec.terminate(es); close(second) }()

	select {
	case <-first:
		t.Fatal("first terminate returned before the in-flight call drained")
	case <-second:
		t.Fatal("duplicate terminate returned before cleanup completed")
	case <-time.After(200 * time.Millisecond):
	}

	es.gate.RUnlock() // in-flight call drains → teardown completes
	mustClose(t, first, 2*time.Second, "first terminate")
	mustClose(t, second, 2*time.Second, "duplicate terminate")
}

// TestReviewFirstBashHonorsBackground: the FIRST Bash in a session with run_in_background
// must materialize the Manager and return immediately, not run synchronously to
// completion (보안 리뷰: 첫 Bash가 run_in_background 무시).
func TestReviewFirstBashHonorsBackground(t *testing.T) {
	exec := newBgExecutor(t)
	in, err := json.Marshal(map[string]any{"command": "sleep 5", "run_in_background": true})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res := serve(t, exec, "Bash", "bg-sid", in) // first call in this session
	elapsed := time.Since(start)
	if res.IsError {
		t.Fatalf("background Bash errored: %s", flat(res))
	}
	if !strings.Contains(strings.ToLower(flat(res)), "background") {
		t.Fatalf("first Bash with run_in_background should run in the background, got: %q", flat(res))
	}
	if elapsed > 3*time.Second {
		t.Fatalf("first background Bash blocked %v — run_in_background was ignored", elapsed)
	}
}

func waitState(t *testing.T, e *Executor, es *execSession, want sessState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		st := es.state
		e.mu.Unlock()
		if st == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session did not reach state %d in time", want)
}

func mustClose(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}
