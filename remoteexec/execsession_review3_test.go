package remoteexec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestReviewCleanupWaitsForInFlightConnClose: when a connection's teardown is already in
// progress (draining an in-flight call) and Agent-exit Cleanup runs concurrently, Cleanup
// must NOT return until that teardown completes — otherwise a background process outlives
// Cleanup (보안 리뷰: Agent 종료 시 진행 중 연결 정리 완료 전 Cleanup 반환).
func TestReviewCleanupWaitsForInFlightConnClose(t *testing.T) {
	exec := NewExecutor(nil, t.TempDir(), nil)
	_ = exec.EnableBackgroundTasks("test")
	conn := exec.NewConn() // live epoch

	// Register a session owned by that connection, with its gate held to stand in for an
	// in-flight call that teardown must drain before cleaning the Manager.
	es := &execSession{state: sessActive, epoch: conn.epoch, done: make(chan struct{})}
	es.ctx, es.cancel = context.WithCancel(context.Background())
	exec.mu.Lock()
	exec.sessions["s"] = es
	exec.mu.Unlock()
	es.gate.RLock()

	closeDone := make(chan struct{})
	go func() { conn.close(); close(closeDone) }() // CloseConn → terminate(es), blocks on gate.Lock
	waitState(t, exec, es, sessTerminating)

	cleanupDone := make(chan struct{})
	go func() { exec.Cleanup(); close(cleanupDone) }()

	select {
	case <-cleanupDone:
		t.Fatal("Cleanup returned before the in-progress connection teardown completed")
	case <-closeDone:
		t.Fatal("conn.close returned before the in-flight call drained")
	case <-time.After(200 * time.Millisecond):
	}

	es.gate.RUnlock() // in-flight call drains → teardown can finish
	mustClose(t, closeDone, 2*time.Second, "conn.close")
	mustClose(t, cleanupDone, 2*time.Second, "Cleanup")
}

// TestReviewForegroundBashAutoBackgrounds: a FOREGROUND Bash (no run_in_background) whose
// command overruns its timeout must be auto-moved to the background — which norma only
// does when a Manager is present. As the first call in a fresh session this only works if
// foreground Bash also materializes the Manager, so the same command+timeout behaves the
// same regardless of whether a session tool ran first (보안 리뷰: foreground Bash 시간
// 초과 처리가 이전 호출에 의존).
func TestReviewForegroundBashAutoBackgrounds(t *testing.T) {
	exec := newBgExecutor(t)
	in, err := json.Marshal(map[string]any{"command": "sh -c 'sleep 5'", "timeout_ms": 500})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res := serve(t, exec, "Bash", "fg-sid", in) // first call in this session
	elapsed := time.Since(start)
	if res.IsError {
		t.Fatalf("foreground Bash that overran its timeout should move to background, not error: %s", flat(res))
	}
	if !strings.Contains(strings.ToLower(flat(res)), "background") {
		t.Fatalf("foreground Bash over timeout should auto-background on the first call, got: %q", flat(res))
	}
	if elapsed > 3*time.Second {
		t.Fatalf("call blocked %v — auto-background did not kick in (ran synchronously)", elapsed)
	}
}
