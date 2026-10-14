package remoteexec

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// newBgExecutor builds an Agent Executor with the background-task + interactive-shell
// tools enabled, so the per-execution-session Manager logic (보안 리뷰 F2/F3) is live.
func newBgExecutor(t *testing.T) *Executor {
	t.Helper()
	tools := DefaultAgentTools("", "", false)
	tools = append(tools, AgentSessionTools()...)
	exec := NewExecutor(tools, t.TempDir(), nil)
	if err := exec.EnableBackgroundTasks("test"); err != nil {
		t.Fatalf("EnableBackgroundTasks: %v", err)
	}
	if exec.tools["Monitor"] == nil || exec.tools["TaskList"] == nil {
		t.Skip("background tools disabled in this environment")
	}
	t.Cleanup(exec.EndAllSessions) // kill any background processes a test left running
	return exec
}

func monitorInput(t *testing.T, cmd string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]string{"command": cmd, "description": "test"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func flat(w *WireResult) string { return fromWireResult(w).Flatten() }

// serve drives one Agent-side call for a given execution session id.
func serve(t *testing.T, exec *Executor, name, sid string, in json.RawMessage) *WireResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := exec.ServeCall(ctx, name, in, &WireToolCtx{SessionID: sid, WorkingDir: "w"}, nil)
	if err != nil {
		t.Fatalf("ServeCall(%s, sid=%q) transport error: %v", name, sid, err)
	}
	return res
}

// within runs fn and fails the test if it does not return inside d (catches a deadlock
// instead of hanging the whole suite).
func mustFinish(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not complete within %s (deadlock?)", what, d)
	}
}

// TestExecSessionIsolation: one session's background task is invisible to another —
// session B cannot enumerate (and so cannot TaskStop) session A's processes.
func TestExecSessionIsolation(t *testing.T) {
	exec := newBgExecutor(t)
	if res := serve(t, exec, "Monitor", "sess-A", monitorInput(t, "sleep 10")); res.IsError {
		t.Fatalf("Monitor in A errored: %s", flat(res))
	}
	if got := flat(serve(t, exec, "TaskList", "sess-B", json.RawMessage(`{}`))); !strings.Contains(got, "No background tasks") {
		t.Fatalf("session B must not see session A's tasks, got: %q", got)
	}
	if got := flat(serve(t, exec, "TaskList", "sess-A", json.RawMessage(`{}`))); strings.Contains(got, "No background tasks") {
		t.Fatalf("session A should list its own monitor task, got: %q", got)
	}
}

// TestExecSessionEmptyIDRefused: a session-dependent tool with no execution-session id
// is refused — never run sessionless, never sharing a Manager.
func TestExecSessionEmptyIDRefused(t *testing.T) {
	exec := newBgExecutor(t)
	if res := serve(t, exec, "Monitor", "", monitorInput(t, "sleep 1")); !res.IsError {
		t.Fatalf("Monitor with empty session id must be refused, got: %q", flat(res))
	}
	// A stateless tool, by contrast, runs fine with no session id (diagnostic/all-in-one).
	if res := serve(t, exec, "Bash", "", bashInput(t, "echo ok")); res.IsError || !strings.Contains(flat(res), "ok") {
		t.Fatalf("Bash with empty session id should run: err=%v out=%q", res.IsError, flat(res))
	}
}

// TestExecSessionTerminated: after a session ends, new session-dependent calls are
// refused; EndSession is idempotent; and a call arriving after an end on a never-seen
// id does NOT recreate a Manager (late previous-run teardown can't revive state).
func TestExecSessionTerminated(t *testing.T) {
	exec := newBgExecutor(t)
	serve(t, exec, "Monitor", "sess-A", monitorInput(t, "sleep 10"))
	exec.EndSession("sess-A")
	exec.EndSession("sess-A") // idempotent: must not panic or block
	if res := serve(t, exec, "Monitor", "sess-A", monitorInput(t, "sleep 1")); !res.IsError {
		t.Fatalf("an ended session must refuse new session-dependent calls, got: %q", flat(res))
	}
	// End on an id never seen, then a late call on it: still refused (no recreate).
	exec.EndSession("ghost")
	if res := serve(t, exec, "Monitor", "ghost", monitorInput(t, "sleep 1")); !res.IsError {
		t.Fatalf("a call after end on an unseen id must not recreate a Manager, got: %q", flat(res))
	}
}

// TestExecSessionEndDoesNotAffectOthers: ending session A leaves session B's tasks
// running — the core of the reviewer's "same conversation/intent re-run" concern, since
// a re-run gets a fresh id and the prior run's late teardown must not touch it.
func TestExecSessionEndDoesNotAffectOthers(t *testing.T) {
	exec := newBgExecutor(t)
	serve(t, exec, "Monitor", "run-1", monitorInput(t, "sleep 10"))
	serve(t, exec, "Monitor", "run-2", monitorInput(t, "sleep 10"))
	exec.EndSession("run-1")
	if got := flat(serve(t, exec, "TaskList", "run-2", json.RawMessage(`{}`))); strings.Contains(got, "No background tasks") {
		t.Fatalf("ending run-1 must not remove run-2's tasks, got: %q", got)
	}
}

// TestExecSessionConcurrentEndAndCalls: teardown racing tool calls on one session must
// not deadlock, panic, or corrupt state. Run under -race for the data-race check.
func TestExecSessionConcurrentEndAndCalls(t *testing.T) {
	exec := newBgExecutor(t)
	in := monitorInput(t, "sleep 5")
	mustFinish(t, 25*time.Second, "concurrent end + calls", func() {
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, _ = exec.ServeCall(ctx, "Monitor", in, &WireToolCtx{SessionID: "race", WorkingDir: "w"}, nil)
			}()
		}
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); exec.EndSession("race") }()
		}
		wg.Wait()
	})
	mustFinish(t, 10*time.Second, "EndAllSessions after race", exec.EndAllSessions)
}

// TestExecEndAllSessions: a dropped connection tears down every session promptly, and a
// fresh session afterward starts clean.
func TestExecEndAllSessions(t *testing.T) {
	exec := newBgExecutor(t)
	serve(t, exec, "Monitor", "A", monitorInput(t, "sleep 10"))
	serve(t, exec, "Monitor", "B", monitorInput(t, "sleep 10"))
	mustFinish(t, 10*time.Second, "EndAllSessions", exec.EndAllSessions)
	if got := flat(serve(t, exec, "TaskList", "C", json.RawMessage(`{}`))); !strings.Contains(got, "No background tasks") {
		t.Fatalf("a fresh session after EndAllSessions should be clean, got: %q", got)
	}
}

// TestMonitorInheritsEgressEnv: the reimplemented Monitor passes tc.Env to the spawned
// process, so a monitored command sees the Agent's egress env (proxy + CA) exactly like
// Bash — the F4 fix. Verified by a monitored command echoing a sentinel env var.
func TestMonitorInheritsEgressEnv(t *testing.T) {
	tools := DefaultAgentTools("", "", false)
	tools = append(tools, AgentSessionTools()...)
	exec := NewExecutor(tools, t.TempDir(), []string{"ARTEX_EGRESS_SENTINEL=proxy-ok"})
	if err := exec.EnableBackgroundTasks("test"); err != nil {
		t.Fatalf("EnableBackgroundTasks: %v", err)
	}
	if exec.tools["Monitor"] == nil {
		t.Skip("background tools disabled in this environment")
	}
	res := serve(t, exec, "Monitor", "A", monitorInput(t, "printenv ARTEX_EGRESS_SENTINEL"))
	if res.IsError {
		t.Fatalf("Monitor errored: %s", flat(res))
	}
	path := monitorOutputPath(t, flat(res))
	got := pollFile(t, path, 5*time.Second)
	if !strings.Contains(got, "proxy-ok") {
		t.Fatalf("monitored process must inherit the egress env (tc.Env); output = %q", got)
	}
}

func monitorOutputPath(t *testing.T, result string) string {
	t.Helper()
	const marker = "Output file: "
	i := strings.Index(result, marker)
	if i < 0 {
		t.Fatalf("Monitor result missing output-file path: %q", result)
	}
	rest := result[i+len(marker):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func pollFile(t *testing.T, path string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(path)
	return string(b)
}
