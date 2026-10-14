package remoteexec

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// toolExecSessionEnd is a reserved pseudo-tool name. Management sends it as an ordinary
// Call so it reuses the request/response correlation machinery: the Agent's dispatcher
// special-cases it (before any tool-registry lookup) to tear down one execution
// session, then returns a Result. Because Management blocks on that Result, end-session
// is a CONFIRMED round-trip — cleanup is observed to have run on the Agent, not merely
// enqueued (unlike a one-way Emit). No real tool name begins with this prefix.
const toolExecSessionEnd = "__artex_exec_session_end__"

// endSessionTimeout bounds how long Management waits for the Agent to confirm an
// execution session's teardown. The call runs on a fresh context (not the possibly-
// cancelled run context), so cleanup is attempted even after the run was aborted; the
// timeout keeps a dead/slow Agent from blocking the caller's defer indefinitely.
const endSessionTimeout = 5 * time.Second

type execSessionCtxKey struct{}

// NewExecSessionID mints a globally-unique execution-session id. A fresh id is issued
// for every control-plane agentcore session (each planner round, worker-intent run,
// chat turn, mainagent turn), NOT derived from the transcript SessionID — transcript
// ids are reused across re-runs and are sometimes unset, so keying the Agent's Manager
// by them would let a previous run's late teardown kill the next run's processes.
func NewExecSessionID() string { return "exec-" + uuid.NewString() }

// WithExecSession binds an execution-session id to ctx so remoteTool.Call can stamp it
// onto every tool call the session issues. Reaches the tool call because norma threads
// the Prompt ctx down to CoreTool.Call (harness toolCtx derives from it).
func WithExecSession(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, execSessionCtxKey{}, id)
}

// ExecSessionFrom returns the execution-session id bound to ctx, or "" when none is.
func ExecSessionFrom(ctx context.Context) string {
	if v, ok := ctx.Value(execSessionCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// EndExecSession tells the Agent to tear down all background/shell state for one
// execution session, and blocks (bounded by endSessionTimeout) until the Agent confirms
// the teardown ran. It is a no-op for a non-remote backend or one with no live Session
// (nothing to clean up on the execution plane). Idempotent on the Agent, so a repeat or
// a late call is safe. Callers pass a fresh base ctx (e.g. context.Background()) so the
// cleanup still runs when the run's own ctx was already cancelled.
func EndExecSession(ctx context.Context, b Backend, sessionID string) {
	if sessionID == "" || b == nil {
		return
	}
	sb, ok := b.(interface{ Session() *Session })
	if !ok {
		return
	}
	sess := sb.Session()
	if sess == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, endSessionTimeout)
	defer cancel()
	// Best-effort: a transport error means the Agent/connection is already gone, so its
	// per-connection teardown (EndAllSessions) will reclaim the session anyway.
	_, _ = sess.Call(cctx, toolExecSessionEnd, nil, &WireToolCtx{SessionID: sessionID}, nil)
}
