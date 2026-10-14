package remoteexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func errNoSuchTool(name string) error {
	return fmt.Errorf("remoteexec: agent cannot execute unknown tool %q", name)
}

// remoteTool is a CoreTool whose metadata (name, description, schema, permission
// self-check) is borrowed verbatim from a local reference instance, but whose Call is
// shipped over the Session to the Agent for execution. The reference instance is never
// Called, so constructing it (e.g. tool.NewBash()) spawns nothing on the control plane.
type remoteTool struct {
	meta actool.CoreTool
	sess *Session
}

// NewRemoteTool wraps a tool so its execution happens on the peer behind sess while its
// advertised contract stays identical to meta.
func NewRemoteTool(meta actool.CoreTool, sess *Session) actool.CoreTool {
	return &remoteTool{meta: meta, sess: sess}
}

func (r *remoteTool) Name() string                { return r.meta.Name() }
func (r *remoteTool) Description() string         { return r.meta.Description() }
func (r *remoteTool) Prompt() string              { return r.meta.Prompt() }
func (r *remoteTool) InputSchema() map[string]any { return r.meta.InputSchema() }
func (r *remoteTool) IsReadOnly(in json.RawMessage) bool {
	return r.meta.IsReadOnly(in)
}
func (r *remoteTool) IsConcurrencySafe(in json.RawMessage) bool {
	return r.meta.IsConcurrencySafe(in)
}
func (r *remoteTool) CheckPermissions(ctx context.Context, in json.RawMessage, pc permission.Context) permission.Decision {
	// Permission decisions (and the guard/intercept hooks) stay on the control plane;
	// only the side effect crosses the wire. Delegate to the reference contract.
	return r.meta.CheckPermissions(ctx, in, pc)
}

func (r *remoteTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	wtc := toWireToolCtx(tc)
	// Stamp the execution-session id bound to ctx so the Agent keys this call's
	// background/shell Manager per session (isolation + teardown). This is the single
	// choke point every remote tool call flows through, so stamping here covers Bash,
	// WebFetch, Monitor, Task* and shell_* uniformly.
	if sid := ExecSessionFrom(ctx); sid != "" {
		if wtc == nil {
			wtc = &WireToolCtx{}
		}
		wtc.SessionID = sid
	}
	var onProgress func(string)
	if tc != nil && tc.Emit != nil {
		onProgress = func(msg string) { tc.Emit(actool.ProgressInfo{Message: msg}) }
	}
	res, err := r.sess.Call(ctx, r.meta.Name(), in, wtc, onProgress)
	if err != nil {
		// Transport/handler failure: surface as a tool error the model can react to
		// rather than a hard run abort, unless the context was cancelled.
		if ctx.Err() != nil {
			return actool.Result{}, ctx.Err()
		}
		return actool.Errorf("remote execution channel error: " + err.Error() + " (this call could not be completed on the execution side)"), nil
	}
	return fromWireResult(res), nil
}

func toWireToolCtx(tc *actool.ToolContext) *WireToolCtx {
	if tc == nil {
		return nil
	}
	return &WireToolCtx{
		WorkingDir:     tc.WorkingDir,
		ToolUseID:      tc.ToolUseID,
		MaxOutputChars: tc.MaxOutputChars,
		OutputDir:      tc.OutputDir,
	}
}

func fromWireResult(res *WireResult) actool.Result {
	if res == nil {
		return actool.Result{}
	}
	return actool.Result{Content: res.Content, IsError: res.IsError, Extra: res.Extra}
}

func toWireResult(res actool.Result) *WireResult {
	return &WireResult{Content: res.Content, IsError: res.IsError, Extra: res.Extra}
}

// Executor is the Agent-side dispatcher: a registry of real tools plus the sandbox
// rooting and egress env that execution needs. It implements Dispatcher.
type Executor struct {
	tools map[string]actool.CoreTool
	// sandboxRoot is where all tool working/output dirs are rooted on the Agent, so a
	// Management path like /app/data/tasks/5/i7 maps to <sandboxRoot>/tasks/5/i7 and
	// files from one intent stay together across calls.
	sandboxRoot string
	// bashEnv is the Agent-local egress environment (proxy + CA trust) injected into
	// every Bash subprocess. It is built on the Agent from the Agent-local recording
	// proxy; Management never supplies it, so no control-plane secret can leak in.
	bashEnv []string

	// Background-task + interactive-shell hosting. When enabled, each execution session
	// (keyed by WireToolCtx.SessionID) gets its OWN Manager, so one session's background
	// processes / live PTYs are invisible and un-killable from another, and are torn down
	// when that session ends — never shared across sessions (보안 리뷰 F2/F3). bgBaseID
	// prefixes each session Manager's work-dir name. nil map / !bgEnabled = no hosting
	// (tests / all-in-one, where the SDK session's own Manager is used).
	bgEnabled bool
	bgBaseID  string
	mu        sync.Mutex
	sessions  map[string]*execSession
	// connSeq hands out a monotonic epoch per inbound connection; liveConns holds the
	// epochs still accepting calls. A call tagged with an epoch no longer in liveConns
	// (its connection was torn down) is refused rather than (re)creating session state —
	// so a goroutine that was already serving an inbound call when the connection dropped
	// cannot revive a dead connection's session (보안 리뷰: 연결 종료 후 지연 호출). Epoch 0
	// is the unmanaged/in-process path (all-in-one, diagnostics, tests) and is always live.
	connSeq   uint64
	liveConns map[uint64]bool
}

// sessState is an execution session's lifecycle. Teardown is a two-step
// active→terminating→terminated transition so a late call cannot slip in after cleanup
// began, and a terminated id can never recreate a Manager (보안 리뷰 F3).
type sessState int

const (
	sessActive sessState = iota
	sessTerminating
	sessTerminated
)

// execSession is one execution session's hosted state on the Agent. mgr is created
// lazily — only when a session-dependent tool actually runs — but ctx/gate exist for
// every session so even stateless calls (Bash) are bound to the session scope and get
// cancelled when it ends or the connection drops. gate is RLocked for a call's duration
// and write-Locked during teardown, so Cleanup never races a concurrent Spawn.
type execSession struct {
	mgr    *actool.Manager
	state  sessState
	gate   sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	epoch  uint64        // connection that owns this session (0 = unmanaged/in-process)
	done   chan struct{} // closed when terminate() has fully finished tearing this down
}

// NewExecutor builds an Executor over the given tools. sandboxRoot is created on
// demand; bashEnv may be nil (direct egress).
func NewExecutor(tools []actool.CoreTool, sandboxRoot string, bashEnv []string) *Executor {
	m := make(map[string]actool.CoreTool, len(tools))
	for _, t := range tools {
		m[t.Name()] = t
	}
	return &Executor{tools: m, sandboxRoot: sandboxRoot, bashEnv: bashEnv, sessions: map[string]*execSession{}, liveConns: map[uint64]bool{}}
}

// connDispatcher is the per-connection Dispatcher wired to each inbound Session. It tags
// every call with its connection epoch so the Executor can refuse calls that arrive after
// the connection was torn down (보안 리뷰: 연결 종료 후 지연 호출). Close() ends the
// connection's sessions and stops it accepting.
type connDispatcher struct {
	exec  *Executor
	epoch uint64
}

func (c *connDispatcher) ServeCall(ctx context.Context, name string, input json.RawMessage, wtc *WireToolCtx, progress func(string)) (*WireResult, error) {
	return c.exec.serveCall(ctx, name, input, wtc, progress, c.epoch)
}

// close ends every session owned by this connection and marks its epoch dead, so later
// in-flight calls on it are refused instead of recreating state.
func (c *connDispatcher) close() { c.exec.CloseConn(c.epoch) }

// NewConn opens a per-connection dispatcher with a fresh epoch and marks that epoch live.
// Each inbound connection gets its own (see startAgentSession); the returned value is both
// the Dispatcher to wire and the handle whose close() the caller invokes when the
// connection ends.
func (e *Executor) NewConn() *connDispatcher {
	e.mu.Lock()
	e.connSeq++
	ep := e.connSeq
	e.liveConns[ep] = true
	e.mu.Unlock()
	return &connDispatcher{exec: e, epoch: ep}
}

// CloseConn marks a connection epoch dead (no new calls accepted on it) and tears down the
// sessions it owns. Idempotent. The sessions are left in the map until their teardown has
// fully completed and only then pruned, so a concurrent Cleanup/EndAllSessions snapshots
// them and waits on their teardown (via terminate's done channel) rather than missing
// them and returning while a background process is still being killed (보안 리뷰: Agent
// 종료 시 진행 중 연결 정리 완료 전 Cleanup 반환).
func (e *Executor) CloseConn(epoch uint64) {
	e.mu.Lock()
	delete(e.liveConns, epoch)
	var owned []*execSession
	for _, es := range e.sessions {
		if es.epoch == epoch {
			owned = append(owned, es)
		}
	}
	e.mu.Unlock()
	for _, es := range owned {
		e.terminate(es)
	}
	// Teardown complete: now drop this connection's entries (live sessions + terminated
	// markers). Anything added since is a different epoch and left untouched.
	e.mu.Lock()
	for id, es := range e.sessions {
		if es.epoch == epoch {
			delete(e.sessions, id)
		}
	}
	e.mu.Unlock()
}

// EnableBackgroundTasks turns on per-session hosting of norma's Monitor/Task* and
// shell_* tools. baseID prefixes each session Manager's work-dir name. Managers are
// created lazily per execution session (see acquireSession), so this no longer creates
// one eagerly and cannot fail; a per-session creation error surfaces at call time.
func (e *Executor) EnableBackgroundTasks(baseID string) error {
	e.bgEnabled = true
	e.bgBaseID = baseID
	return nil
}

// Cleanup tears down every live execution session (kills processes/PTYs, removes work
// dirs). Called on Agent process exit. Safe when hosting was never enabled.
func (e *Executor) Cleanup() { e.EndAllSessions() }

// EndSession tears down one execution session: refuse new calls, cancel in-flight ones,
// wait for them to drain, then tear down its Manager. Idempotent AND synchronous for
// every caller — a duplicate/late end-session RPC blocks until the teardown that is
// already in progress has fully finished, so no caller is told "done" before the Manager
// is actually gone (보안 리뷰: 중복 종료 RPC가 정리 완료 전 성공 반환). A never-seen id is
// recorded as terminated so a call that arrives after it can NOT recreate a Manager
// under it. epoch tags the terminated marker to the connection so CloseConn reclaims it.
func (e *Executor) EndSession(sessionID string) { e.endSession(sessionID, 0) }

func (e *Executor) endSession(sessionID string, epoch uint64) {
	if sessionID == "" {
		return
	}
	e.mu.Lock()
	es := e.sessions[sessionID]
	if es == nil {
		e.sessions[sessionID] = &execSession{state: sessTerminated, epoch: epoch, done: closedChan}
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	e.terminate(es)
}

// EndAllSessions tears down every session this Executor holds, across all connections.
// Used by Cleanup on process exit. It snapshots the sessions and terminates each WITHOUT
// removing them from the map first, so a teardown already in progress on another
// goroutine (a disconnect's CloseConn) is seen and waited on (via terminate's done
// channel) rather than skipped; the map is cleared only after every teardown has
// completed (보안 리뷰: Agent 종료 시 진행 중 연결 정리 완료 전 Cleanup 반환). Per-connection
// teardown on disconnect goes through CloseConn, which also marks the epoch dead.
func (e *Executor) EndAllSessions() {
	e.mu.Lock()
	all := make([]*execSession, 0, len(e.sessions))
	for _, es := range e.sessions {
		all = append(all, es)
	}
	e.liveConns = map[uint64]bool{}
	e.mu.Unlock()
	for _, es := range all {
		e.terminate(es)
	}
	// Every teardown is now complete; drop all entries (live sessions + terminated markers).
	e.mu.Lock()
	e.sessions = map[string]*execSession{}
	e.mu.Unlock()
}

// terminate drives one session through terminating→terminated. It cancels the session
// ctx first (so in-flight calls abort promptly), then takes the gate's write lock —
// which blocks until every in-flight call (gate readers) has drained — before tearing
// down the Manager, so a concurrent Spawn can never outlive Cleanup. A caller that finds
// the teardown already in progress waits on es.done until it completes, rather than
// returning early, so a duplicate end-session RPC never reports success before cleanup.
func (e *Executor) terminate(es *execSession) {
	e.mu.Lock()
	switch es.state {
	case sessTerminated:
		e.mu.Unlock()
		return
	case sessTerminating:
		done := es.done
		e.mu.Unlock()
		if done != nil {
			<-done // another caller is tearing this down; wait for it to finish
		}
		return
	}
	es.state = sessTerminating
	e.mu.Unlock()

	if es.cancel != nil {
		es.cancel()
	}
	es.gate.Lock()
	if es.mgr != nil {
		es.mgr.Cleanup()
		es.mgr = nil
	}
	es.gate.Unlock()

	e.mu.Lock()
	es.state = sessTerminated
	e.mu.Unlock()
	if es.done != nil {
		close(es.done) // release any duplicate-end waiters now that cleanup is complete
	}
}

// acquireSession returns the live execSession for id with its gate RLocked (the caller
// must RUnlock) and a SNAPSHOT of its Manager taken under e.mu. It returns (nil, nil, nil)
// when there is no session scope (hosting off, or empty id — diagnostic/all-in-one), and
// (nil, nil, err) when the connection epoch is dead (errConnClosed) or the session is
// terminating/terminated (errExecSessionEnded) or its Manager could not be built — in
// each case the caller refuses rather than reviving. The Manager is returned (not read
// from es.mgr by the caller) so a concurrent acquireSession materializing it on the same
// session is not a data race (보안 리뷰: Manager 생성·조회 경쟁).
func (e *Executor) acquireSession(id string, needMgr bool, epoch uint64) (*execSession, *actool.Manager, error) {
	e.mu.Lock()
	// Refuse any call whose connection was torn down; epoch 0 is the always-live
	// unmanaged path (in-process/all-in-one/diagnostics).
	if epoch != 0 && !e.liveConns[epoch] {
		e.mu.Unlock()
		return nil, nil, errConnClosed
	}
	if !e.bgEnabled || id == "" {
		e.mu.Unlock()
		return nil, nil, nil
	}
	es := e.sessions[id]
	if es == nil {
		es = &execSession{state: sessActive, epoch: epoch, done: make(chan struct{})}
		es.ctx, es.cancel = context.WithCancel(context.Background())
		e.sessions[id] = es
	}
	if es.state != sessActive {
		e.mu.Unlock()
		return nil, nil, errExecSessionEnded
	}
	if needMgr && es.mgr == nil {
		mgr, err := actool.NewManager(e.bgBaseID + "-" + sanitizeID(id))
		if err != nil {
			e.mu.Unlock()
			return nil, nil, err
		}
		es.mgr = mgr
	}
	mgr := es.mgr // snapshot under e.mu
	// RLock while holding e.mu is safe and never blocks here: terminate only write-Locks
	// the gate AFTER setting state!=active under e.mu, and we only reach this on an active
	// session, so no writer is holding or waiting on this gate.
	es.gate.RLock()
	e.mu.Unlock()
	return es, mgr, nil
}

var (
	errExecSessionEnded = errors.New("remoteexec: execution session has ended")
	errConnClosed       = errors.New("remoteexec: connection has been closed")
)

// closedChan is a shared, already-closed channel used as the done signal for terminated
// markers (sessions that never ran a tool), so a wait on it returns immediately.
var closedChan = func() chan struct{} { ch := make(chan struct{}); close(ch); return ch }()

// bashToolName is the one non-strict tool that still needs the per-session Manager.
const bashToolName = "Bash"

// needsManager reports whether a tool call must run against the per-session background
// Manager. The strict session tools (Monitor/Task*/shell_*) always do. Bash always does
// too — not only for an explicit run_in_background, but because norma moves even a
// FOREGROUND command to the background when it exceeds its timeout, and both paths need
// tc.Tasks. Without a Manager norma silently falls back to synchronous execution, so the
// same command+timeout would behave differently depending on whether a session tool ran
// first in the session (보안 리뷰: foreground Bash 시간 초과 처리가 이전 호출에 의존 / 첫
// Bash가 run_in_background 무시). A sessionless Bash (empty id) still falls back to sync
// rather than being refused — only strict session tools require a session.
func needsManager(name string) bool {
	return sessionToolSet[name] || name == bashToolName
}

// sessionToolSet names every tool whose state lives on the per-session Manager,
// independent of the env gates that may exclude some at runtime. Constructing these
// instances spawns nothing (they are read for their names only); used to decide when a
// session's Manager must be materialized and to refuse these on a sessionless call.
var sessionToolSet = buildSessionToolSet()

func buildSessionToolSet() map[string]bool {
	names := map[string]bool{}
	for _, t := range []actool.CoreTool{newEgressMonitor(), actool.NewTaskOutput(), actool.NewTaskStop(), actool.NewTaskList()} {
		names[t.Name()] = true
	}
	for _, t := range actool.ShellSessionTools() {
		names[t.Name()] = true
	}
	return names
}

// sanitizeID keeps only filesystem-safe characters for a Manager work-dir name.
func sanitizeID(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b = append(b, r)
		default:
			b = append(b, '_')
		}
	}
	return string(b)
}

// ToolNames returns the executable tool names, for the hello announcement.
func (e *Executor) ToolNames() []string {
	out := make([]string, 0, len(e.tools))
	for n := range e.tools {
		out = append(out, n)
	}
	return out
}

// ServeCall serves an inbound call on the unmanaged path (epoch 0): all-in-one /
// in-process / diagnostics / tests, where there is no connection lifecycle to gate on.
// Networked connections are served through a per-connection connDispatcher (see NewConn),
// which carries the connection epoch into serveCall.
func (e *Executor) ServeCall(ctx context.Context, name string, input json.RawMessage, wtc *WireToolCtx, progress func(string)) (*WireResult, error) {
	return e.serveCall(ctx, name, input, wtc, progress, 0)
}

func (e *Executor) serveCall(ctx context.Context, name string, input json.RawMessage, wtc *WireToolCtx, progress func(string), epoch uint64) (*WireResult, error) {
	sid := ""
	if wtc != nil {
		sid = wtc.SessionID
	}
	// Reserved control call: tear down one execution session's hosted state. Handled
	// before tool-registry lookup, so it is ready the moment the dispatcher is wired
	// (before any call is served). Returning a Result is what confirms teardown to the
	// caller's EndExecSession (not merely that it was enqueued) — and endSession blocks
	// until the teardown actually completes, even for a duplicate request.
	if name == toolExecSessionEnd {
		e.endSession(sid, epoch)
		return &WireResult{}, nil
	}

	t := e.tools[name]
	if t == nil {
		return &WireResult{Content: nil, IsError: true}, errNoSuchTool(name)
	}

	// Strictly session-scoped tools (Monitor/Task*/shell_*) REQUIRE a live session and are
	// refused sessionless. Bash additionally needs the Manager only when backgrounding; a
	// sessionless background Bash is not refused but falls back to synchronous execution.
	strictSession := sessionToolSet[name]
	if strictSession && (!e.bgEnabled || sid == "") {
		return toWireResult(actool.Errorf("this tool requires an execution session (no session ID was provided); this call is rejected.")), nil
	}
	needMgr := needsManager(name)

	es, mgr, err := e.acquireSession(sid, needMgr, epoch)
	if err != nil {
		// Connection closed, session terminating/terminated, or its Manager could not be
		// built. Refuse without reviving it — the model sees a tool error, never a
		// shared/stale Manager or a session resurrected on a dead connection.
		return toWireResult(actool.Errorf("this execution session has ended or is unavailable (" + err.Error() + "); this call is rejected.")), nil
	}

	tc := &actool.ToolContext{Env: e.bashEnv}
	if es != nil {
		defer es.gate.RUnlock()
		tc.Tasks = mgr // snapshot from acquireSession; nil for a stateless tool with no Manager
		// Bind this call to the session scope so EndSession / a dropped connection can
		// cancel it in flight, while still honoring the per-call cancel (peer KindCancel).
		callCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(es.ctx, cancel)
		defer stop()
		defer cancel()
		ctx = callCtx
	}

	if wtc != nil {
		tc.ToolUseID = wtc.ToolUseID
		tc.MaxOutputChars = wtc.MaxOutputChars
		tc.WorkingDir = e.localDir(wtc.WorkingDir)
		if wtc.OutputDir != "" {
			tc.OutputDir = e.localDir(wtc.OutputDir)
		}
	}
	if progress != nil {
		tc.Emit = func(p actool.ProgressInfo) { progress(p.Message) }
	}
	if tc.WorkingDir != "" {
		_ = os.MkdirAll(tc.WorkingDir, 0o755)
	}
	if tc.OutputDir != "" {
		_ = os.MkdirAll(tc.OutputDir, 0o755)
	}
	res, err := callToolGuarded(ctx, t, input, tc)
	if err != nil {
		return toWireResult(res), err
	}
	return toWireResult(res), nil
}

// callToolGuarded runs a hosted tool and converts a panic in its handler into an ordinary
// error result. On the control plane the monolith wraps every tool in agent.guardPanic for
// exactly this reason; Agent-hosted tools (norma built-ins, Agent-hosted MCP, execsvc) are
// NOT wrapped by it, and they run on serveInbound's goroutine with no recover — so without
// this a single panicking tool would unwind that goroutine and crash the whole sandbox Agent
// process, dropping every in-flight call. Recovering here keeps one bad tool call local.
func callToolGuarded(ctx context.Context, t actool.CoreTool, input json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[remoteexec] tool %s panic: %v\n%s", t.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("tool %s internal error: %v (this call failed; try different arguments or a different tool)", t.Name(), r)), nil
		}
	}()
	return t.Call(ctx, input, tc)
}

// localDir maps a Management-supplied path into the Agent sandbox. Absolute inputs are
// stripped to their path tail and re-rooted; relative inputs are joined directly. The
// result is always contained under sandboxRoot (filepath.Clean + a contains check),
// so a crafted "../" path cannot escape the sandbox.
func (e *Executor) localDir(p string) string {
	if e.sandboxRoot == "" {
		return p // no rooting configured: trust caller (used only in in-proc/all-in-one)
	}
	rel := p
	if filepath.IsAbs(rel) {
		rel = strings.TrimPrefix(rel, string(filepath.Separator))
		// drop a leading volume-ish segment pattern like app/data to keep paths short
	}
	rel = filepath.Clean("/" + rel) // force absolute-clean then make relative to root
	full := filepath.Join(e.sandboxRoot, rel)
	// Containment guard: ensure full stays within sandboxRoot.
	if !within(e.sandboxRoot, full) {
		return e.sandboxRoot
	}
	return full
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
