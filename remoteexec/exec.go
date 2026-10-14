package remoteexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		return actool.Errorf("远程执行通道错误：" + err.Error() + "（本次调用未能在执行端完成）"), nil
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
}

// NewExecutor builds an Executor over the given tools. sandboxRoot is created on
// demand; bashEnv may be nil (direct egress).
func NewExecutor(tools []actool.CoreTool, sandboxRoot string, bashEnv []string) *Executor {
	m := make(map[string]actool.CoreTool, len(tools))
	for _, t := range tools {
		m[t.Name()] = t
	}
	return &Executor{tools: m, sandboxRoot: sandboxRoot, bashEnv: bashEnv, sessions: map[string]*execSession{}}
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
// wait for them to drain, then tear down its Manager. Idempotent (a repeat or late call
// is a no-op), and a never-seen id is recorded as terminated so a call that arrives
// after it can NOT recreate a Manager under it (보안 리뷰 F3).
func (e *Executor) EndSession(sessionID string) {
	if sessionID == "" {
		return
	}
	e.mu.Lock()
	es := e.sessions[sessionID]
	if es == nil {
		e.sessions[sessionID] = &execSession{state: sessTerminated}
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	e.terminate(es)
}

// EndAllSessions tears down every session this Executor holds. Called when the
// control-plane connection drops (the Agent reuses one Executor across reconnects, and
// at most one connection is active per ConnectAgentSide) and on process exit, so a
// dropped connection's sessions and their in-flight calls do not linger.
func (e *Executor) EndAllSessions() {
	e.mu.Lock()
	all := make([]*execSession, 0, len(e.sessions))
	for _, es := range e.sessions {
		all = append(all, es)
	}
	e.sessions = map[string]*execSession{}
	e.mu.Unlock()
	for _, es := range all {
		e.terminate(es)
	}
}

// terminate drives one session through terminating→terminated. It cancels the session
// ctx first (so in-flight calls abort promptly), then takes the gate's write lock —
// which blocks until every in-flight call (gate readers) has drained — before tearing
// down the Manager, so a concurrent Spawn can never outlive Cleanup.
func (e *Executor) terminate(es *execSession) {
	e.mu.Lock()
	if es.state != sessActive {
		e.mu.Unlock()
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
}

// acquireSession returns the live execSession for id with its gate RLocked (the caller
// must RUnlock), materializing its Manager when needMgr. It returns (nil, nil) when
// there is no session scope (hosting off, or empty id — diagnostic/all-in-one calls),
// and (nil, errExecSessionEnded) when the session is terminating/terminated so the
// caller refuses the call rather than reviving it.
func (e *Executor) acquireSession(id string, needMgr bool) (*execSession, error) {
	if !e.bgEnabled || id == "" {
		return nil, nil
	}
	e.mu.Lock()
	es := e.sessions[id]
	if es == nil {
		es = &execSession{state: sessActive}
		es.ctx, es.cancel = context.WithCancel(context.Background())
		e.sessions[id] = es
	}
	if es.state != sessActive {
		e.mu.Unlock()
		return nil, errExecSessionEnded
	}
	if needMgr && es.mgr == nil {
		mgr, err := actool.NewManager(e.bgBaseID + "-" + sanitizeID(id))
		if err != nil {
			e.mu.Unlock()
			return nil, err
		}
		es.mgr = mgr
	}
	// RLock while holding e.mu is safe and never blocks here: terminate only write-Locks
	// the gate AFTER setting state!=active under e.mu, and we only reach this on an active
	// session, so no writer is holding or waiting on this gate.
	es.gate.RLock()
	e.mu.Unlock()
	return es, nil
}

var errExecSessionEnded = errors.New("remoteexec: execution session has ended")

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

func (e *Executor) ServeCall(ctx context.Context, name string, input json.RawMessage, wtc *WireToolCtx, progress func(string)) (*WireResult, error) {
	sid := ""
	if wtc != nil {
		sid = wtc.SessionID
	}
	// Reserved control call: tear down one execution session's hosted state. Handled
	// before tool-registry lookup, so it is ready the moment the dispatcher is wired
	// (before any call is served). Returning a Result is what confirms teardown to the
	// caller's EndExecSession (not merely that it was enqueued).
	if name == toolExecSessionEnd {
		e.EndSession(sid)
		return &WireResult{}, nil
	}

	t := e.tools[name]
	if t == nil {
		return &WireResult{Content: nil, IsError: true}, errNoSuchTool(name)
	}

	needMgr := sessionToolSet[name]
	// A session-dependent tool needs a live execution session; refuse it (never share a
	// Manager, never run sessionless) when hosting is off or no id was supplied.
	if needMgr && (!e.bgEnabled || sid == "") {
		return toWireResult(actool.Errorf("该工具需要一个执行会话（未提供会话标识）；本次调用被拒绝。")), nil
	}

	es, err := e.acquireSession(sid, needMgr)
	if err != nil {
		// Session is terminating/terminated, or its Manager could not be created. Refuse
		// without reviving it — the model sees a tool error, not a shared/stale Manager.
		return toWireResult(actool.Errorf("该执行会话已结束或不可用（" + err.Error() + "）；本次调用被拒绝。")), nil
	}

	tc := &actool.ToolContext{Env: e.bashEnv}
	if es != nil {
		defer es.gate.RUnlock()
		tc.Tasks = es.mgr // nil for a stateless tool that never materialized one
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
	res, err := t.Call(ctx, input, tc)
	if err != nil {
		return toWireResult(res), err
	}
	return toWireResult(res), nil
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
