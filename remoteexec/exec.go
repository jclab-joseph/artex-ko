package remoteexec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
}

// NewExecutor builds an Executor over the given tools. sandboxRoot is created on
// demand; bashEnv may be nil (direct egress).
func NewExecutor(tools []actool.CoreTool, sandboxRoot string, bashEnv []string) *Executor {
	m := make(map[string]actool.CoreTool, len(tools))
	for _, t := range tools {
		m[t.Name()] = t
	}
	return &Executor{tools: m, sandboxRoot: sandboxRoot, bashEnv: bashEnv}
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
	t := e.tools[name]
	if t == nil {
		return &WireResult{Content: nil, IsError: true}, errNoSuchTool(name)
	}
	tc := &actool.ToolContext{Env: e.bashEnv}
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
