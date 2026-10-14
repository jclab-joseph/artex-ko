package remoteexec

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Backend decides, per execution tool, where it runs. The control plane holds one
// Backend per agent session (or the process-wide Local one in all-in-one mode) and
// asks it to Wrap each tool as the tool list is assembled.
//
// The default is LocalBackend, which is a no-op: behavior is identical to the
// pre-split monolith until a RemoteBackend is bound. This keeps the split opt-in and
// risk-free for single-box users.
type Backend interface {
	// IsRemote reports whether execution is delegated to a sandboxed Agent.
	IsRemote() bool
	// Executes reports whether the named tool is one this backend runs remotely (so
	// the caller can, e.g., disable norma's built-in WebFetch and inject a proxy).
	Executes(toolName string) bool
	// Wrap returns the CoreTool to register: the original for a tool this backend does
	// not handle, or a remote proxy whose Call ships to the Agent for one it does.
	Wrap(meta actool.CoreTool) actool.CoreTool
}

// LocalBackend runs every tool in-process — the monolith's original behavior.
type LocalBackend struct{}

func (LocalBackend) IsRemote() bool                         { return false }
func (LocalBackend) Executes(string) bool                   { return false }
func (LocalBackend) Wrap(m actool.CoreTool) actool.CoreTool { return m }

// RemoteBackend delegates the Agent-announced tool set to a Session; everything else
// stays local. The announced set (from the Agent's hello) is authoritative: Management
// wraps exactly the tools the Agent said it can execute, and leaves data/graph tools
// (insert_assets, record_fact, traffic_*) in-process.
type RemoteBackend struct {
	sess       *Session
	agentTools map[string]bool
}

// NewRemoteBackend binds a Session and the tool names the Agent announced.
func NewRemoteBackend(sess *Session, agentTools []string) *RemoteBackend {
	set := make(map[string]bool, len(agentTools))
	for _, n := range agentTools {
		set[n] = true
	}
	return &RemoteBackend{sess: sess, agentTools: set}
}

func (b *RemoteBackend) IsRemote() bool { return true }

func (b *RemoteBackend) Executes(name string) bool { return b.agentTools[name] }

func (b *RemoteBackend) Wrap(meta actool.CoreTool) actool.CoreTool {
	name := meta.Name()
	if b.agentTools[name] {
		return NewRemoteTool(meta, b.sess)
	}
	// Fail closed: an execution-plane tool the connected Agent did NOT announce must not
	// silently run on the control plane. "Not announced" means the Agent cannot host it
	// (capability missing), so block it rather than falling back to local execution —
	// the isolation boundary must not depend on a complete announce list. Non-execution
	// tools (data/graph writes) stay in-process as before.
	if IsExecTool(name) {
		return &blockedTool{meta: meta, reason: "연결된 샌드박스 Agent 가 이 실행 도구를 제공하지 않습니다(" + name + "); 격리 정책상 제어 플레인에서 실행할 수 없습니다"}
	}
	return meta
}

// Session exposes the underlying session (for event handlers / lifecycle).
func (b *RemoteBackend) Session() *Session { return b.sess }

// DefaultExecToolNames returns the names of the execution tools an Agent hosts. Used
// by FailClosedBackend (which has no Agent hello to consult) and by callers that need
// to reason about the execution surface without a live connection.
func DefaultExecToolNames() []string {
	tools := DefaultAgentTools("", "", false)
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name())
	}
	return out
}

// FailClosedBackend is bound when execution offload to a sandbox is *required* but no
// Agent is currently connected. It makes every execution tool fail with a clear error
// instead of silently running the dangerous operation on the control plane — the
// security property the split exists to guarantee. Non-execution tools (data/graph
// writes) still run locally so the agent loop can keep recording what it already knows.
type FailClosedBackend struct {
	execNames map[string]bool
	reason    string
}

// NewFailClosedBackend builds a fail-closed backend. reason is surfaced to the model.
func NewFailClosedBackend(reason string) *FailClosedBackend {
	set := map[string]bool{}
	for _, n := range ExecToolNames() {
		set[n] = true
	}
	if reason == "" {
		reason = "no sandbox Agent is connected; execution is blocked by policy"
	}
	return &FailClosedBackend{execNames: set, reason: reason}
}

func (b *FailClosedBackend) IsRemote() bool            { return true }
func (b *FailClosedBackend) Executes(name string) bool { return b.execNames[name] }

func (b *FailClosedBackend) Wrap(meta actool.CoreTool) actool.CoreTool {
	if b.execNames[meta.Name()] {
		return &blockedTool{meta: meta, reason: b.reason}
	}
	return meta
}

type blockedTool struct {
	meta   actool.CoreTool
	reason string
}

func (t *blockedTool) Name() string                { return t.meta.Name() }
func (t *blockedTool) Description() string         { return t.meta.Description() }
func (t *blockedTool) Prompt() string              { return t.meta.Prompt() }
func (t *blockedTool) InputSchema() map[string]any { return t.meta.InputSchema() }
func (t *blockedTool) IsReadOnly(in json.RawMessage) bool {
	return t.meta.IsReadOnly(in)
}
func (t *blockedTool) IsConcurrencySafe(in json.RawMessage) bool {
	return t.meta.IsConcurrencySafe(in)
}
func (t *blockedTool) CheckPermissions(ctx context.Context, in json.RawMessage, pc permission.Context) permission.Decision {
	return t.meta.CheckPermissions(ctx, in, pc)
}
func (t *blockedTool) Call(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
	return actool.Errorf("【ARTEX Platform Control · Execution Plane Not Ready】" + t.reason + " (this tool must run inside the isolated sandbox Agent; connect an Agent and retry)"), nil
}

type backendCtxKey struct{}

// WithBackend binds an execution backend to ctx so the tool-assembly seam
// (agent.AugmentTools) can consult it without threading it through every signature.
func WithBackend(ctx context.Context, b Backend) context.Context {
	return context.WithValue(ctx, backendCtxKey{}, b)
}

// BackendFrom returns the backend bound to ctx, or LocalBackend when none is — so
// callers never need a nil check and unbound runs stay local.
func BackendFrom(ctx context.Context) Backend {
	if b, ok := ctx.Value(backendCtxKey{}).(Backend); ok && b != nil {
		return b
	}
	return LocalBackend{}
}
