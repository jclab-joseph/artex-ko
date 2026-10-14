package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/Autumn-27/artex/remoteexec"
	actool "github.com/Autumn-27/norma/tool"
)

// DeferredInfo carries the deferred-tools wiring an agent needs to build its
// Options: the MCP tool names whose schemas are withheld, the subset listed in the
// global system-prompt block (non-skill-gated), and the shared session unlock set.
// UnlockSkill unlocks a named skill's MCPs — hosts call it to rebuild the unlock set
// from history on a resumed session (design doc C2).
type DeferredInfo struct {
	FindingGuidance string            // derived from the final permitted tools, including DB overrides
	Deferred        []string          // all MCP tool names (schema withheld)
	GlobalNames     []string          // MCP names to list in the system-prompt block
	Unlock          *actool.UnlockSet // shared call-gate; nil when no MCP tools
	UnlockSkill     func(skillName string)
}

// ToolAugment, if set, returns the EXTRA tools an agent should see beyond its
// built-in base set — the agent's visible skills (packed into one Skill meta-tool)
// and visible MCP servers (expanded to mcp__server__tool). It also returns the
// DeferredInfo describing how those MCP tools are deferred/gated. The server wires
// it to the PG agent_visibility table. cleanup releases any spawned MCP clients.
//
// When nil, agents run with only their built-in tools — behavior is unchanged
// until a user assigns a skill/MCP to the agent in the UI.
var ToolAugment func(ctx context.Context, agentKey string) (extra []actool.CoreTool, def DeferredInfo, cleanup func())

// AugmentTools returns base plus the agent's visible skill/MCP tools, the
// DeferredInfo, and a cleanup func the caller must defer (closes MCP clients).
// Built-in base tools are kept as-is — never filtered (内置工具留代码层，不做可见性过滤).
func AugmentTools(ctx context.Context, agentKey string, base []actool.CoreTool) ([]actool.CoreTool, DeferredInfo, func()) {
	var (
		def     DeferredInfo
		cleanup = func() {}
		out     = base
	)
	if ToolAugment != nil {
		var extra []actool.CoreTool
		var cl func()
		extra, def, cl = ToolAugment(ctx, agentKey)
		if cl != nil {
			cleanup = cl
		}
		if len(extra) > 0 {
			out = append(append([]actool.CoreTool{}, base...), extra...)
		}
	}
	// DB tools table has the final say on the built-in tools: drop the ones this
	// agent isn't bound to (or that are disabled) and swap in overridden
	// descriptions/schemas + default injection. MCP/skill/host tools have no row
	// and pass through untouched, so deferred/unlock wiring stays consistent.
	if ToolResolve != nil {
		out = ToolResolve(ctx, agentKey, out)
	}
	out, def.FindingGuidance = findingWorkflowTools(agentKey, out)
	// Execution-plane split: when a sandboxed Agent is bound to this run (via the
	// context), replace each execution tool's Call with a proxy that ships the call
	// over mTLS to the Agent. Data/graph tools (insert_assets, record_fact, …) and
	// anything the Agent did not announce stay in-process. Unbound runs get the
	// LocalBackend, which is a no-op — identical to the pre-split monolith. The guard
	// panic-wrapper is applied last, so it still covers remote tools (a transport
	// error returns as a tool error, never a panic).
	backend := remoteexec.BackendFrom(ctx)
	for i, t := range out {
		out[i] = guardPanic(backend.Wrap(t))
	}
	// Register lowercase/snake_case aliases for the CamelCase built-ins (Bash → bash,
	// WebFetch → web_fetch) and defer them, so a model that drifts to the model-
	// conventional spelling still hits the handler while the model keeps seeing only
	// the official names (see issue #19). Added AFTER backend wrapping so each alias
	// delegates to the already-wrapped tool: in split mode a drifted spelling (bash)
	// routes to the sandbox Agent — or is fail-closed-blocked — exactly like the
	// official name, never around the isolation boundary.
	out, def.Deferred = addToolAliases(out, def.Deferred)
	return out, def, cleanup
}

// RemoteExecActive reports whether a sandbox-Agent execution backend is bound to ctx
// (i.e. the run is in split mode). When true, EVERY execution-plane tool must run in the
// Agent or be blocked — none may run on the control plane — so roles disable norma's
// in-process WebFetch + background manager and inject remote proxies. The decision keys
// off IsRemote alone, not off whether the Agent announced a specific tool: a missing
// capability must fail closed (block), never fall back to local execution.
func RemoteExecActive(ctx context.Context) bool {
	return remoteexec.BackendFrom(ctx).IsRemote()
}

// beginExecSession opens a fresh execution session for one agentcore session when the
// run is in split mode, binding a unique id to ctx (so every remote tool call this
// session issues is keyed by it on the Agent) and returning a cleanup func. The cleanup
// tells the Agent to tear down that session's background/shell state — on its OWN base
// context, so it still runs when the run ctx was cancelled. Callers defer it alongside
// Session.Close so the remote teardown follows the local session's end. No-op (and no
// id, no RPC) when execution is in-process (보안 리뷰 F2/F3).
//
// A fresh id per agentcore session — not the reused transcript SessionID — is what
// keeps a previous run's late teardown from killing the next run's processes.
func beginExecSession(ctx context.Context) (context.Context, func()) {
	b := remoteexec.BackendFrom(ctx)
	if !b.IsRemote() {
		return ctx, func() {}
	}
	id := remoteexec.NewExecSessionID()
	return remoteexec.WithExecSession(ctx, id), func() {
		remoteexec.EndExecSession(context.Background(), b, id)
	}
}

// RemoteWebFetchActive reports whether WebFetch must be routed to the sandbox Agent
// (true whenever execution is remote — WebFetch is an execution-plane tool and may never
// egress from the control plane in split mode). Roles use it to disable norma's
// in-process WebFetch and switch to the remote proxy.
func RemoteWebFetchActive(ctx context.Context) bool { return RemoteExecActive(ctx) }

// InjectRemoteWebFetch appends a plain WebFetch tool to base when execution is remote, so
// AugmentTools wraps it: a remote proxy when the Agent announced WebFetch, or a blocked
// tool when it did not (fail closed — never a control-plane fetch). The config is empty
// on purpose: the Agent builds the real WebFetch with its own local recording proxy; here
// we only need the tool's name/description/schema. No-op when execution is in-process.
func InjectRemoteWebFetch(ctx context.Context, base []actool.CoreTool) []actool.CoreTool {
	if RemoteExecActive(ctx) {
		return append(base, actool.NewWebFetch(actool.WebFetchConfig{}))
	}
	return base
}

// InjectRemoteBackgroundTools appends norma's background-task tools (Monitor/TaskOutput/
// TaskStop/TaskList) to base when execution is remote, so AugmentTools wraps them into
// remote proxies (or blocked tools when the Agent does not host them). In split mode the
// background Manager lives only in the sandbox Agent, so each role also sets
// opts.DisableBackgroundTasks=RemoteExecActive(ctx) to suppress the SDK's LOCAL injection
// of these same tools (which would spawn processes on the control plane — 보안 리뷰 F1).
// No-op when execution is in-process: the SDK injects the local ones as before.
func InjectRemoteBackgroundTools(ctx context.Context, base []actool.CoreTool) []actool.CoreTool {
	if RemoteExecActive(ctx) {
		return append(base, actool.NewMonitor(), actool.NewTaskOutput(), actool.NewTaskStop(), actool.NewTaskList())
	}
	return base
}

// ExecBashEnv returns the Bash-subprocess egress env for a role. When Bash runs in a
// sandboxed Agent the control plane sends none (the Agent injects its own, pointed at its
// local recording proxy); otherwise it is the ordinary in-process proxyEnv.
func ExecBashEnv(ctx context.Context, proxyAddr, caCert string) []string {
	return remoteBashEnv(remoteexec.BackendFrom(ctx), proxyAddr, caCert)
}

// guardPanic turns a panicking tool handler into an ordinary tool error. The
// harness runs each tool on its own goroutine, so a panic inside a handler can't
// be recovered by the caller that started the run — it takes the whole process
// down, and on restart the agent replays the same call and crashes again. Applied
// last, so it covers every tool the agent can reach: domain, SDK, MCP and skill.
func guardPanic(t actool.CoreTool) actool.CoreTool { return &guardedTool{CoreTool: t} }

type guardedTool struct{ actool.CoreTool }

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] %s panic: %v\n%s", g.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("工具 %s 内部错误：%v（本次调用已失败，可换个参数或改用别的工具）", g.Name(), r)), nil
		}
	}()
	return g.CoreTool.Call(ctx, in, tc)
}
