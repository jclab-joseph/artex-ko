package remoteexec

import (
	"github.com/Autumn-27/artex/execsvc"
	actool "github.com/Autumn-27/norma/tool"
)

// BackgroundToolNames are norma's background-task tools. They are injected into a session
// by the SDK and operate on the per-session background Manager (tc.Tasks). In split mode
// that Manager lives ONLY inside the sandbox Agent, so these are hosted there and the
// control plane disables the SDK's local injection, injecting remote proxies instead
// (see agent role options + cmd/artex-agent). Classified as execution tools so a run
// without a connected Agent blocks them rather than spawning processes on the control
// plane.
var BackgroundToolNames = []string{"Monitor", "TaskOutput", "TaskStop", "TaskList"}

// execToolNames is the AUTHORITATIVE set of execution-plane tool names: tools whose side
// effects (shell, file I/O, target network, DNS, interactive PTY shells, background
// processes) must happen inside the sandbox Agent and NEVER on the control plane.
//
// Management owns this classification. An Agent's hello only decides whether a given
// execution tool can CURRENTLY run remotely (it announced it); it does not decide where
// the tool runs. The invariant: an execution tool with no connected/announcing Agent is
// BLOCKED — never executed locally. "Not announced" must never be read as "run here",
// which is the fail-open hole the split exists to close.
//
// The set unions every surface that reaches dangerous execution:
//   - norma built-ins hosted by the Agent (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash/
//     Sleep) + WebFetch,
//   - the interactive-shell session tools (shell_open/send/read/close/list),
//   - the background-task tools (Monitor/TaskOutput/TaskStop/TaskList),
//   - the db-free execution services custom tools + enrich dispatch into
//     (__artex_script/__artex_http/__artex_dns/__artex_httpprobe).
var execToolNames = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range DefaultAgentTools("", "", false) { // file tools + WebFetch
		m[t.Name()] = true
	}
	for _, t := range actool.ShellSessionTools() { // shell_open/send/read/close/list
		m[t.Name()] = true
	}
	for _, n := range BackgroundToolNames {
		m[n] = true
	}
	for _, n := range []string{execsvc.ToolScript, execsvc.ToolHTTP, execsvc.ToolDNS, execsvc.ToolHTTPProbe} {
		m[n] = true
	}
	return m
}()

// IsExecTool reports whether name is an execution-plane tool that must run inside a
// sandbox Agent. The backend proxies it when the Agent announces it and BLOCKS it
// otherwise — it is never run on the control plane.
func IsExecTool(name string) bool { return execToolNames[name] }

// ExecToolNames returns the execution-plane tool-name set. Used by FailClosedBackend
// (which has no Agent hello to consult) and by callers that need to reason about the
// execution surface without a live connection.
func ExecToolNames() []string {
	out := make([]string, 0, len(execToolNames))
	for n := range execToolNames {
		out = append(out, n)
	}
	return out
}
