package remoteexec

import actool "github.com/Autumn-27/norma/tool"

// DefaultAgentTools is the execution-plane tool set an Agent hosts: norma's built-in
// file/shell tools (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash/Sleep) plus WebFetch.
//
// Deliberately excluded: web_search (search engines are reconnaissance, not
// target-facing, so per the egress policy it stays on the control plane), and every
// LLM-touching or data/graph tool (those never leave Management). The Agent's WebFetch
// is pointed at the Agent-local recording proxy so target HTTP is still captured as
// evidence — co-located with the traffic sink inside the sandbox.
func DefaultAgentTools(webFetchProxy, webFetchCACert string, webFetchInsecureTLS bool) []actool.CoreTool {
	tools := actool.DefaultTools()
	tools = append(tools, actool.NewWebFetch(actool.WebFetchConfig{
		Proxy:       webFetchProxy,
		CACert:      webFetchCACert,
		InsecureTLS: webFetchInsecureTLS,
	}))
	return tools
}

// AgentSessionTools returns the execution tools whose state lives on the Agent's
// per-session background Manager: the background-task tools (Monitor / TaskOutput /
// TaskStop / TaskList) and the interactive-shell session tools (shell_open/send/read/
// close/list). The Agent hosts them so these dangerous features — spawning background
// processes and driving interactive PTYs — happen inside the sandbox, never on the
// control plane (보안 리뷰 F1/F5). On Management these are injected as remote proxies
// (InjectRemoteBackgroundTools / the interactive-shell assembly) and the SDK's local
// injection is disabled. Respects norma's AGENT_CORE_DISABLE_* env gates. The Executor
// must have a background Manager (EnableBackgroundTasks) for them to actually run.
func AgentSessionTools() []actool.CoreTool {
	var out []actool.CoreTool
	if !actool.BackgroundTasksDisabled() {
		out = append(out, actool.NewMonitor(), actool.NewTaskOutput(), actool.NewTaskStop(), actool.NewTaskList())
	}
	if !actool.InteractiveShellDisabled() {
		out = append(out, actool.ShellSessionTools()...)
	}
	return out
}
