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
