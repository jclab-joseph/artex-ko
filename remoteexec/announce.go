package remoteexec

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// WireToolMeta is the announced metadata for one Agent tool: enough for Management to
// present it to the model and build an RPC proxy for it WITHOUT a local definition.
// Used for Agent-hosted MCP tools, whose schemas exist only on the Agent.
type WireToolMeta struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	ReadOnly    bool            `json:"read_only,omitempty"`
}

// ToolMetas returns the announced metadata for every tool this Executor hosts. The
// Agent sends it in its hello so Management can proxy tools it has no local code for.
func (e *Executor) ToolMetas() []WireToolMeta {
	out := make([]WireToolMeta, 0, len(e.tools))
	for name, t := range e.tools {
		schema, _ := json.Marshal(t.InputSchema())
		out = append(out, WireToolMeta{
			Name:        name,
			Description: t.Description(),
			Schema:      schema,
			ReadOnly:    safeReadOnly(t),
		})
	}
	return out
}

// safeReadOnly best-effort probes a tool's read-only flag for the announce without a
// real input. Some tools inspect the input; an empty object is the neutral probe, and
// a panic (none expected) degrades to false rather than crashing the hello.
func safeReadOnly(t actool.CoreTool) (ro bool) {
	defer func() { _ = recover() }()
	return t.IsReadOnly(json.RawMessage("{}"))
}

// metaTool is a metadata-only CoreTool built from announced WireToolMeta. Its Call is
// never meant to run in-process (NewRemoteTool overrides it with the RPC proxy); if a
// metaTool is ever left unwrapped it fails closed instead of pretending to execute.
type metaTool struct {
	name, desc string
	schema     map[string]any
	readOnly   bool
}

func (m *metaTool) Name() string                           { return m.name }
func (m *metaTool) Description() string                    { return m.desc }
func (m *metaTool) Prompt() string                         { return "" }
func (m *metaTool) InputSchema() map[string]any            { return m.schema }
func (m *metaTool) IsReadOnly(json.RawMessage) bool        { return m.readOnly }
func (m *metaTool) IsConcurrencySafe(json.RawMessage) bool { return m.readOnly }
func (m *metaTool) CheckPermissions(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}
func (m *metaTool) Call(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
	return actool.Errorf("【ARTEX Platform Control · Execution Plane Not Ready】This tool is hosted by the sandbox Agent but is not currently routed to an Agent (the Agent is not connected, or does not provide this tool)."), nil
}

// CoreToolFromMeta rebuilds a metadata-only CoreTool from an announced WireToolMeta.
func CoreToolFromMeta(m WireToolMeta) actool.CoreTool {
	var schema map[string]any
	if len(m.Schema) > 0 {
		_ = json.Unmarshal(m.Schema, &schema)
	}
	return &metaTool{name: m.Name, desc: m.Description, schema: schema, readOnly: m.ReadOnly}
}

// NewRemoteToolFromMeta builds an RPC-proxy tool straight from announced metadata, for
// tools Management has no local definition of (Agent-hosted MCP). The proxy's Call
// ships to the Agent exactly like NewRemoteTool; only the metadata source differs.
func NewRemoteToolFromMeta(m WireToolMeta, sess *Session) actool.CoreTool {
	return NewRemoteTool(CoreToolFromMeta(m), sess)
}
