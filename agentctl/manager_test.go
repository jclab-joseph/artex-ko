package agentctl

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// TestManagerAgentDialsRoundtrip exercises the full control-plane flow without a
// database: issue a bundle, have an Agent dial in over mTLS, then run Bash through the
// registered connection — the same path POST /api/agents/{id}/exec drives.
func TestManagerAgentDialsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Management listens on an ephemeral port.
	if err := mgr.StartListener(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	addr := mgr.listener.Addr().String()

	// Issue a bundle for an agent that dials Management at that address.
	bundle, err := mgr.IssueBundle(remoteexec.ModeAgentDials, addr, "e2e-agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Expired() {
		t.Fatal("freshly issued bundle should not be expired")
	}

	// Launch the Agent side with a real executor.
	exec := remoteexec.NewExecutor(remoteexec.DefaultAgentTools("", "", false), t.TempDir(), nil)
	agentSess, err := remoteexec.ConnectAgentSide(ctx, bundle, exec)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer agentSess.Close()

	// Wait for Management to register the connection.
	if !waitFor(2*time.Second, func() bool { return mgr.HasLive() }) {
		t.Fatal("agent never registered with manager")
	}
	agents := mgr.List()
	if len(agents) != 1 || agents[0].ID != "e2e-agent" {
		t.Fatalf("unexpected agent list: %+v", agents)
	}

	// Announced metadata must carry each tool's full schema (not just its name), so
	// Management can build placeholders/proxies for tools it has no local code for
	// (Agent-hosted MCP relies on this). Bash is always announced with an input schema.
	metas := mgr.AnnouncedMetas()
	bash, ok := metas["Bash"]
	if !ok {
		t.Fatalf("AnnouncedMetas missing Bash: %v", keys(metas))
	}
	if len(bash.Schema) == 0 || !strings.Contains(string(bash.Schema), "command") {
		t.Fatalf("Bash announced schema missing/empty: %q", string(bash.Schema))
	}
	// A proxy rebuilt purely from the announced meta must preserve name + schema.
	rebuilt := remoteexec.CoreToolFromMeta(bash)
	if rebuilt.Name() != "Bash" || rebuilt.InputSchema()["properties"] == nil {
		t.Fatalf("CoreToolFromMeta lost metadata: name=%q schema=%v", rebuilt.Name(), rebuilt.InputSchema())
	}

	// Run Bash through the manager, as the HTTP exec handler does.
	input, _ := json.Marshal(map[string]string{"command": "echo manager-e2e-ok"})
	res, err := mgr.Exec(ctx, "e2e-agent", "Bash", input)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	out := ""
	for _, b := range res.Content {
		out += b.Text
	}
	if res.IsError || !strings.Contains(out, "manager-e2e-ok") {
		t.Fatalf("bad exec result: isErr=%v out=%q", res.IsError, out)
	}

	// The backend the engine would bind should also execute Bash remotely.
	be := mgr.AnyBackend()
	if be == nil || !be.IsRemote() || !be.Executes("Bash") {
		t.Fatalf("AnyBackend not usable: %+v", be)
	}
}

// TestFailClosedWhenNoAgent verifies the "require" posture blocks execution tools when
// no Agent is connected, while leaving non-execution tools alone.
func TestFailClosedWhenNoAgent(t *testing.T) {
	b := remoteexec.NewFailClosedBackend("")
	if !b.Executes("Bash") || !b.Executes("WebFetch") {
		t.Fatal("fail-closed backend should claim execution tools")
	}
	if b.Executes("record_fact") {
		t.Fatal("fail-closed backend must not block data/graph tools")
	}
}

// TestAgentHostedMCPToolRouting proves the Agent-hosted MCP mechanism end to end at
// the control-plane boundary: an Agent announces an MCP-shaped tool (mcp__server__tool)
// WITH its schema, and Management — which has no local definition of it — builds a
// placeholder from the announced metadata alone and routes a call through the backend
// to the Agent. (mcpconn.Connect's stdio/http wiring is a thin delegate to the
// upstream-tested clients; what is artex-specific is announce → placeholder → route.)
func TestAgentHostedMCPToolRouting(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mgr.StartListener(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	bundle, err := mgr.IssueBundle(remoteexec.ModeAgentDials, mgr.listener.Addr().String(), "mcp-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	// An Agent whose tool set includes an MCP-shaped tool with a real schema.
	echo := actool.Build(actool.Spec{
		Name:        "mcp__demo__echo",
		Description: "echo back text",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
			"required":   []any{"text"},
		},
		ReadOnly: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(in, &a)
			return actool.Text("echo:" + a.Text), nil
		},
	})
	exec := remoteexec.NewExecutor(append(remoteexec.DefaultAgentTools("", "", false), echo), t.TempDir(), nil)
	agentSess, err := remoteexec.ConnectAgentSide(ctx, bundle, exec)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer agentSess.Close()
	if !waitFor(2*time.Second, func() bool { return mgr.HasLive() }) {
		t.Fatal("agent never registered")
	}

	// Management has the MCP tool's metadata (schema) purely from the announce.
	meta, ok := mgr.AnnouncedMetas()["mcp__demo__echo"]
	if !ok || len(meta.Schema) == 0 || !strings.Contains(string(meta.Schema), "text") {
		t.Fatalf("announced MCP meta missing/schemaless: %+v", meta)
	}

	// Build a placeholder from the announced meta alone and route it via the backend.
	be := mgr.AnyBackend()
	if be == nil || !be.Executes("mcp__demo__echo") {
		t.Fatalf("backend should route the announced MCP tool: %+v", be)
	}
	proxy := be.Wrap(remoteexec.CoreToolFromMeta(meta))
	in, _ := json.Marshal(map[string]string{"text": "hi"})
	res, err := proxy.Call(ctx, in, &actool.ToolContext{WorkingDir: "mcp"})
	if err != nil {
		t.Fatalf("proxy call: %v", err)
	}
	if res.IsError || res.Flatten() != "echo:hi" {
		t.Fatalf("unexpected MCP proxy result: isErr=%v out=%q", res.IsError, res.Flatten())
	}
}

func keys(m map[string]remoteexec.WireToolMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
