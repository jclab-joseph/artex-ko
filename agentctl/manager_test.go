package agentctl

import (
	"context"
	"encoding/json"
	"net"
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

// TestAgentDialsRejectsIdSpoof proves Management binds the registered agent id to the
// mTLS client certificate: a CA-valid Agent holding a cert for "alice" cannot register
// under "bob" by announcing a different id in its hello (보안 리뷰 F8).
func TestAgentDialsRejectsIdSpoof(t *testing.T) {
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
	// Issue a cert bound to "alice", then tamper the announced id to "bob". The TLS cert
	// (from bundle.Identity) still carries CN artex-agent:alice.
	bundle, err := mgr.IssueBundle(remoteexec.ModeAgentDials, mgr.listener.Addr().String(), "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle.AgentID = "bob"

	exec := remoteexec.NewExecutor(remoteexec.DefaultAgentTools("", "", false), t.TempDir(), nil)
	sess, _ := remoteexec.ConnectAgentSide(ctx, bundle, exec)
	if sess != nil {
		defer sess.Close()
	}
	// Management must reject the identity mismatch: nothing registers under "bob" or
	// "alice".
	if waitFor(1500*time.Millisecond, func() bool { return mgr.HasLive() }) {
		t.Fatalf("id-spoofed agent must not register, got: %+v", mgr.List())
	}
}

// TestManagerListenerNotBlockedByIdlePeer proves one unauthenticated TCP peer that
// completes neither the TLS handshake nor the hello cannot occupy the Management receive
// path and starve a legitimate Agent's registration. A silent raw peer is opened first; a
// real Agent dialing in must still register promptly (보안 리뷰: 미인증 TCP 연결 하나가
// Management 수신을 막음 — 역방향 Agent 수신에 적용한 개선을 Management 에도 적용).
func TestManagerListenerNotBlockedByIdlePeer(t *testing.T) {
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
	addr := mgr.listener.Addr().String()

	// A raw TCP peer that connects first and sends nothing — it never starts the TLS
	// handshake, so under the old serial accept loop its waitHello parked the loop for up to
	// 30s and blocked every other Agent.
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer raw.Close()

	// A legitimate Agent dialing in must still register promptly despite the idle peer. The
	// dial runs in its own goroutine because, under the serial-accept bug, the accept loop is
	// parked on the idle peer's handshake and the Agent's own TLS handshake would block too —
	// measuring registration only after the dial returns would hide the stall.
	bundle, err := mgr.IssueBundle(remoteexec.ModeAgentDials, addr, "live-agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	exec := remoteexec.NewExecutor(remoteexec.DefaultAgentTools("", "", false), t.TempDir(), nil)
	sessCh := make(chan *remoteexec.Session, 1)
	go func() {
		s, e := remoteexec.ConnectAgentSide(ctx, bundle, exec)
		if e == nil {
			sessCh <- s
		}
	}()
	t.Cleanup(func() {
		select {
		case s := <-sessCh:
			s.Close()
		default:
		}
	})

	// Well under the 10s handshake deadline a stalled peer would otherwise impose on the
	// serial loop: the Agent must be registered quickly.
	if !waitFor(3*time.Second, func() bool { return mgr.Has("live-agent") }) {
		t.Fatal("a legitimate Agent was blocked from registering by one idle unauthenticated TCP peer")
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
