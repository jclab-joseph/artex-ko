package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/norma/llm"
)

// Regression tests for the "dangerous ops only in the Agent" review: each mirrors a
// reproduced control-plane execution/egress path and asserts it is now blocked under a
// strict (require) posture.

type splitIsoProvider struct {
	command string
	calls   int
}

func (p *splitIsoProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	if p.calls == 1 {
		in, _ := json.Marshal(map[string]string{"command": p.command})
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "iso-bash", Name: "Bash", Input: in}}}, "tool_use", llm.Usage{}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
}

func (p *splitIsoProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) { y(llm.StreamEvent{}, fmt.Errorf("unexpected stream")) }
}

func splitIsoManager(t *testing.T, proxy string) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), proxy)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// F1: the final (task-timeout) planner round must bind the task's execution backend, so a
// require/fail-closed posture blocks Bash instead of running it on the control plane.
func TestFinalPlannerRoundBindsExecBackend(t *testing.T) {
	t.Setenv(envAgentOffload, "require")
	m := splitIsoManager(t, "")
	task, err := m.CreateTask("split isolation", "regression", nil, 60, 0)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "mgmt-exec.txt")
	p := agent.NewPlanner(&splitIsoProvider{command: fmt.Sprintf("printf x > '%s'", marker)}, "review", t.TempDir(), nil, 100000, 5)
	p.SetNonStreaming(func() bool { return true })
	oldAugment, oldResolve := agent.ToolAugment, agent.ToolResolve
	agent.ToolAugment, agent.ToolResolve = nil, nil
	t.Cleanup(func() { agent.ToolAugment, agent.ToolResolve = oldAugment, oldResolve })

	e := NewEngine(m)
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return p, nil })
	e.SetExecBackendResolver(func(*Task) remoteexec.Backend { return remoteexec.NewFailClosedBackend("regression: no Agent") })
	e.runFinalPlannerRound(context.Background(), task)

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		data, _ := os.ReadFile(marker)
		t.Fatalf("final planner ran Bash on Management (fail-closed backend not bound): marker=%q err=%v", data, err)
	}
}

// F2: under a strict posture a non-agent-hosted MCP must not be connected on the control
// plane — the tool-assembly seam marks it handled (so it is never locally connected), and
// discovery classifies it as blocked. (DB-free.)
func TestNonHostedMCPBlockedUnderStrict(t *testing.T) {
	t.Setenv(envAgentOffload, "require")
	s := &Server{}
	m := &db.MCPServer{Name: "iso-local", Transport: "stdio", Command: "/bin/sh",
		Args: json.RawMessage(`["-c","true"]`), Enabled: true}
	if d := s.dispositionOfMCP(m); d != mcpBlockedStrict {
		t.Fatalf("non-hosted stdio MCP under require should be blocked, got disposition %d", d)
	}
	if tools, handled := s.mcpHostedTools(m); !handled || len(tools) != 0 {
		t.Fatalf("strict mode must mark a non-hosted MCP handled with no tools (no local connect), got handled=%v tools=%d", handled, len(tools))
	}
	// Sanity: in off mode the same server connects locally as before.
	t.Setenv(envAgentOffload, "off")
	if _, handled := s.mcpHostedTools(m); handled {
		t.Fatal("in off mode a non-hosted MCP must be a normal local connect (handled=false)")
	}
}

// F3: ScopeSentry sync must refuse a direct control-plane connection when the data source
// is agent-hosted (or the posture is strict) — no HTTP leaves Management.
func TestScopeSentrySyncRefusedInSplitMode(t *testing.T) {
	t.Setenv(envAgentOffload, "require")
	m := splitIsoManager(t, "")
	var requests atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer endpoint.Close()

	s := &Server{m: m}
	row, err := s.findMCPByName(scopeSentryMCPName) // NewManager may seed a placeholder row
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		row = &db.MCPServer{Name: scopeSentryMCPName}
	}
	row.Transport, row.URL, row.AgentHosted, row.Enabled = "http", endpoint.URL, true, true
	row.Env = json.RawMessage(`{"X-API-Key":"regression"}`)
	if _, err := m.pg.SaveMCP(row); err != nil {
		t.Fatal(err)
	}
	cl, err := s.scopeSentryClient(context.Background())
	if err == nil {
		if cl != nil {
			_ = cl.Close()
		}
		t.Fatal("scopeSentryClient must refuse a direct connection in split mode")
	}
	if requests.Load() != 0 {
		t.Fatalf("no HTTP should leave Management in split mode, saw %d request(s)", requests.Load())
	}
}

// F4: under a strict posture the Management recording proxy must not start, so it cannot
// act as an open forward proxy relaying target HTTP.
func TestManagementProxyDisabledUnderStrict(t *testing.T) {
	t.Setenv(envAgentOffload, "require")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	m := splitIsoManager(t, addr)
	if m.traffic != nil {
		t.Fatal("strict offload must not start the Management recording proxy")
	}

	// It must also not be listening/relaying on that address.
	u, _ := url.Parse("http://" + addr)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer target.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 500 * time.Millisecond}
	defer client.CloseIdleConnections()
	if resp, err := client.Get(target.URL); err == nil {
		resp.Body.Close()
		t.Fatal("a proxy is still relaying on the management proxy address under strict offload")
	}
}
