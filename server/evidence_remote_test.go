package server

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agentctl"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// markerEvidenceTool hosts a fake __artex_traffic_evidence that always returns one exchange
// whose URL encodes which Agent answered, so a test can tell which sandbox the evidence came
// from.
func markerEvidenceTool(marker string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        traffic.EvidenceToolName,
		Description: "test evidence source",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			out := traffic.EvidenceWireResult{Exchanges: []traffic.EvidenceWireExchange{{
				ID: marker, TS: 1, URL: "http://" + marker + "/", Method: "GET", Status: 200,
			}}}
			b, _ := json.Marshal(out)
			return actool.Text(string(b)), nil
		},
	})
}

// connectMarkerAgent registers a ModeMgmtDials Agent (Management dials it) under agentID that
// hosts markerEvidenceTool(marker), and returns the agent-side session for cleanup.
func connectMarkerAgent(t *testing.T, ctx context.Context, mgr *agentctl.Manager, agentID, marker string) *remoteexec.Session {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // free the port for the agent listener
	bundle, err := mgr.IssueBundle(remoteexec.ModeMgmtDials, addr, agentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	exec := remoteexec.NewExecutor([]actool.CoreTool{markerEvidenceTool(marker)}, t.TempDir(), nil)
	sessCh := make(chan *remoteexec.Session, 1)
	go func() {
		if s, e := remoteexec.ConnectAgentSide(ctx, bundle, exec); e == nil {
			sessCh <- s
		}
	}()
	// Management dials the listening agent (retry until it is bound).
	var derr error
	for i := 0; i < 100; i++ {
		if _, e := mgr.DialAgent(ctx, agentID, addr); e == nil {
			derr = nil
			break
		} else {
			derr = e
			time.Sleep(20 * time.Millisecond)
		}
	}
	if derr != nil {
		t.Fatalf("dial agent %s: %v", agentID, derr)
	}
	select {
	case s := <-sessCh:
		return s
	case <-time.After(5 * time.Second):
		t.Fatalf("agent %s never established a session", agentID)
		return nil
	}
}

// TestRemoteEvidenceRoutesToPinnedAgentNotNewest proves split-mode evidence is pulled from
// the sandbox Agent that EXECUTED the task (its pinned Agent), never from the newest-connected
// one. In a multi-Agent / multi-tenant deployment (agent == tenant) the old newest-Agent
// routing would read another tenant's capture — wrong data and a cross-tenant leak.
func TestRemoteEvidenceRoutesToPinnedAgentNotNewest(t *testing.T) {
	mgr, err := agentctl.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// tenant-a connects first (older); tenant-b connects second (newest-connected).
	aSess := connectMarkerAgent(t, ctx, mgr, "tenant-a", "tenant-a")
	defer aSess.Close()
	time.Sleep(15 * time.Millisecond) // distinct ConnectedAt, so "newest" is unambiguously tenant-b
	bSess := connectMarkerAgent(t, ctx, mgr, "tenant-b", "tenant-b")
	defer bSess.Close()

	// --- Manual-bind path (no backend on the ctx): route via the task's pin. ---
	// The task was executed by (pinned to) tenant-a — the OLDER connection.
	mgr.PinTask("42", "tenant-a")

	src := &splitEvidenceSource{agents: mgr, taskID: "42"}
	var got []string
	if err := src.ReadEvidence(ctx, []string{"x"}, func(e traffic.EvidenceExchange) error {
		got = append(got, e.URL)
		return nil
	}); err != nil {
		t.Fatalf("ReadEvidence from the pinned agent failed: %v", err)
	}
	if len(got) != 1 || got[0] != "http://tenant-a/" {
		t.Fatalf("evidence came from the wrong Agent: %v (want tenant-a; newest-connected was tenant-b — newest-routing is the bug)", got)
	}

	// Pinned to an Agent that is not connected → fail closed, never fall back to another.
	mgr.PinTask("99", "tenant-ghost")
	ghost := &splitEvidenceSource{agents: mgr, taskID: "99"}
	if err := ghost.ReadEvidence(ctx, []string{"x"}, func(traffic.EvidenceExchange) error { return nil }); err == nil {
		t.Fatal("evidence for a task pinned to a disconnected Agent must fail closed, not fall back to a connected one")
	}

	// No pin at all → fail closed (must NOT silently use the newest-connected Agent).
	noPin := &splitEvidenceSource{agents: mgr, taskID: "no-such-task"}
	if err := noPin.ReadEvidence(ctx, []string{"x"}, func(traffic.EvidenceExchange) error { return nil }); err == nil {
		t.Fatal("evidence for an unpinned task must fail closed, not use the newest-connected Agent")
	}

	// --- During-run path: the executing Agent's backend is on the ctx. It is authoritative
	// in every offload mode (require/auto never pin), so evidence must come from THAT Agent
	// even if a (stale/other) pin points elsewhere. Here the backend is tenant-b while the
	// task is pinned to tenant-a → evidence must be tenant-b's.
	runCtx := remoteexec.WithBackend(ctx, mgr.Backend("tenant-b"))
	var runGot []string
	if err := src.ReadEvidence(runCtx, []string{"x"}, func(e traffic.EvidenceExchange) error {
		runGot = append(runGot, e.URL)
		return nil
	}); err != nil {
		t.Fatalf("ReadEvidence via the executing backend failed: %v", err)
	}
	if len(runGot) != 1 || runGot[0] != "http://tenant-b/" {
		t.Fatalf("during a run, evidence must come from the executing Agent on the ctx: %v (want tenant-b)", runGot)
	}
}
