package remoteexec

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// TestConnectionCloseCancelsSessionlessInbound: a tool call carrying NO execution-session
// id (e.g. a sessionless ExecAny) must be cancelled when the connection drops, rather than
// running to completion uncancelled (보안 리뷰: 연결 종료가 세션 ID 없는 실행을 취소하지 않음).
func TestConnectionCloseCancelsSessionlessInbound(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	blocking := actool.Build(actool.Spec{
		Name:        "block",
		Description: "blocks until its context is cancelled",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return actool.Text("cancelled"), nil
		},
	})
	exec := NewExecutor([]actool.CoreTool{blocking}, t.TempDir(), nil)
	mgmt, _, closeFn := InProcess(exec)
	defer closeFn()

	go func() {
		// No SessionID: a sessionless call, not reached by per-session teardown.
		_, _ = mgmt.Call(context.Background(), "block", json.RawMessage(`{}`), &WireToolCtx{WorkingDir: "enrich"}, nil)
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("tool never started")
	}
	mgmt.Close() // connection drops
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("sessionless inbound call was not cancelled when the connection closed")
	}
}

// TestListeningAgentRequiresHandshake: a listening Agent (ModeMgmtDials) must not treat a
// raw TCP peer that never completes the TLS handshake as its session, nor let such a peer
// block a legitimate Management connection (보안 리뷰: 미인증 TCP 연결 하나가 Agent 를 점유).
func TestListeningAgentRequiresHandshake(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	aid, err := ca.IssueAgent("ta")
	if err != nil {
		t.Fatal(err)
	}
	mid, err := ca.IssueManagement()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free the port for the Agent listener

	bundle := &Bundle{Version: 1, Mode: ModeMgmtDials, AgentID: "ta", Address: addr, CACert: ca.CertPEM, Identity: aid}
	exec := NewExecutor(nil, t.TempDir(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessCh := make(chan *Session, 1)
	errCh := make(chan error, 1)
	go func() {
		s, e := ConnectAgentSide(ctx, bundle, exec)
		if e != nil {
			errCh <- e
			return
		}
		sessCh <- s
	}()

	// A raw TCP peer that sends nothing (never completes the handshake).
	var raw net.Conn
	for i := 0; i < 50; i++ {
		if c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond); e == nil {
			raw = c
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if raw == nil {
		t.Fatal("could not open a raw TCP connection to the Agent listener")
	}
	defer raw.Close()

	// A legitimate Management dial must still connect promptly, not blocked by the idle peer.
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	msess, _, derr := DialAgent(dctx, addr, mid, string(ca.CertPEM), "ta")
	if derr != nil {
		t.Fatalf("a legitimate Management dial was blocked/failed by an idle raw TCP peer: %v", derr)
	}
	defer msess.Close()

	select {
	case s := <-sessCh:
		s.Close() // the Agent established its session from the authenticated dial
	case e := <-errCh:
		t.Fatalf("Agent connect errored: %v", e)
	case <-time.After(5 * time.Second):
		t.Fatal("Agent never established a session despite a legitimate dial")
	}
}
