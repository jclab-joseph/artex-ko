package remoteexec

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func tlsListen(t *testing.T, addr string, cfg *tls.Config) (net.Listener, error) {
	t.Helper()
	return tls.Listen("tcp", addr, cfg)
}

// bashInput builds the JSON a Bash tool call carries.
func bashInput(t *testing.T, cmd string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]string{"command": cmd})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// callBashVia drives a Bash call through a Management-side session and returns the
// flattened text output.
func callBashVia(t *testing.T, backend Backend, cmd string) actool.Result {
	t.Helper()
	meta := actool.NewBash()
	tool := backend.Wrap(meta)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := tool.Call(ctx, bashInput(t, cmd), &actool.ToolContext{WorkingDir: "tasks/1/i1"})
	if err != nil {
		t.Fatalf("Bash call errored: %v", err)
	}
	return res
}

func TestInProcessBashEcho(t *testing.T) {
	root := t.TempDir()
	exec := NewExecutor(DefaultAgentTools("", "", false), root, nil)
	_, backend, closeFn := InProcess(exec)
	defer closeFn()

	if !backend.IsRemote() || !backend.Executes("Bash") {
		t.Fatalf("backend should execute Bash remotely")
	}
	res := callBashVia(t, backend, "echo artex-remote-ok")
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "artex-remote-ok") {
		t.Fatalf("missing echo output, got: %q", res.Flatten())
	}
}

// TestInProcessCancel verifies a cancelled context kills a long remote run promptly.
func TestInProcessCancel(t *testing.T) {
	root := t.TempDir()
	exec := NewExecutor(DefaultAgentTools("", "", false), root, nil)
	_, backend, closeFn := InProcess(exec)
	defer closeFn()

	meta := actool.NewBash()
	tool := backend.Wrap(meta)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = tool.Call(ctx, bashInput(t, "sleep 30"), &actool.ToolContext{WorkingDir: "tasks/1/i1"})
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled Bash call did not return promptly")
	}
}

func TestMTLSRoundtrip(t *testing.T) {
	for _, mode := range []ConnMode{ModeAgentDials, ModeMgmtDials} {
		t.Run(string(mode), func(t *testing.T) {
			runMTLSRoundtrip(t, mode)
		})
	}
}

func runMTLSRoundtrip(t *testing.T, mode ConnMode) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	mgmtID, err := ca.IssueManagement()
	if err != nil {
		t.Fatal(err)
	}
	agentID := "test-agent"
	agentIdentity, err := ca.IssueAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	exec := NewExecutor(DefaultAgentTools("", "", false), root, nil)

	var backend *RemoteBackend
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch mode {
	case ModeAgentDials:
		// Management listens; Agent dials in.
		ln, err := ListenForAgents("127.0.0.1:0", mgmtID, ca.CertPEM)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		bundle := &Bundle{Version: 1, Mode: ModeAgentDials, AgentID: agentID, Address: ln.Addr().String(), CACert: ca.CertPEM, Identity: agentIdentity}

		agentErr := make(chan error, 1)
		go func() {
			_, e := ConnectAgentSide(ctx, bundle, exec)
			agentErr <- e
		}()
		sess, hello, err := ln.Accept(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if hello.AgentID != agentID {
			t.Fatalf("hello agent id = %q, want %q", hello.AgentID, agentID)
		}
		if e := <-agentErr; e != nil {
			t.Fatalf("agent connect: %v", e)
		}
		backend = NewRemoteBackend(sess, hello.Tools)

	case ModeMgmtDials:
		// Agent listens; Management dials it.
		bundle := &Bundle{Version: 1, Mode: ModeMgmtDials, AgentID: agentID, Address: "127.0.0.1:0", CACert: ca.CertPEM, Identity: agentIdentity}
		// We need the actual listen address; open the listener here to learn the port,
		// then hand it to ConnectAgentSide via a fixed address.
		// Simpler: bind to an ephemeral port by letting the agent listen and reporting.
		lnCfg, err := AgentListenerTLS(bundle)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := tlsListen(t, "127.0.0.1:0", lnCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		addr := ln.Addr().String()

		agentSessCh := make(chan *Session, 1)
		go func() {
			conn, e := ln.Accept()
			if e != nil {
				agentSessCh <- nil
				return
			}
			s := newSession(conn, "agent", exec)
			s.sendHello(agentID, exec.ToolNames(), exec.ToolMetas())
			agentSessCh <- s
		}()

		sess, hello, err := DialAgent(ctx, addr, mgmtID, string(ca.CertPEM), agentID)
		if err != nil {
			t.Fatalf("dial agent: %v", err)
		}
		if <-agentSessCh == nil {
			t.Fatal("agent accept failed")
		}
		backend = NewRemoteBackend(sess, hello.Tools)
	}

	res := callBashVia(t, backend, "echo mtls-"+string(mode))
	if res.IsError || !strings.Contains(res.Flatten(), "mtls-"+string(mode)) {
		t.Fatalf("mtls roundtrip output wrong: err=%v out=%q", res.IsError, res.Flatten())
	}
}
