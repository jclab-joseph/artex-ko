package remoteexec

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// keepaliveInterval is the application-level ping cadence on an established session.
const keepaliveInterval = 20 * time.Second

// dialTimeout bounds a single TCP+TLS dial attempt.
const dialTimeout = 15 * time.Second

// ConnectAgentSide establishes the Agent's session from its launch bundle, handling
// both connection modes, and announces the Agent's tool set. In ModeAgentDials the
// Agent dials Management; in ModeMgmtDials the Agent listens and accepts one
// connection. The returned Session has the Executor wired as its Dispatcher. Callers
// that want to accept repeatedly should use ListenAgent instead.
func ConnectAgentSide(ctx context.Context, bundle *Bundle, exec *Executor) (*Session, error) {
	switch bundle.Mode {
	case ModeAgentDials:
		cfg, err := AgentDialTLS(bundle)
		if err != nil {
			return nil, err
		}
		conn, err := tlsDial(ctx, bundle.Address, cfg)
		if err != nil {
			return nil, err
		}
		return startAgentSession(conn, bundle.AgentID, exec), nil
	case ModeMgmtDials:
		cfg, err := AgentListenerTLS(bundle)
		if err != nil {
			return nil, err
		}
		ln, err := tls.Listen("tcp", bundle.Address, cfg)
		if err != nil {
			return nil, err
		}
		defer ln.Close()
		conn, err := acceptOne(ctx, ln)
		if err != nil {
			return nil, err
		}
		return startAgentSession(conn, bundle.AgentID, exec), nil
	default:
		return nil, fmt.Errorf("remoteexec: unknown connection mode %q", bundle.Mode)
	}
}

// AgentListener accepts Agent connections on the Management side when the Agent dials
// in (ModeAgentDials). The caller loops on Accept and binds each returned Session to a
// task. It is a thin wrapper over a tls.Listener using MgmtListenerTLS.
type AgentListener struct {
	ln net.Listener
}

// ListenForAgents opens a Management-side mTLS listener for Agents dialing in.
func ListenForAgents(addr string, mgmtID Identity, caPEM []byte) (*AgentListener, error) {
	cfg, err := MgmtListenerTLS(mgmtID, caPEM)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &AgentListener{ln: ln}, nil
}

// Accept blocks for the next Agent, returning a Management-side Session (call-only; no
// Dispatcher) and the Agent's hello (id + tool set). The caller controls the hello
// timeout via ctx.
func (l *AgentListener) Accept(ctx context.Context) (*Session, *Frame, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, nil, err
	}
	sess := newSession(conn, "mgmt", nil)
	sess.startKeepalive(keepaliveInterval)
	hello, err := sess.waitHello(ctx)
	if err != nil {
		sess.Close()
		return nil, nil, fmt.Errorf("remoteexec: waiting for agent hello: %w", err)
	}
	return sess, hello, nil
}

// Addr returns the listener's address (useful when addr used :0).
func (l *AgentListener) Addr() net.Addr { return l.ln.Addr() }

// Close stops accepting.
func (l *AgentListener) Close() error { return l.ln.Close() }

// DialAgent establishes a Management-side session to a listening Agent
// (ModeMgmtDials). It returns the session and the Agent's hello.
func DialAgent(ctx context.Context, addr string, mgmtID Identity, caPEM, agentID string) (*Session, *Frame, error) {
	cfg, err := MgmtDialTLS(mgmtID, []byte(caPEM), agentID)
	if err != nil {
		return nil, nil, err
	}
	conn, err := tlsDial(ctx, addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	sess := newSession(conn, "mgmt", nil)
	sess.startKeepalive(keepaliveInterval)
	hello, err := sess.waitHello(ctx)
	if err != nil {
		sess.Close()
		return nil, nil, fmt.Errorf("remoteexec: waiting for agent hello: %w", err)
	}
	return sess, hello, nil
}

func startAgentSession(conn net.Conn, agentID string, exec *Executor) *Session {
	sess := newSession(conn, "agent", exec)
	sess.startKeepalive(keepaliveInterval)
	sess.sendHello(agentID, exec.ToolNames())
	return sess
}

func tlsDial(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
	d := &tls.Dialer{Config: cfg}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("remoteexec: dial %s: %w", addr, err)
	}
	return conn, nil
}

func acceptOne(ctx context.Context, ln net.Listener) (net.Conn, error) {
	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
