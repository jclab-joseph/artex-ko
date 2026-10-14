package remoteexec

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// peerCertCN returns the CommonName of the TLS peer's leaf certificate. The caller must
// invoke it only after the handshake has completed (e.g. after waitHello), so the peer
// certificates are populated. It is how Management binds the agent id a connection
// registers under to the certificate the peer actually presented — a CA-valid cert can no
// longer claim another agent's id in its hello (보안 리뷰 F8).
func peerCertCN(conn net.Conn) (string, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("remoteexec: connection is not TLS")
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", fmt.Errorf("remoteexec: peer presented no certificate")
	}
	return st.PeerCertificates[0].Subject.CommonName, nil
}

// bindAgentIdentity verifies the peer's certificate CN matches the agent id it announced
// in hello, so a connection is registered under the identity it proved, not one it merely
// claimed. Returns an error (the caller closes the session) on any mismatch.
func bindAgentIdentity(conn net.Conn, hello *Frame) error {
	cn, err := peerCertCN(conn)
	if err != nil {
		return err
	}
	if want := agentCN(hello.AgentID); cn != want {
		return fmt.Errorf("remoteexec: agent cert CN %q does not match announced id %q", cn, want)
	}
	return nil
}

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
		conn, err := acceptAuthenticated(ctx, ln)
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
// timeout via ctx. It is a convenience that accepts one raw connection and authenticates
// it inline; a long-lived registry that must not let one stalled peer block others should
// use AcceptConn + Handshake and run Handshake per-connection in its own goroutine.
func (l *AgentListener) Accept(ctx context.Context) (*Session, *Frame, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, nil, err
	}
	return l.Handshake(ctx, conn)
}

// AcceptConn returns the next raw (pre-handshake) connection. The caller must authenticate
// it with Handshake — ideally in a separate goroutine, so a peer that connects but never
// completes the TLS handshake / never sends its hello cannot block the accept loop and
// starve legitimate Agents (보안 리뷰: 미인증 TCP 연결 하나가 Management 수신을 점유).
func (l *AgentListener) AcceptConn() (net.Conn, error) { return l.ln.Accept() }

// Handshake drives one accepted connection through the TLS handshake (bounded by
// handshakeTimeout so a silent peer is dropped, not parked) and the Agent hello, binding
// the announced agent id to the presented client certificate. On any failure it closes the
// connection/session and returns the error; the caller drops that peer and keeps serving.
func (l *AgentListener) Handshake(ctx context.Context, conn net.Conn) (*Session, *Frame, error) {
	if tc, ok := conn.(*tls.Conn); ok {
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("remoteexec: agent TLS handshake: %w", err)
		}
	}
	sess := newSession(conn, "mgmt", nil)
	sess.startKeepalive(keepaliveInterval)
	hello, err := sess.waitHello(ctx)
	if err != nil {
		sess.Close()
		return nil, nil, fmt.Errorf("remoteexec: waiting for agent hello: %w", err)
	}
	// Bind the announced agent id to the mTLS client cert: a CA-valid Agent cannot
	// register under another Agent's id (보안 리뷰 F8).
	if err := bindAgentIdentity(conn, hello); err != nil {
		sess.Close()
		return nil, nil, err
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
	// The dial already pinned the cert CN to agentID; also bind the hello's self-declared
	// id to that same cert, so a listening Agent cannot register under a different id than
	// the one it proved (보안 리뷰 F8).
	if err := bindAgentIdentity(conn, hello); err != nil {
		sess.Close()
		return nil, nil, err
	}
	return sess, hello, nil
}

func startAgentSession(conn net.Conn, agentID string, exec *Executor) *Session {
	disp := exec.NewConn()
	sess := newSession(conn, "agent", disp)
	sess.startKeepalive(keepaliveInterval)
	sess.sendHello(agentID, exec.ToolNames(), exec.ToolMetas())
	// When this connection ends (drop or Close), tear down the execution sessions it owns
	// and mark its epoch dead, so a call whose goroutine was already serving when the
	// connection dropped is refused instead of recreating a dead connection's session
	// (보안 리뷰: 연결 종료 후 지연 호출).
	go func() {
		<-sess.Done()
		disp.close()
	}()
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

// handshakeTimeout bounds a single accepted connection's TLS handshake on the listening
// Agent, so a peer that connects but never completes (or never starts) the handshake is
// dropped instead of occupying the Agent.
const handshakeTimeout = 10 * time.Second

// acceptAuthenticated returns the first accepted connection that COMPLETES the TLS
// handshake within handshakeTimeout. A listening Agent (ModeMgmtDials) otherwise treated
// a raw TCP peer as its session the moment it connected — the handshake is lazy, so a
// peer that sent nothing left the Agent "connected" and, because the listener is closed
// after one accept, blocked the real Management from ever connecting (보안 리뷰: 미인증
// TCP 연결 하나가 Agent 를 점유). Connections are accepted continuously and handshaked
// concurrently, so a stalled peer cannot delay a legitimate one; the first to authenticate
// wins and the listener is closed, dropping the rest.
func acceptAuthenticated(ctx context.Context, ln net.Listener) (net.Conn, error) {
	winner := make(chan *tls.Conn, 1)
	var won atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed (a winner was chosen, or ctx cancelled)
			}
			tc, ok := conn.(*tls.Conn)
			if !ok {
				_ = conn.Close()
				continue
			}
			go func() {
				hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
				defer cancel()
				if err := tc.HandshakeContext(hctx); err != nil {
					_ = tc.Close()
					return
				}
				if won.CompareAndSwap(false, true) {
					winner <- tc
					_ = ln.Close() // stop accepting; unblocks the Accept loop above
				} else {
					_ = tc.Close() // a peer already won
				}
			}()
		}
	}()
	select {
	case tc := <-winner:
		return tc, nil
	case <-ctx.Done():
		_ = ln.Close()
		return nil, ctx.Err()
	}
}
