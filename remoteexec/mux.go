package remoteexec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Dispatcher executes an inbound tool call. The Agent side provides one backed by a
// real norma tool registry; Management usually leaves it nil (it only calls out).
type Dispatcher interface {
	// ServeCall runs the named tool. progress, when non-nil, may be invoked any number
	// of times before the call returns to stream incremental output. The returned
	// error is a transport/handler failure (tool could not run); a tool that ran and
	// failed returns its failure inside WireResult.IsError with a nil error.
	ServeCall(ctx context.Context, tool string, input json.RawMessage, tc *WireToolCtx, progress func(string)) (*WireResult, error)
}

// ErrSessionClosed is returned by Call once the underlying connection is gone.
var ErrSessionClosed = errors.New("remoteexec: session closed")

type pendingCall struct {
	resultCh chan *Frame
	progress func(string)
}

// Session multiplexes calls, results, progress and events over one connection. It is
// symmetric: either peer may Call, and either may serve inbound calls if it has a
// Dispatcher. A Session is safe for concurrent use.
type Session struct {
	conn io.ReadWriteCloser
	side string // ID namespace so two peers' call ids never collide

	dispatcher   Dispatcher
	eventHandler func(name string, body json.RawMessage)

	writeCh chan *Frame
	counter atomic.Uint64

	mu       sync.Mutex
	pending  map[string]*pendingCall       // calls I originated, awaiting result
	inbound  map[string]context.CancelFunc // calls I am serving, cancellable by peer
	closed   bool
	closeErr error

	helloCh   chan *Frame
	closeOnce sync.Once
	done      chan struct{}
}

// newSession wires a Session over conn and starts its read/write loops. side must
// differ between the two peers ("mgmt" vs "agent"); dispatcher may be nil on a
// call-only peer.
func newSession(conn io.ReadWriteCloser, side string, dispatcher Dispatcher) *Session {
	s := &Session{
		conn:       conn,
		side:       side,
		dispatcher: dispatcher,
		writeCh:    make(chan *Frame, 64),
		pending:    make(map[string]*pendingCall),
		inbound:    make(map[string]context.CancelFunc),
		helloCh:    make(chan *Frame, 1),
		done:       make(chan struct{}),
	}
	go s.writeLoop()
	go s.readLoop()
	return s
}

// SetEventHandler registers a callback for one-way KindEvent pushes. Safe to call
// before the peer sends events; nil (the default) drops events.
func (s *Session) SetEventHandler(h func(name string, body json.RawMessage)) {
	s.mu.Lock()
	s.eventHandler = h
	s.mu.Unlock()
}

// Done is closed when the session ends (peer closed, I/O error, or Close).
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session closed, or nil while it is live.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case f := <-s.writeCh:
			if err := writeFrame(s.conn, f); err != nil {
				s.closeWith(err)
				return
			}
		}
	}
}

// send enqueues a frame; it never blocks the caller past the session's lifetime.
func (s *Session) send(f *Frame) {
	select {
	case s.writeCh <- f:
	case <-s.done:
	}
}

func (s *Session) readLoop() {
	for {
		f, err := readFrame(s.conn)
		if err != nil {
			if err == io.EOF {
				err = ErrSessionClosed
			}
			s.closeWith(err)
			return
		}
		s.route(f)
	}
}

func (s *Session) route(f *Frame) {
	switch f.Kind {
	case KindHello:
		select {
		case s.helloCh <- f:
		default:
		}
	case KindResult:
		s.deliverResult(f)
	case KindProgress:
		s.deliverProgress(f)
	case KindCall:
		s.serveInbound(f)
	case KindCancel:
		s.cancelInbound(f.Id)
	case KindEvent:
		s.mu.Lock()
		h := s.eventHandler
		s.mu.Unlock()
		if h != nil {
			h(f.Event, f.Body)
		}
	case KindPing:
		s.send(&Frame{Kind: KindPong})
	case KindPong:
		// liveness noted implicitly; keepalive loop checks the connection via writes
	}
}

func (s *Session) deliverResult(f *Frame) {
	s.mu.Lock()
	pc := s.pending[f.Id]
	delete(s.pending, f.Id)
	s.mu.Unlock()
	if pc != nil {
		pc.resultCh <- f
	}
}

func (s *Session) deliverProgress(f *Frame) {
	s.mu.Lock()
	pc := s.pending[f.Id]
	s.mu.Unlock()
	if pc != nil && pc.progress != nil {
		pc.progress(f.Message)
	}
}

// serveInbound runs an inbound call on its own goroutine so the read loop keeps
// draining (progress, cancels, other calls) while a tool runs.
func (s *Session) serveInbound(f *Frame) {
	if s.dispatcher == nil {
		s.send(&Frame{Kind: KindResult, Id: f.Id, Err: "remoteexec: peer has no execution dispatcher"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.inbound[f.Id] = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.inbound, f.Id)
			s.mu.Unlock()
			cancel()
		}()
		progress := func(msg string) {
			s.send(&Frame{Kind: KindProgress, Id: f.Id, Message: msg})
		}
		res, err := s.dispatcher.ServeCall(ctx, f.Tool, f.Input, f.TC, progress)
		out := &Frame{Kind: KindResult, Id: f.Id}
		if err != nil {
			out.Err = err.Error()
		}
		out.Result = res
		s.send(out)
	}()
}

func (s *Session) cancelInbound(id string) {
	s.mu.Lock()
	cancel := s.inbound[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Call invokes a tool on the peer and blocks until the peer returns a result, the
// context is cancelled, or the session closes. onProgress, when non-nil, receives
// streamed progress messages. The returned error is a transport error; a tool error
// is carried inside the returned *WireResult (IsError).
func (s *Session) Call(ctx context.Context, tool string, input json.RawMessage, tc *WireToolCtx, onProgress func(string)) (*WireResult, error) {
	id := s.side + "-" + strconvU(s.counter.Add(1))
	pc := &pendingCall{resultCh: make(chan *Frame, 1), progress: onProgress}

	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		if err == nil {
			err = ErrSessionClosed
		}
		return nil, err
	}
	s.pending[id] = pc
	s.mu.Unlock()

	s.send(&Frame{Kind: KindCall, Id: id, Tool: tool, Input: input, TC: tc})

	select {
	case f := <-pc.resultCh:
		if f.Err != "" {
			return f.Result, errors.New(f.Err)
		}
		return f.Result, nil
	case <-ctx.Done():
		// Tell the peer to kill the running tool, then stop waiting.
		s.send(&Frame{Kind: KindCancel, Id: id})
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, ctx.Err()
	case <-s.done:
		err := s.Err()
		if err == nil {
			err = ErrSessionClosed
		}
		return nil, err
	}
}

// Emit sends a one-way event to the peer (no reply). Used for Agent→Management
// enrichment/traffic pushes.
func (s *Session) Emit(event string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	s.send(&Frame{Kind: KindEvent, Event: event, Body: raw})
	return nil
}

// sendHello announces this peer's identity and tool set. The Agent calls it right
// after connecting.
func (s *Session) sendHello(agentID string, tools []string, metas []WireToolMeta) {
	s.send(&Frame{Kind: KindHello, AgentID: agentID, Tools: tools, ToolMetas: metas})
}

// waitHello blocks for the peer's hello (the Agent's announcement) or ctx/close.
func (s *Session) waitHello(ctx context.Context) (*Frame, error) {
	select {
	case f := <-s.helloCh:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		err := s.Err()
		if err == nil {
			err = ErrSessionClosed
		}
		return nil, err
	}
}

// startKeepalive pings the peer every interval; a write failure tears the session
// down via writeLoop. Cheap liveness independent of TCP keepalive.
func (s *Session) startKeepalive(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				s.send(&Frame{Kind: KindPing})
			}
		}
	}()
}

func (s *Session) closeWith(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.closeErr = err
		pending := s.pending
		s.pending = map[string]*pendingCall{}
		s.mu.Unlock()
		close(s.done)
		_ = s.conn.Close()
		// Fail every outstanding call so callers unblock.
		for _, pc := range pending {
			select {
			case pc.resultCh <- &Frame{Kind: KindResult, Err: errString(err)}:
			default:
			}
		}
	})
}

// Close shuts the session down and fails outstanding calls.
func (s *Session) Close() error {
	s.closeWith(ErrSessionClosed)
	return nil
}

func errString(err error) string {
	if err == nil {
		return ErrSessionClosed.Error()
	}
	return err.Error()
}

// strconvU formats a uint64 without importing strconv into hot paths repeatedly;
// kept local so the file is self-contained.
func strconvU(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
