package remoteexec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// delayedFrameConn pauses the read loop at the exact moment it has fully decoded a frame
// but before readLoop routes it, so a close can be interleaved between the two. This
// reproduces the "frame read before Close, registered after closeWith()" ordering the
// reviewer flagged for serveInbound (보안 리뷰: 연결 종료와 호출 등록 경합 시 취소 누락).
type delayedFrameConn struct {
	r       *bytes.Reader
	ready   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *delayedFrameConn) Read(p []byte) (int, error) {
	n, e := c.r.Read(p)
	if n > 0 && c.r.Len() == 0 {
		c.once.Do(func() { close(c.ready); <-c.release })
	}
	return n, e
}
func (c *delayedFrameConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *delayedFrameConn) Close() error                { return nil }

var _ io.ReadWriteCloser = (*delayedFrameConn)(nil)

// TestInboundCallRegisteredAfterCloseIsCancelled: a call whose frame was fully read before
// the session closed but whose serveInbound registration lands after closeWith() has
// snapshotted the inbound map must NOT run with a live, never-cancelled context. The fix
// checks s.closed and registers under the same lock, so such a late call is either never
// started or started already cancelled — it can never execute uncancellable past the
// connection's death.
func TestInboundCallRegisteredAfterCloseIsCancelled(t *testing.T) {
	started := make(chan context.Context, 1)
	finish := make(chan struct{})
	defer close(finish)
	tool := actool.Build(actool.Spec{
		Name:   "audit",
		Schema: map[string]any{"type": "object"},
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			started <- ctx
			<-finish
			return actool.Text("done"), nil
		},
	})
	executor := NewExecutor([]actool.CoreTool{tool}, t.TempDir(), nil)
	_ = executor.EnableBackgroundTasks("audit")
	// Keep the dispatcher's epoch LIVE so the per-connection epoch check (a separate guard)
	// does not refuse this late call — this isolates the mux-level inbound-registration race,
	// which is the only thing the fix under test addresses.
	dispatcher := executor.NewConn()
	defer executor.Cleanup()

	var buf bytes.Buffer
	if e := writeFrame(&buf, &Frame{Kind: KindCall, Id: "mgmt-1", Tool: "audit", TC: &WireToolCtx{WorkingDir: "enrich"}}); e != nil {
		t.Fatal(e)
	}
	conn := &delayedFrameConn{r: bytes.NewReader(buf.Bytes()), ready: make(chan struct{}), release: make(chan struct{})}
	sess := newSession(conn, "agent", dispatcher)
	defer sess.Close()

	<-conn.ready        // the frame is fully read; readLoop is paused before routing it
	sess.Close()        // tear the session down first (closeWith snapshots+cancels inbound)
	close(conn.release) // now let the read return → route → serveInbound registers the call

	select {
	case ctx := <-started:
		// If the late call ran at all, teardown must already have cancelled its context.
		select {
		case <-ctx.Done():
			// acceptable: it ran but was cancelled promptly
		case <-time.After(time.Second):
			t.Fatal("a call registered after Session.Close ran with a live, never-cancelled context")
		}
	case <-time.After(500 * time.Millisecond):
		// preferred outcome: the close check refused the late registration, tool never started
	}
}
