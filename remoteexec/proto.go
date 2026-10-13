// Package remoteexec splits ARTEX's execution plane off from its control plane.
//
// The control plane (Management Server) runs the LLM agent loop and holds all
// LLM secrets; the execution plane (Agent) runs the dangerous side-effecting
// tools — Bash, file I/O, WebFetch, WebSearch, scanners invoked via Bash — inside
// a user-provided, internet-isolated sandbox. The two talk over a single mutually
// authenticated TLS connection (see pki.go), multiplexed by the frame protocol in
// this file and driven by the Session in mux.go.
//
// The connection may be dialed from either side (infra's choice): Management→Agent
// or Agent→Management. Who dials is independent of who calls: once the mTLS
// handshake completes, Management is always the RPC *caller* (it decides which
// tool to run) and the Agent is always the RPC *server* (it executes). The frame
// protocol is symmetric, so the reverse direction (Agent pushing enrichment/traffic
// events back to Management) rides the same connection without a second socket.
package remoteexec

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Autumn-27/norma/llm"
)

// maxFrameBytes caps a single frame's JSON payload. Tool output that would exceed
// it is spilled to the Agent's OutputDir before crossing the wire (the harness does
// this for us via ToolContext.OutputDir), so a legitimate frame stays well under
// this. The cap exists only to stop a corrupt or hostile length prefix from forcing
// an unbounded allocation.
const maxFrameBytes = 64 << 20 // 64 MiB

// FrameKind tags what a frame carries. The set is deliberately small; new control
// messages get a new kind rather than overloading an existing one.
type FrameKind string

const (
	// KindHello is sent once by the Agent right after the handshake, announcing its
	// id and the tools it can execute. Management waits for it before routing work.
	KindHello FrameKind = "hello"
	// KindCall asks the peer to execute one tool. Carries a caller-chosen Id used to
	// match the eventual KindResult (and any KindProgress) back to the waiter.
	KindCall FrameKind = "call"
	// KindProgress is an optional incremental update emitted while a call runs; it
	// maps onto norma's tool.ProgressInfo / ToolContext.Emit.
	KindProgress FrameKind = "progress"
	// KindResult is the terminal frame for a call: the tool.Result plus any
	// transport/handler error string. Exactly one is sent per Id.
	KindResult FrameKind = "result"
	// KindCancel tells the peer the caller's context was cancelled; the peer cancels
	// the in-flight tool context so a long Bash run is actually killed.
	KindCancel FrameKind = "cancel"
	// KindEvent is a one-way push with no reply (enrichment asset discoveries,
	// traffic-evidence notices). The reverse of KindCall; Id is ignored.
	KindEvent FrameKind = "event"
	// KindPing / KindPong are the application-level keepalive, independent of TCP so a
	// silently dead peer (sandbox torn down) is detected.
	KindPing FrameKind = "ping"
	KindPong FrameKind = "pong"
)

// Frame is one unit on the wire: a 4-byte big-endian length prefix followed by the
// JSON encoding of this struct. Fields are reused across kinds; absent ones stay at
// their zero value and omitempty keeps them off the wire.
type Frame struct {
	Kind FrameKind `json:"kind"`
	// Id matches a KindResult/KindProgress to the KindCall that started it. The
	// caller picks it; it is unique per caller (see Session's side prefix in mux.go)
	// so results route unambiguously even though both peers may originate calls.
	Id string `json:"id,omitempty"`

	// Call fields (KindCall).
	Tool  string          `json:"tool,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	TC    *WireToolCtx    `json:"tc,omitempty"`

	// Result fields (KindResult).
	Result *WireResult `json:"result,omitempty"`
	// Err, when non-empty, is a transport/handler error (tool *not* run, or run
	// aborted) — distinct from a tool that ran and returned Result.IsError. It maps
	// to the error return of CoreTool.Call.
	Err string `json:"err,omitempty"`

	// Progress field (KindProgress).
	Message string `json:"message,omitempty"`

	// Hello fields (KindHello).
	AgentID string   `json:"agent_id,omitempty"`
	Tools   []string `json:"tools,omitempty"`

	// Event fields (KindEvent): a named event with an opaque JSON body, decoded by
	// whoever registered for that event name.
	Event string          `json:"event,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
}

// WireToolCtx is the subset of norma's tool.ToolContext that is meaningful across
// the boundary. WorkingDir / OutputDir are resolved to the *Agent's* sandbox paths
// on the far side (they are advisory hints, not Management paths), and Env carries
// only non-secret egress hints — in practice the Agent injects its own proxy/CA env
// locally and ignores inbound Env, so no LLM secret can ride along here. The live
// bits of ToolContext (Emit, Tasks) are reconstructed on the Agent and streamed back
// as KindProgress rather than serialized.
type WireToolCtx struct {
	WorkingDir     string `json:"working_dir,omitempty"`
	ToolUseID      string `json:"tool_use_id,omitempty"`
	MaxOutputChars int    `json:"max_output_chars,omitempty"`
	OutputDir      string `json:"output_dir,omitempty"`
}

// WireResult is the serializable projection of norma's tool.Result.
type WireResult struct {
	Content []llm.ContentBlock `json:"content,omitempty"`
	IsError bool               `json:"is_error,omitempty"`
	Extra   []llm.Message      `json:"extra,omitempty"`
}

// writeFrame length-prefixes and writes one frame. Callers must serialize writes on
// a single conn; the Session does this with a dedicated write goroutine.
func writeFrame(w io.Writer, f *Frame) error {
	payload, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("remoteexec: marshal frame: %w", err)
	}
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("remoteexec: frame too large (%d bytes > %d)", len(payload), maxFrameBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame. It returns io.EOF cleanly when the peer
// closes between frames (not mid-frame).
func readFrame(r io.Reader) (*Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("remoteexec: zero-length frame")
	}
	if n > maxFrameBytes {
		return nil, fmt.Errorf("remoteexec: inbound frame too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		// A partial frame is a protocol error, not a clean EOF.
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return nil, fmt.Errorf("remoteexec: unmarshal frame: %w", err)
	}
	return &f, nil
}
