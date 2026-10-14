package remoteexec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// TestHostedToolPanicDoesNotCrashAgent: a hosted tool whose handler panics must be converted
// into an error result, never unwind serveInbound's goroutine and crash the whole sandbox
// Agent process. Without the recover in callToolGuarded this test aborts the binary (the
// panic propagates straight through ServeCall) (보안 리뷰: Agent 측 패닉 가드 부재).
func TestHostedToolPanicDoesNotCrashAgent(t *testing.T) {
	panicky := actool.Build(actool.Spec{
		Name:        "boom",
		Description: "panics on call",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			panic("boom in a hosted tool")
		},
	})
	exec := NewExecutor([]actool.CoreTool{panicky}, t.TempDir(), nil)

	res, err := exec.ServeCall(context.Background(), "boom", json.RawMessage(`{}`), &WireToolCtx{WorkingDir: "enrich"}, nil)
	if err != nil {
		t.Fatalf("a recovered panic should surface as an error result, not a transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("a panicking hosted tool must return an error result (IsError), got res=%v", res)
	}
}
