package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/remoteexec"
	actool "github.com/Autumn-27/norma/tool"
)

// TestSplitModeAliasRoutesThroughBackend guards the merge of the drift-tolerant tool
// aliases (issue #19) with the execution-plane split: a lowercase/snake_case alias (bash)
// must delegate to the SAME backend-wrapped tool as its CamelCase original (Bash), so a
// model that drifts to "bash" in split mode is routed to the sandbox Agent (or fail-closed
// blocked) and can never execute on the control plane. This holds only because AugmentTools
// registers aliases AFTER backend wrapping; the reverse order would leave "bash" unrecognized
// by the backend (which keys off Name()) and running locally — an isolation bypass.
func TestSplitModeAliasRoutesThroughBackend(t *testing.T) {
	// This unit exercises only the assembly ordering; no DB-backed augment/resolve hooks.
	oldAug, oldRes := ToolAugment, ToolResolve
	ToolAugment, ToolResolve = nil, nil
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAug, oldRes })

	base := []actool.CoreTool{actool.NewBash()} // Name() == "Bash"
	// A require posture with no Agent connected → fail-closed: every execution tool blocks.
	ctx := remoteexec.WithBackend(context.Background(), remoteexec.NewFailClosedBackend("regression: no Agent"))
	out, _, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	var alias actool.CoreTool
	for _, tl := range out {
		if tl.Name() == "bash" {
			alias = tl
			break
		}
	}
	if alias == nil {
		t.Fatal("expected a lowercase 'bash' alias to be registered for the CamelCase Bash tool")
	}
	res, err := alias.Call(ctx, json.RawMessage(`{"command":"echo isolation-bypass"}`), &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("alias call transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("the lowercase 'bash' alias ran on the control plane in split mode (isolation bypass): %q", res.Flatten())
	}
}
