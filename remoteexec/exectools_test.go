package remoteexec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/execsvc"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// stubTool is a minimal CoreTool with an arbitrary name, used to assert how a backend
// classifies and wraps a tool by name alone.
type stubTool struct{ name string }

func (s stubTool) Name() string                           { return s.name }
func (s stubTool) Description() string                    { return "" }
func (s stubTool) Prompt() string                         { return "" }
func (s stubTool) InputSchema() map[string]any            { return map[string]any{} }
func (s stubTool) IsReadOnly(json.RawMessage) bool        { return true }
func (s stubTool) IsConcurrencySafe(json.RawMessage) bool { return true }
func (s stubTool) CheckPermissions(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Decision{}
}
func (s stubTool) Call(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
	return actool.Text("ran-locally:" + s.name), nil
}

func TestIsExecToolCoversEverySurface(t *testing.T) {
	for _, n := range []string{
		"Bash", "WebFetch", "Read", "Write", "Edit", "sleep", // built-ins + fetch
		"shell_open", "shell_send", "shell_read", "shell_close", "shell_list", // interactive PTY
		"Monitor", "TaskOutput", "TaskStop", "TaskList", // background manager
		execsvc.ToolScript, execsvc.ToolHTTP, execsvc.ToolDNS, execsvc.ToolHTTPProbe, // db-free services
	} {
		if !IsExecTool(n) {
			t.Errorf("IsExecTool(%q) = false, want true (execution surface must be classified)", n)
		}
	}
	for _, n := range []string{"insert_assets", "record_fact", "web_search", "mcp__github__list"} {
		if IsExecTool(n) {
			t.Errorf("IsExecTool(%q) = true, want false (non-execution tool must not be classified)", n)
		}
	}
}

func ranLocally(res actool.Result) bool {
	for _, b := range res.Content {
		if len(b.Text) >= len("ran-locally:") && b.Text[:len("ran-locally:")] == "ran-locally:" {
			return true
		}
	}
	return false
}

// A RemoteBackend must proxy a tool the Agent announced, BLOCK an execution tool it did
// not announce (fail closed — never local), and pass through a non-execution tool.
func TestRemoteBackendFailsClosedOnUnannouncedExecTool(t *testing.T) {
	be := NewRemoteBackend(&Session{}, []string{"Bash"})

	if _, ok := be.Wrap(stubTool{name: "Bash"}).(*remoteTool); !ok {
		t.Fatalf("announced Bash should be wrapped as a remoteTool")
	}

	// An execution tool the Agent did NOT announce must be blocked, not run locally.
	wrapped := be.Wrap(stubTool{name: "shell_open"})
	if _, ok := wrapped.(*blockedTool); !ok {
		t.Fatalf("unannounced execution tool shell_open should be blocked, got %T", wrapped)
	}
	res, _ := wrapped.Call(context.Background(), nil, nil)
	if !res.IsError || ranLocally(res) {
		t.Fatalf("blocked tool must return an error without executing locally: %+v", res)
	}

	// A non-execution tool passes through and runs in-process.
	passthru := be.Wrap(stubTool{name: "record_fact"})
	if _, ok := passthru.(stubTool); !ok {
		t.Fatalf("non-execution tool should pass through unchanged, got %T", passthru)
	}
}

// A FailClosedBackend must block the entire execution surface (including the shell,
// background and db-free service tools), while leaving data tools local.
func TestFailClosedBackendBlocksWholeExecSurface(t *testing.T) {
	be := NewFailClosedBackend("no agent")
	for _, n := range []string{"Bash", "WebFetch", "shell_open", "Monitor", execsvc.ToolScript, execsvc.ToolHTTP} {
		if _, ok := be.Wrap(stubTool{name: n}).(*blockedTool); !ok {
			t.Errorf("FailClosedBackend should block execution tool %q", n)
		}
	}
	if _, ok := be.Wrap(stubTool{name: "record_fact"}).(stubTool); !ok {
		t.Errorf("FailClosedBackend should leave non-execution tool local")
	}
}
