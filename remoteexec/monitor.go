package remoteexec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// bashSafetyFloor is a single Bash reference instance consulted only for its
// permission check — norma's catastrophic-command floor (the same one Bash and the
// stock Monitor enforce). Constructing a Bash tool spawns nothing (it is never
// Called), so this is cheap and side-effect free. We delegate to it because norma's
// bashPermissions is unexported, and Monitor's input carries the same "command"
// field the floor inspects.
var bashSafetyFloor = actool.NewBash()

// newEgressMonitor rebuilds norma's Monitor so the background process it spawns
// inherits the Agent's egress environment (tc.Env): the Agent-local recording proxy
// + CA trust. The stock actool.NewMonitor() omits Env from its SpawnSpec, so a
// monitored process — unlike Bash (bash.go sets Env) and the shell_* tools — would
// NOT route through the sandbox's recording/upstream proxy. Its target traffic would
// egress directly, escaping evidence capture and the configured upstream-proxy policy
// (보안 리뷰: Monitor egress-env 누락). Name, description, schema and the
// catastrophic-command safety floor match the stock tool, so the model-facing
// contract is byte-for-byte identical; only the spawned process's env changes.
func newEgressMonitor() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "Monitor",
		Description: "Starts a long-running streaming process in the background (e.g. tail -f, watch, a dev server, a polling loop) and returns immediately with a task id and output-file path. Use Read or TaskOutput to inspect it and TaskStop to end it.",
		Prompt:      "Provide a command that streams output over time. It always runs in the background; you are notified if it exits on its own.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command":     map[string]any{"type": "string", "description": "The streaming command to run."},
				"description": map[string]any{"type": "string", "description": "Short description of what is being monitored."},
			},
			"required": []any{"command"},
		},
		// Same catastrophic-command safety floor as Bash (delegated; see bashSafetyFloor).
		Permissions: bashSafetyFloor.CheckPermissions,
		Run:         runEgressMonitor,
	})
}

func runEgressMonitor(_ context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var in struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return actool.Result{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return actool.Errorf("Error: command is required"), nil
	}
	if tc == nil || tc.Tasks == nil {
		return actool.Errorf("Error: background tasks are not enabled"), nil
	}
	t, err := tc.Tasks.Spawn(actool.SpawnSpec{
		Command:     in.Command,
		Description: in.Description,
		Kind:        actool.KindMonitor,
		WorkingDir:  tc.WorkingDir,
		// The fix: pass the egress env so the monitored process goes through the
		// Agent's recording proxy, exactly like Bash. Empty = inherit unchanged.
		Env: tc.Env,
	})
	if err != nil {
		return actool.Errorf("Error: failed to start monitor: " + err.Error()), nil
	}
	tc.Tasks.Background(t.ID)
	return actool.Text(fmt.Sprintf(
		"Started monitor %s. Output file: %s\nUse TaskOutput{task_id:%q} or Read to inspect it; TaskStop{task_id:%q} to end it.",
		t.ID, t.OutputPath, t.ID, t.ID)), nil
}
