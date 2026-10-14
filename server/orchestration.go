package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// This file implements the P2 "cross-task orchestration toolset" (docs/benchmark-orchestration §2 P2). These are host tools — they need
// access to the Manager (any task's Store), the Engine (pause), and the task-creation flow, so they live in the server layer.
// The read tools redirect the "existing per-task tools" to run against the target task's store (building a temporary ToolSet
// and calling the corresponding tool), reusing the exact same logic; the control tools (spawn/pause) call Manager/Engine directly.
// Like the traffic tools, they are seeded into the tools table and bound per agent (visible only when bound to the orchestration agent).

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.trafficHostTools(), s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // platform operation tools (create/modify skill/tool/MCP, for Auto)
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] load failed: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// trafficHostTools returns the traffic query tools to inject into every agent's
// base list (ToolAugment), honoring split mode:
//
//   - Capture on, running in-process (monolith / non-split): the real local tools
//     bound to this Manager's *Traffic (unchanged behavior).
//   - Split mode (offload != off) with capture on but no local recorder: metadata-
//     only placeholders. The per-task backend (AugmentTools → backend.Wrap) turns
//     them into RPC proxies to the sandbox Agent that hosts the recorder, or leaves
//     them fail-closed when no Agent is connected. Never a nil-receiver call.
//   - Capture off: nothing, same as before.
//
// Per-agent binding (tools table, default: worker) still decides who sees them.
func (s *Server) trafficHostTools() []actool.CoreTool {
	if local := s.m.HostTools(); len(local) > 0 {
		return local
	}
	if s.offloadMode() != "off" && s.m.TrafficEnabled() {
		return traffic.RemoteToolMetas()
	}
	return nil
}

// trafficRecordingActive reports whether target traffic is being recorded for this
// deployment — a local MITM (monolith) OR a sandbox Agent hosting the recorder
// (split mode). It mirrors trafficHostTools' injection condition exactly, so the
// worker's traffic-tool prompt note appears precisely when traffic_* are callable.
// Without this, split mode would register the tools but never tell the model to use
// them (the old signal was the local MITM's CA, absent when Mgmt runs -proxy "").
func (s *Server) trafficRecordingActive() bool {
	if !s.m.TrafficEnabled() {
		return false
	}
	return s.m.traffic != nil || s.offloadMode() != "off"
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id is required"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task does not exist: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify)         // generic wake (write ops without a dedicated callback use it; read tools are a no-op)
	tsx.SetNotifyHint(t.NotifyHint) // add_hint → record a "a human added N strategy hints: …" trigger and wake the planner
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"List all tasks (id/description/goal/status/runtime/parent task/LLM profile). The orchestration agent uses it to grasp the whole picture, see which tasks are stuck too long, and which LLM each uses. Runtime: running = created→now, terminal = created→last activity (seconds). llm_profile: the profile name the task's planner/worker uses; (active profile) = follows the global active one.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			lastAct, _ := s.m.PG().LastActivityAll()
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				end := lastAct[t.ExpID]
				if live := s.engine.LastActivity(t.ID); live > end {
					end = live
				}
				dur := int64(0)
				if status == "running" {
					dur = time.Now().Unix() - t.CreatedAt
				} else if end > t.CreatedAt {
					dur = end - t.CreatedAt
				}
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(active profile)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d (deleted)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"List the available LLM profiles: id, name, model, format, and whether it is the currently active profile. Use an id for spawn_task's llm_profile_id parameter to give a subtask its own LLM (e.g. a cheap model for recon, a strong model for exploitation). Does not include the API Key.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"Create a new subtask and start the exploration engine, returning task_id. Used to spin one thing (e.g. a challenge / a goal) off into an independent task. parent_ref is optional: fill in the current orchestration's parent task id for a parent-child link.",
		objSchema(map[string]any{
			"description":            strParam("task description (short title)"),
			"goal":                   strParam("task goal (what to achieve)"),
			"parent_ref":             strParam("optional: parent task id (for a parent-child link)"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("optional: list of read-only inherited source task ids (at most %d). The subtask can read-only reference the assets/conclusions these tasks already found as a starting point; unlike parent_ref's pure parent-child pointer, this is content inheritance.", db.MaxTaskSourceCount)},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "optional: the LLM profile id this subtask's planner/worker uses (see list_llm_profiles); if empty, inherit the parent task and then fall back to the global active profile"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "optional: task-level timeout (seconds). When it elapses it triggers graceful settlement and enters the timeout terminal state; empty or 0 = no time limit"},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "optional: planner heartbeat trigger interval (seconds). When this long has passed since the last planning round ended / the task started with no trigger in between → trigger one planning round (deadlock fallback + waking to supervise in-flight workers). Empty or 0 = default 600 (10min);"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "optional: can be enabled for simple tasks; on creation it directly issues a seed intent (content = description + goal) so the worker starts immediately without waiting for the first planner round; default false (standard plan-then-execute)."},
		}, "description", "goal"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description          string          `json:"description"`
				Goal                 string          `json:"goal"`
				ParentRef            string          `json:"parent_ref"`
				SourceTaskIDs        []string        `json:"source_task_ids"`
				LLMProfileID         json.RawMessage `json:"llm_profile_id"`
				TimeoutSeconds       int             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool            `json:"seed_first_intent"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "Unnamed task"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal is required"), nil
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			// Read-only inherited source tasks: a count cap + each id valid/deduped/existing, with validation rules identical to HTTP task creation.
			if len(a.SourceTaskIDs) > db.MaxTaskSourceCount {
				return actool.Errorf(fmt.Sprintf("at most %d source tasks can be selected", db.MaxTaskSourceCount)), nil
			}
			sourceIDs := make([]int64, 0, len(a.SourceTaskIDs))
			seenSources := map[int64]bool{}
			for _, raw := range a.SourceTaskIDs {
				id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
				if err != nil || id <= 0 || seenSources[id] {
					return actool.Errorf("source task id is invalid or duplicated"), nil
				}
				if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
					return actool.Errorf(fmt.Sprintf("source task #%d does not exist", id)), nil
				}
				seenSources[id] = true
				sourceIDs = append(sourceIDs, id)
			}
			// LLM profile resolution: explicit id > inherit parent's pin > active(nil).
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("LLM profile #%d does not exist or has no API Key set", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			var llmIDs []int64
			if pin != nil {
				llmIDs = []int64{*pin}
			}
			t, err := s.m.CreateTaskWithOptions(a.Description, a.Goal, db.TaskCreateOptions{
				SourceTaskIDs:        sourceIDs,
				LLMProfileIDs:        llmIDs,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			// The shared post-creation flow, reusing the same launchTask as HTTP task creation (server.go createTask):
			// seed + visibly doing goal breakdown in the background (round 0 / LLM steps / one goal at a time) + engine.Run.
			// seed_first_intent defaults to false (standard plan-then-execute); simple tasks can enable it to issue one work directly as a test.
			s.launchTask(t, a.Description+" "+a.Goal, a.SeedFirstIntent)
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "Pause the specified task (stop its planner/worker loop).",
		objSchema(map[string]any{"task_id": strParam("the id of the task to pause")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task does not exist: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "Read the specified task's exploration-graph overview (same as graph_overview: asset counts/frontier/findings/coverage, etc.), with task_id naming the task.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "Read the specified task's confirmed findings (including flag/PoC; each carries id/task_id/intent_id/vulnclass/severity/summary/status), with task_id naming the task.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "Inject a strategy hint into the specified task (its planner reads it on the next round of generating intents).\n"+
		"★Prefer batching: put multiple hints into the hints array and submit at once (returns an ids array, same length and order as hints, with id=0 for failed items); for a single hint, omit hints and pass the top-level text directly.",
		objSchema(map[string]any{
			"task_id":      strParam("task id"),
			"hints":        map[string]any{"type": "array", "description": "[prefer this] an array of hints, each element having the same fields as the top level (text/asset_ids/traffic_refs).", "items": objSchema(map[string]any{"text": strParam("hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[single] hint content"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset ids (optional, 0/1/many; asset ids within this task)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"View the execution trace of one work (intent) in the specified task: get_task_worker_trace(task_id, intent_id) shows step summaries; add step_ids=[...] to fetch the full content of those steps (at most 5 at a time; passing more returns only the first 5).",
		objSchema(map[string]any{
			"task_id":   strParam("task id"),
			"intent_id": map[string]any{"type": "integer", "description": "intent id (a work in this task)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "optional: step ids to fetch full content for (at most 5 at a time; passing more returns only the first 5, with the rest listed in omitted_step_ids)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "List which works (intents) ran in the specified task and each one's step count, to find which works are worth reviewing (then use get_task_worker_trace).",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "Search all works' execution traces in the specified task by keyword (returns matching step summaries + intent_id).",
		objSchema(map[string]any{"task_id": strParam("task id"), "q": strParam("search keyword")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"Read the full content of an exploration-graph node in the specified task (finding/fact/intent/goal: summary + details/evidence/PoC). id is the exploration node id (e.g. returned by report_finding, or the id in list_task_findings). Use it to fetch a finding's full evidence before writing the report.",
		objSchema(map[string]any{
			"task_id": strParam("task id"),
			"id":      map[string]any{"type": "integer", "description": "exploration-graph node id (not an asset id)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

// toolUpdateFindingReport writes/overwrites a finding's detailed Markdown report.
// finding_id is the id report_finding returned ("finding recorded: <id>", the
// finding node id). The write (SetFindingReportByNodeID) is keyed by node_id and
// task-agnostic, so this host tool needs no task_id / exploration store.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	return wrTool("update_finding_report",
		"Write/update the [detailed report] for an already-recorded finding (full Markdown, overwriting the old content wholesale). Pass the id returned by report_finding for finding_id (the number in \"finding recorded: <id>\"). The report should include: finding overview, impact and severity, reproduction steps, evidence/PoC, and remediation advice.",
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "the target finding id (the id returned by report_finding)"},
			"report":           strParam("the full detailed report, in Markdown"),
			"evidence_version": map[string]any{"type": "integer", "description": "the evidence version returned by get_finding_traffic; used to prevent the report from overwriting a new evidence change"},
		}, "finding_id", "report"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64          `json:"evidence_version"`
				FindingID       json.RawMessage `json:"finding_id"`
				Report          string          `json:"report"`
			}
			_ = json.Unmarshal(in, &a)
			nodeID := parseProfileID(a.FindingID) // reuse the "number or numeric string" parsing
			if nodeID <= 0 {
				return actool.Errorf("invalid finding_id"), nil
			}
			n, err := s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("no finding record found for finding_id=%d (record it with report_finding first)", nodeID)), nil
			}
			return actool.Text(fmt.Sprintf("finding %d report updated (%d chars)", nodeID, len(a.Report))), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (which exists precisely to
	// operate the platform). SeedTool takes effect on first insert; rows already seeded in old DBs are rebound by seedAutoDefaultBindings.
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // unbind list_facts/list_companies/list_worker_traces from worker by default (one-time)
	s.seedWorkerReadbackRebind()  // fix an old migration's mistaken removal: rebind search_all_worker_traces/get_worker_trace/node_detail back to worker (one-time)
	s.seedAutoReportFindingBinding()
	s.unbindGoalMetDefault()
	s.reseedGoalsPrompt()             // add an "extract operation constraints" step to the goals prompt → append a new default version for old DBs (one-time)
	s.reseedMainAgentPrompt()         // add "after goals are met, add_intent asks back whether to register as a goal" to the mainagent prompt (one-time)
	s.reseedPlannerPrompt()           // planner prompt: rewrite the "0 intents" justification + add quantified acceptance checks (one-time)
	s.reseedWorkerPrompt()            // worker prompt: add an evidence threshold for negative conclusions (one-time)
	s.seedReporterAgent()             // preinstall the "보고서 작성" agent + tool bindings + finding trigger (one-time)
	s.upgradeReporterTriggerMessage() // migrate old DBs: make the reporter return evidence_version (one-time)
	s.seedFindingTrafficTools()       // add the optional evidence params and the read-only evidence tool, preserving user config
	s.seedFindingWorkflowTools()
	// Note: the pentest default tool bindings need no migration — BuiltinToolSeeds already seeds
	// list_assets/insert_assets/report_finding/list_findings/list_companies together with
	// pentest at fresh initialization (the project has no old DBs yet, so no migration).
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task's llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v7_list_facts_paging"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// Also refresh some built-in agent tools to the code defaults:
	//   - goal_met: the old DB's seeded description had the misleading "end this planning round", making the planner treat it
	//     as a means to "end an empty round" and misjudge the whole task complete right after starting.
	//   - insert_assets: added the related param (marks whether an asset is relevant to the current task and decides whether it counts toward coverage);
	//     SeedTool is first-insert-only, so an old DB's already-seeded schema would otherwise not get this new param.
	//   - list_facts: switched to pagination, adding the limit/before/q params; an old DB's already-seeded empty schema would otherwise
	//     show "no parameters" on the tool-management page, and the model would not get these parameter descriptions.
	refreshBuiltin := map[string]bool{"goal_met": true, "insert_assets": true, "list_facts": true}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !refreshBuiltin[sd.Key] {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Print(logT("[tools] orchestration/platform 도구 스키마를 코드 기본값으로 새로고침(1회성)"))
}

// unbindGoalMetDefault removes goal_met's default "planner" binding ONCE (guarded by
// a settings flag), so existing DBs match the new default of NO agent. goal_met bypasses
// per-goal prove_goal to declare the whole task done — powerful/risky and redundant with
// the prove_goal→auto-complete path — so it ships unbound; users can re-bind it per agent
// in the UI. A user's own binding to another agent is untouched (we only strip planner).
func (s *Server) unbindGoalMetDefault() {
	const flag = "goal_met_unbind_default_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("planner", "goal_met"); err != nil {
		log.Printf("[tools] failed to unbind goal_met from planner: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedGoalsPrompt refreshes the goals goal-breakdown prompt to the [current code default] — because the default body added
// the step "extract operation constraints (set_constraints) first, then break down goals", and SeedPromptIfEmpty is first-insert-only, so an old DB's
// existing version 1 does not get this step. Here we use versioning to [append a new version] and switch to it (ResetPromptToDefault),
// keeping the old version in history so a user who customized it can recover it from the version record. A settings flag guards it → done only once;
// bump this flag whenever the default changes later. A fresh DB needs no handling (SeedPromptIfEmpty already seeds the latest default).
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_constraint_step_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once, whether it succeeds or not
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // on a fresh DB where the agent row does not exist yet, seedPrompts seeds the latest default directly, so this migration is unneeded
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// on a fresh DB seedPrompts already seeded the latest default → the current version already equals the code default, so no duplicate version is appended.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh the goals prompt to the new default: %v", err)
		return
	}
	log.Printf("[prompts] appended a new default version to the goals prompt (added the extract-operation-constraints step, one-time)")
}

// reseedMainAgentPrompt refreshes the mainagent prompt to the [current code default] — the default body added the guidance "after all goals
// are met, when add_intent injects an intent directly, ask the human whether to register it as a formal goal", and SeedPromptIfEmpty is first-insert-
// only, so an old DB's existing version does not get it. Using versioning, [append a new version] and switch to it (ResetPromptToDefault); the old version is still
// kept in history so a user who customized it can recover it from the version record. A settings flag guards it → done only once. A fresh DB needs no handling
// (SeedPromptIfEmpty already seeds the latest default). Fully isomorphic to reseedGoalsPrompt.
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once, whether it succeeds or not
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // on a fresh DB where the agent row does not exist yet, seedPrompts seeds the latest default directly, so this migration is unneeded
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// on a fresh DB seedPrompts already seeded the latest default → the current version already equals the code default, so no duplicate version is appended.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh the mainagent prompt to the new default: %v", err)
		return
	}
	log.Printf("[prompts] appended a new default version to the mainagent prompt (added asking back to create a goal after goals are met, one-time)")
}

// reseedPlannerPrompt refreshes the planner prompt to the [current code default] — the default body was streamlined and restructured, downgrading "restraint" to
// dedup only, adding "depth before coverage" and "hard floor: when a goal is unmet and no intent is running, something must be produced", and bounding the negative-conclusion recheck.
// Whenever the default changes substantively, bump the flag below (currently v2) to re-refresh existing old DBs once. SeedPromptIfEmpty is first-insert-only, so an old DB's existing version does not get it, hence versioning:
// [append a new version] and switch to it (ResetPromptToDefault); the old version is still kept in history so a user who customized it can recover it from the version record.
// A settings flag guards it → done only once. A fresh DB needs no handling (SeedPromptIfEmpty already seeds the latest default). Fully
// isomorphic to reseedGoalsPrompt.
func (s *Server) reseedPlannerPrompt() {
	const flag = "planner_prompt_compact_realistic_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once, whether it succeeds or not
	a, err := s.m.pg.GetAgentByKey("planner")
	if err != nil || a == nil {
		return // on a fresh DB where the agent row does not exist yet, seedPrompts seeds the latest default directly, so this migration is unneeded
	}
	tmpl := agent.BuiltinPromptSeeds()["planner"]
	if tmpl == "" {
		return
	}
	// on a fresh DB seedPrompts already seeded the latest default → the current version already equals the code default, so no duplicate version is appended.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh the planner prompt to the new default: %v", err)
		return
	}
	log.Printf("[prompts] appended a new default version to the planner prompt (streamlined restructure + restraint downgraded to dedup + depth-first + negative-recheck bound, one-time)")
}

// reseedWorkerPrompt refreshes the worker prompt to the [current code default] — the default body's record_fact section dropped the whole sentence "write a negative
// conclusion as an observation + a tentative reading", and decoupled confidence (observed/inferred) from "whether this intent's means are exhausted" (these mislead the planner),
// and also tightened the facts array into the rare exceptions of "fully independent, unmergeable" items. Bump the flag to v3 to re-refresh existing old DBs once.
// SeedPromptIfEmpty is first-insert-only, so an old DB's existing version does not get it, hence versioning: [append a new version] and switch to it; the old version is still kept in history and recoverable.
// A settings flag guards it → done only once. A fresh DB needs no handling. Fully isomorphic to reseedGoalsPrompt.
func (s *Server) reseedWorkerPrompt() {
	const flag = "worker_prompt_compact_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once, whether it succeeds or not
	a, err := s.m.pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		return // on a fresh DB where the agent row does not exist yet, seedPrompts seeds the latest default directly, so this migration is unneeded
	}
	tmpl := agent.BuiltinPromptSeeds()["worker"]
	if tmpl == "" {
		return
	}
	// on a fresh DB seedPrompts already seeded the latest default → the current version already equals the code default, so no duplicate version is appended.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh the worker prompt to the new default: %v", err)
		return
	}
	log.Printf("[prompts] appended a new default version to the worker prompt (context-lookup section narrowed to list_assets/list_findings, dropping list_facts/node_detail/asset_neighbors, one-time)")
}

// reporterToolCallMessage must unconditionally require reading get_finding_traffic once before writing the report.
// That tool is read-only and "independent of the capture toggle", so manually bound evidence is readable whether auto-binding is on or off. If this were
// written as "read only when auto-binding is enabled", then under the default off config the reporter would not pass evidence_version,
// SetFindingReportVersionByNodeID would then write -1 per legacy semantics, and the finding detail and Markdown export would
// permanently sit at "evidence changed, report pending update", with no entry in the UI to clear it.
const reporterToolCallMessage = "A finding was just recorded above by report_finding. Read the finding_id (the standalone finding record ID) and finding_node_id (the exploration node ID) from the returned JSON, " +
	"then first use get_finding_traffic(finding_id) to read the current evidence manifest and its version (an empty manifest is normal — write the report as usual); " +
	"if the runtime guidance enables auto-binding, verify and link this finding's traffic before reading. Use finding_node_id for node details. " +
	"Finally call update_finding_report(finding_id=finding_node_id, report, evidence_version=the version you actually read) to save; " +
	"evidence_version must be passed, otherwise the report is permanently marked pending update. Do not mix the two ID types."

// The old trigger message (0.3.8 and earlier). Only records still byte-identical to it are overwritten by migration; those the user changed stay as-is.
const reporterToolCallMessageV1 = "上面刚有一个漏洞被 report_finding 登记。请从触发上下文里取出 finding_id" +
	"（工具返回 \"finding recorded: <id>\" 里的数字）与任务 id，按你的职责撰写该漏洞的详细报告，" +
	"最后调用 update_finding_report(finding_id, report) 保存。"

// upgradeReporterTriggerMessage refreshes the reporter trigger message in old DBs that still hold the default text to the new version.
// seedReporterAgent is guarded by reporter_agent_seed_v1 and only writes the trigger when creating a new agent, so
// an upgraded DB does not get the new text — the tool schema was completed with evidence_version by seedFindingTrafficTools,
// but nothing tells the reporter to use it. One-time, and overwrites only text that has not been modified.
func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_evidence_version_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] failed to read triggers: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageV1 {
			continue // the user changed it or it is not a finding trigger, leave it.
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] failed to upgrade the trigger message: %v", err)
			return
		}
		log.Printf("[reporter] upgraded the trigger message to read and return evidence_version")
	}
}

// reporterAgentName·reporterAgentDescription 은 시드되는 reporter 에이전트의 표시 전용
// 라벨이다(한국어화). 에이전트의 두뇌(segment[A] agent.ReporterDefaultPrompt)와 트리거 주입
// 메시지(reporterToolCallMessage)는 모델 입력이라 중국어 원문을 보존하지만, 이 이름·설명은
// `agentDTO` 로 system/agents UI 에만 렌더되고(server_mgmt.go) 어떤 프롬프트·에이전트 선택에도
// 들어가지 않는 순수 UI 라벨이라 한국어화한다(BRIEF 사용자 노출 산출물 한국어화 범위). 트리거는
// report_finding 도구 호출 기반(OnToolCall·결정적)이라 reporter 는 key "reporter" 로 참조될 뿐
// 표시 이름으로 선택되지 않는다. 회귀 방어: reporter_seed_localized_test.go. [[F35]]
const reporterAgentName = "보고서 작성"
const reporterAgentDescription = "취약점 상세 보고서 작성: 취약점을 발견하면 자동으로 트리거되어, 증거와 실행 과정을 조회한 뒤 Markdown 보고서를 작성해 해당 취약점에 기록합니다."

// seedReporterAgent preinstalls a "보고서 작성" custom agent (builtin=false, editable/deletable in the UI):
// it binds update_finding_report + the task-query tools and attaches a "trigger whenever report_finding is called"
// trigger — waking it to write a detailed report for each recorded finding. One-time (guarded by a settings flag): once the user deletes it, it is not recreated.
// Dependency: the orchestration tools were already inserted via SeedTool above this function, so the binding resolves.
func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // try only once, whether it succeeds or not

	if exist, _ := s.m.pg.GetAgentByKey("reporter"); exist != nil {
		return // the key is already taken (the user created it manually) — do not overwrite
	}
	a, err := s.m.pg.CreateAgent("reporter", reporterAgentName, reporterAgentDescription)
	if err != nil {
		log.Printf("[reporter] failed to create agent: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] seed prompt failed: %v", err)
	}
	// Trigger run policy: parallel + none — one report per finding, multiple findings writing concurrently and independently.
	// merge must be none: otherwise (default all) a wave of findings would be merged into one run, defeating parallelism.
	// maxParallel=5: at most 5 report sessions at once, to avoid too many LLM calls in a burst.
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] failed to set the trigger run policy: %v", err)
	}
	// bind the tools it needs: write the report + read evidence/execution trace/situation.
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] failed to bind tools: %v", err)
	}
	// Trigger: fires whenever report_finding is called (the tool returns "finding recorded: <id>" carrying finding_id,
	// and the task id is also in the trigger message).
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] failed to create trigger: %v", err)
	}
	log.Printf(logT("[reporter] 「%s」 agent + finding 트리거 사전 구성"), reporterAgentName)
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] failed to default-bind report_finding: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] failed to default-bind report_finding: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] failed to default-bind list_assets: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // switch the default binding worker→planner
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] failed to default-bind add_company_scope: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] failed to unbind add_company_scope: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] failed to unbind %s from worker: %v", k, err)
			return // on error do not set the flag, retry on the next startup
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2: add node_detail
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] failed to rebind the readback/detail tools: %v", err)
		return // on error do not set the flag, retry on the next startup
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3: replace old asset tool names, add insert_assets/add_company_scope
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// asset tools: Auto operating the platform often needs to view/record assets and manage company scope.
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] default-bind failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
