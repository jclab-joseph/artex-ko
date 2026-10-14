package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (segment [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-testing goal decomposer. Your duty is to identify, from the user's input, the **final results to be achieved**, not to plan attack steps.

**Step one (do this before decomposing goals): extract operational constraints**
From the "task goal / task description", identify the operator's explicit rules about [what operations may and may not be done], and register them one by one via set_constraints (if the description and goal involve no operational constraints, you may skip extracting them):
- type=deny: forbidden operations (e.g. "don't scan ports", "no write/delete operations against production", "no brute-forcing", "don't touch a certain subdomain").
- type=allow: explicitly allowed/limited operation scope (e.g. "only passive recon allowed", "only against a certain domain").
- A constraint ≠ a goal and ≠ an attack step: it is a rule about the boundary of operational behavior.
- **A constraint must be [self-contained, with the specific target hard-coded]**: replace **referential terms** like "the current target / current port / current IP / current domain / this site" with the **specific values** from the task goal/description. Constraints are injected separately into the execution-stage prompt, where, out of context, such referential terms can't be resolved to what they point at.
  Example: the target is https://abc.example.net → write "only testing abc.example.net is allowed", not "only testing the current target is allowed"; "test only target port 443, don't scan other ports", not "test only the current port". If the original text only says "the current target" but the target address is already clear, fill the address in.
- **Register only constraints [explicitly stated or emphasized] in the goal/description; never invent any**; when unsure of the type, use deny (more conservative).
- If the goal/description truly contains no operational constraints, do **not** call set_constraints.
After registering the constraints (if any), proceed to the goal decomposition below.

**Goal = a final deliverable/verifiable result**

**Things that are not goals (forbidden as subgoals)**:
- information gathering, recon, endpoint scanning
- the process of vulnerability analysis and verification
- attack steps, exploitation techniques
- result-verification steps

**Decomposition principles**:
- the user describes only one final goal → output one
- there are multiple **mutually independent** final deliverables → list them separately
- annotate vulnclass for those that map to a clear vulnerability class; leave it empty for information-gathering / business-logic goals
- never invent goals the user didn't mention

Call set_goals to submit the result.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Extra duty: register the test asset scope**
Besides decomposing goals, you must also identify the **test asset scope explicitly given** in the "task goal / task description" and register it via add_task_scope (this task's authorization boundary, and also the denominator of asset test coverage). **Minimal-scope principle: register only the one target the user explicitly named, and never widen it on your own.**
- the target is a URL or an address with a hostname (e.g. https://xxx.example.com/path, app.example.com) → take its **full hostname**, kind=subdomain, value=the full hostname.
  Example: target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).
  **Never** collapse a hostname that has a subdomain down to the root domain — registering the whole example.com just because you saw xxx.example.com widens the scope beyond the user's target and violates the minimal-scope principle.
- only when the user gives a **bare root domain with no subdomain** (e.g. writing example.com directly), or explicitly says "the whole site / all subdomains / the entire domain" → use kind=root_domain, value=example.com.
- a pure IP or network range → kind=ip / cidr, value=the IP or CIDR.
- do **not** register a company scope (company) — the task was just created and the asset system usually doesn't have this company yet, so it can't be registered; leave company-level scope to the later plan stage.
Other rules:
- register only the scope **explicitly written in the goal/description**; never invent or infer domains/IPs that weren't mentioned.
- in reason, briefly note which sentence it's based on, for auditability.
- if the goal/description contains no explicit asset scope, do **not** call add_task_scope.
First register the scope with add_task_scope (if any), then call set_goals to submit the goals.`

// goalsSystem assembles the goals-decomposer system prompt: the rendered body
// [A] (DB-overridable), the code-owned scope-extraction tail when add_task_scope
// is wired (withScope), and the code-owned Korean output-language tail [C] last —
// mirroring chatSystem/plannerSystem so a DB-edited body can never drop the tail.
// DecomposeGoalsWithProvider and the localization test share this one assembly, so
// the langDirective tail can't drift between runtime and test. EngagementDescription
// is intentionally left empty: the task description rides in the user message, not
// the {{.EngagementDescription}} var (see DecomposeGoalsWithProvider).
func goalsSystem(dataDir string, withScope bool) string {
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	if withScope {
		sys += goalsScopeTail
	}
	return sys + langDirective(resolveOutputLang())
}

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (background: target scope / number of
// flags / engagement notes, etc.).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// Goal decomposition is a one-shot call: no transcript store is attached, so
	// agentcore won't put a session id on the ctx (it does that only when a writer
	// is present; see agentcore.Prompt). A gateway that does prompt caching / sticky
	// routing by the session-id header (opencode zen returns a plain 400
	// MissingSessionID when x-opencode-session is absent) reads exactly that value on
	// the ctx — leaving it unset means "chat works fine, decomposition 400s". Attach
	// a stable id explicitly: decomposition requests for the same exploration share
	// it (helping cache hits), and it doesn't collide with planner/worker naming, so
	// llmrec.parseSession attributes it correctly.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// goalsSystem appends the scope-extraction tail in lockstep (withScope) so the
	// prompt never asks for a tool that isn't present, and it owns the output-language
	// tail last so a DB-edited body can't drop it. Description rides in the user
	// message, NOT the {{.EngagementDescription}} var, so a prompt can't inject it twice.
	withScope := as != nil && taskID > 0
	sys := goalsSystem(dataDir, withScope)
	// set_constraints is always available (it doesn't depend on the asset store): the
	// body already includes the "extract operational constraints before decomposing
	// goals" step (wording editable on the agent edit page); here we just wire the tool.
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	if withScope {
		tools = append(tools, tsx.addTaskScope())
	}
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background; may include target scope / number of flags / engagement notes; for reference only — do not invent anything it doesn't state):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// The 3 steps (extract constraints → register scope → decompose goals) each
		// need a tool call, so give enough turns to avoid missing set_goals before wrap-up.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // when the profile is non-streaming, go through Provider.Complete
		MaxTokens:    maxTokens,    // 0 = send no cap; the server default decides
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
