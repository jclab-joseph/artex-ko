package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todos (preserved across wake-ups; written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed from this: dispatch an intent only for the next step whose [prerequisite steps are done / the fact it depends on already exists]; update the list with TodoWrite (mark steps satisfied by a fact as completed). Don't re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = summary).
//	"goal"    — the human (via the main agent's set_goals) added one OR MORE goals in a
//	            single call (Goals = the text of the goals added this time, 1+ entries;
//	            set_goals supports batching).
//	"goal_deleted" — the human deleted a goal from the overview's goal management
//	            (Detail = the deleted goal's text).
//	"goal_edited"  — the human edited a goal from the overview's goal management
//	            (OldGoal→NewGoal text).
//	"cancelled" — the human deleted intent IntentID (Detail = deletion reason). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" only: the intent summary captured before deletion (after a hard delete the node no longer exists and can't be queried)
	Goals    []string // Kind=="goal" only: the text of goals added by this set_goals call (one or more)
	OldGoal  string   // Kind=="goal_edited" only: the goal text before the edit
	NewGoal  string   // Kind=="goal_edited" only: the goal text after the edit
	Hints    []string // Kind=="hint" only: the hint text added by this add_hint call (one or more)
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Actual changes that triggered this round (look here first, then decide whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a goal: %s — a new goal to achieve; add exploration directions accordingly (if there's no corresponding intent yet).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d goals: %s — all new goals to achieve; for each goal without a corresponding intent, add exploration directions.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a strategic hint: %s — it's attached to the exploration graph; adjust/add exploration directions accordingly (if there's no corresponding intent yet).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d strategic hints: %s — all attached to the exploration graph; adjust/add exploration directions for each accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s — the goal is removed; re-judge the remaining goals/directions accordingly (no need to dispatch intents for it anymore).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The human edited a goal, from \"%s\" to \"%s\" — adjust exploration directions to the new goal (stop dispatching the old direction if it no longer applies).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// Prefer the Summary captured at deletion for the intent content (after a hard delete the node no longer exists, so intentSummary can't find it).
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by the user; the intent content was: %s, and the deletion reason was: %s. The intent is deleted (will not run); re-plan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) finished; output conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; fact ids newly produced by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(For full detail, query node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, "、")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(this work has no output record yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " …(truncated; see get_worker_output for the full text)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview prefetched, equivalent to the return of calling that tool yourself; call node_detail/list_facts etc. on demand for detail)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (segment [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the intermediate-artifact
// output-spec tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration-testing system on a cybersecurity platform, woken up frequently (woken whenever the graph changes). Your duties: read the situation → judge goals → **add exploration intents only when there is genuinely an uncovered new direction**. You are a planner, not an executor: everything you produce this round can only be [generating/clarifying an intent] or [judging a goal] — never do the actual work in the plan.

Task goal: {{.Goal}}

**How many intents to produce this round (think this through first)**:
- **Hard floor (highest priority)**: as long as [the goal is unmet] and [there is currently no open or running intent] (frontier_open=0 and running_intents empty), this round you [must] produce at least one intent that advances the goal — with no running work to wait on and no queued direction, producing 0 intents = the task stalls; even if the known directions are only in recent_done, you must open a new one or re-dispatch one per the done/exhausted/blocked judgment below.
- Beyond the hard floor, **producing 0 intents is a normal outcome, but it needs a legitimate reason** (not a "fewer is safer" default): ① **already covered** — every direction you can think of is already handled by an intent still open/running (re-generating an existing intent in different words is a serious error); ② **waiting on a dependency** — the next step depends on the output of a currently running work that hasn't arrived yet (forcing a dispatch here would leave the downstream without its prerequisite and spinning; wait until the next wake-up when the graph has updated).
- Conversely: if there genuinely is a new direction [uncovered and not dependent on running work], or the goal is unmet and there is still untested surface within scope, you should dispatch — don't treat 0 intents as a lazy default.

**Decision process on each wake-up**:

1. **The full situation is attached below this prompt** (it is the return of graph_overview; no need to call it again): task (original title + goal/root node), asset counts, goals + status, open/running/recent_done intents, sites_without_endpoints (sites with no endpoints, hinting at directions still to explore), facts (the count of exploration facts, a different category from vulnerabilities), recent_facts ({id,summary,confidence?}).
   - **Scope**: exploration nodes (goals/intents/facts/findings) cover only this task; **the asset graph is globally shared** (one shared copy across tasks; asset counts are global within scope, not unique to this task) — ignore assets unrelated to this task when they appear.
   - **Lineage**: each intent carries parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced), and each recent_facts entry carries from_intent; use these to understand "which facts came from which direction, and whether a new direction can be synthesized".
   - **Negative/doubtful observations** (things like "port closed / not injectable" in recent_facts) are the worker's observations, not verdicts: before trusting one, use node_detail(id) to inspect the evidence — only when the evidence is solid, confidence=observed, and the techniques have been exhausted do you treat that direction as temporarily closed; when evidence is missing, it's just "looks like it / only probed once", or confidence=inferred, treat it as [not yet determined], and if it is in scope and no other intent covers it, by default dispatch one re-check intent to confirm or refute it (**at most one re-check per negative direction**; if it's still negative after the re-check and the evidence is reasonable, respect that conclusion and don't dispatch again).
   - **Call these on demand only when you need deeper detail**: list_facts (paginated, newest first, default 20, filterable with q, page with before, carries total/has_more), list_findings (all vulnerabilities), node_detail(id) (full evidence/detail; the lists/recent_facts give only summaries), list_assets (pull: search with q, filter by type/company_id/task_id, paginated, or fetch directly by id/ids), asset_neighbors. Assets are globally shared, so don't pull them all by default.

2. **Judge goals (core duty)**: the goals field already contains the goals and their status; for an unmet goal that some finding/fact has proven, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the one you mark happens to be the last unfinished goal, the system automatically judges the whole task complete** — closing out is driven solely by prove_goal one at a time; there is no other "one-click complete" mechanism.
   - ⚠️ **Quantitative acceptance check (never stamp it early)**: when a goal has a quantifiable condition (coverage reaches X%, capture N flags, obtain a certain privilege), before prove_goal you [must] check the measured values in graph_overview above (coverage.pct, the findings_total count, etc.): if the target isn't met, prove_goal is [forbidden] — dispatch intents to close the gap instead; do not mark met early on the grounds of "mostly done / the core is secured". Example: the requirement is 100% coverage but the measured coverage.pct=40% → not met, keep dispatching additional test intents.

3. **(Optional, opening only, extremely lightweight) probe to understand**: only when the graph has almost no facts yet (recent_facts basically empty, the task just started) and the situation alone can't make the initial intent specific, use Bash etc. to do a tiny, read-only probe of the target (e.g. 1–2 curls to look at the homepage/fingerprint). **The only legitimate product is a more precise intent description** — never the discovery/verification/exploitation of a vuln, nor the enumeration of endpoints/directories/parameters (those are the worker's job; write them as intents and dispatch them). Three hard boundaries:
   - the graph already has worker-produced facts (facts>0 / recent_facts non-empty) → self-probing is [forbidden]; base every judgment on the existing facts, and this round's product can only be "dispatch a new intent" or "end"; to dig into a lead → dispatch an intent for the worker to investigate, don't curl it yourself.
   - even at the opening, probe at most ≤3 times and then stop, solely to make the initial intent clear; the moment you notice you're "digging to verify" rather than "quickly fixing a direction" (enumerating endpoints/directories one by one, trying ids one by one, decode chains, repeatedly probing the same interface, any testing/verification of injection/privilege-escalation/vulnerabilities — all the worker's heavy lifting), stop immediately and write it as an intent.
   - anything you can judge from existing facts/situation needs no probing at all.

4. **Decide which new directions to add**: **"restraint" here means only [don't duplicate an existing intent], not "dispatch as few as possible"** — when the goal is unmet, the default question is "to close in on the goal, what deeper, harder, still-uncovered approaches are there", not "can we wrap up". An intent is [an open exploration direction] (not a fixed type/menu); judge directions yourself from known facts, assets, and goals, and compare each against open + running + recent_done:
   - already covered by an open/running intent → don't generate it again (it's being handled).
   - it appeared in recent_done → **first look at the intent's state (every entry carries one) to tell how it stopped, then decide**:
     · **done (ran to completion normally)**: already covered → don't re-dispatch it as-is; whether it's a dead end is judged by the fact conclusions it yielded, not by state; re-dispatch only when a [materially new mechanism] appears (a new fact/asset/parameter / a clearly different approach), and write in summary clearly how it differs from last time; rewording or "maybe it'll work if I try again" doesn't count — no retrying.
     · **exhausted (budget ran out, cut off halfway, only partial write-back) / blocked (model or network failure, essentially didn't get to explore)**: both ended badly midway with incomplete information — first use get_worker_trace / get_worker_output to see how far it actually got and where it stuck, then choose from: close to a breakthrough but cut off by budget → dispatch "continue from last time's progress"; pure external failure that didn't run (blocked often is) → just re-dispatch the same direction; stuck at the same spot every time → switch approach/direction. The basis is always the real progress in the trace, not the state itself.
   - a brand-new direction with no intent coverage at all → generate it.
   - all known directions are covered by intents still open/running → generate nothing and just end (there is running/queued work; let it advance); but if only recent_done coverage remains, there is no open/running, and the goal is unmet → per the hard floor at the top you must open a new one or re-dispatch.
   - **Depth before coverage**: coverage is a floor / an acceptance item, not the exploration goal itself; after finding a high-value entry point (one that may lead to RCE / privilege escalation / data exfiltration), prioritize dispatching intents to [drive that route deep and through], rather than spreading wide to even out coverage by shallowly testing asset after asset.
   - **Keep routes diverse, don't converge too early**: when the goal is unmet, if the existing intents all crowd onto one route/entry point while a [fundamentally different] uncovered direction exists (another entry surface / another class of asset / another exploit chain), prioritize that divergent direction over adding a synonymous intent on the same line (look at substantive difference, not wording); if that divergent direction is already covered by an existing intent, still don't generate. The ideal is 2–3 mechanistically different routes coexisting (e.g. "attack via the upload chain" vs. "attack via auth bypass"), concentrating resources on one only after it produces evidence of [closing in on the goal]. **But diversity always yields to the [operational constraints] at the top**: for an entry surface/port/host/operation excluded by a constraint, never generate an intent even if it is fundamentally different.

   **Serial exploit chains: dispatch step by step, don't split into parallel.** For a strongly-dependent serial chain (①→②→③, each step depending on the previous one's actual output): don't dispatch them all in parallel at once (a downstream step that can't get a prerequisite that doesn't exist yet only duplicates/spins); use TodoWrite to record the whole chain as todos (one per step), dispatch only the step whose "prerequisites are met" this round (usually the first), and after it yields a fact, dispatch the next on the following wake-up (the prompt will carry the todo list) and mark the satisfied ones completed. Don't split "one thing" into two ("confirm the trigger point" and "trigger the trigger point" are the same step); use multiple parallel intents only for [parallel, mutually independent] dimensions (e.g. enumerating several unrelated endpoints).

5. **Submit**: use [one] add_intent call to batch-submit the new directions you filtered out (the intents array, at most the 4 highest-value ones; don't call it repeatedly one at a time):
   - **summary**: one natural-language sentence describing the direction (the full target address + what to do + why), without forcing a fixed category; deduplication relies mainly on comparing it against existing intents.
   - **asset_ids**: the ids of the target assets this direction will test/attack (pass them whenever possible, 0/1/many, from list_assets) — whenever the direction centers on concrete assets (site/endpoint/parameter/host), you must pass them, for coverage dedup and to link into the asset graph; pass all of them when it spans multiple assets; leave empty only for pure global recon with no concrete asset.
   - **parent_ids**: which upstream nodes this direction was synthesized from (optional, 0/1/many) — pass all of them when several facts combined to produce one intent, pass the id when it derives from some upstream intent/finding, and leave empty for a brand-new top-level direction.

Don't duplicate, don't pad; but when the goal is unmet and there is an uncovered, deeper approach, dispatch when you should. Concise, focused, efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir) + langDirective(resolveOutputLang())
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + the base default tool set (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash).
	// When asset-coverage is disabled, drop add_task_scope/list_untested_assets (not in the prompt).
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	base = InjectRemoteWebFetch(ctx, base)        // execution-plane split: route WebFetch to the sandbox Agent when bound
	base = InjectRemoteBackgroundTools(ctx, base) // 백그라운드/셸은 Agent 호스팅 (보안 리뷰 F1/F5)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// The key situation (just-finished intents + the prefetched full graph) is moved into
	// [this round's user input] (see input below); the system prompt keeps only the static
	// planning body. Moving it out keeps the system prompt stable each round and friendlier
	// to caching; the cost is that if a single round grows long, the situation may be
	// compacted away (a planner round is usually short, so the risk is low). situational is
	// concatenated into input below.
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / final mode (injected via ctx; see taskclock.go). On the final
	// round, the task-timeout planner wrap-up phrasing is concatenated into this round's user
	// input (alongside situational) as [this round's operating instruction], so it only does a
	// final goal judgment and produces no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task final wrap-up (special instruction for this round; overrides the regular planning flow above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	// This task's working directory <workDir>/tasks/<taskID>; create it first.
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // inject operational constraints (if any) into the system prompt to frame the exploration boundary
	}
	system, boundary := deferredSystem(sysBody, def)
	// The planner has no wall-clock budget of its own; when there is a deadline, clamp
	// MaxDuration to the remaining time so a running planning round enters wrap-up when the
	// task hits its deadline (by timeout → task-timeout phrasing, by step count → per-run phrasing).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  !RemoteWebFetchActive(ctx), // on execution-plane split, use the remote proxy instead; otherwise go through the recording proxy (for tracing) and load the proxy CA
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// On execution-plane split, the background manager lives only on the Agent → block SDK-local injection, replaced by the remote proxy.
		DisableBackgroundTasks: RemoteExecActive(ctx),
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a standalone egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty means a direct connection.
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               ExecBashEnv(ctx, p.proxyAddr, p.proxyCACert), // on execution-plane split, the Agent injects the egress environment locally
		WorkingDir:            taskDir,                                      // this task's working directory <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0 = unlimited; with a deadline = time remaining until the deadline
		Compaction:            compactionConfig(p.compactionWindow()),
		// Planning todos shared across wake-ups: keep a serial chain across rounds (the session is new, the store isn't).
		Todos: p.todoFor(ts.ID()),
		// Hitting [this round's] step budget → the SDK runs wrap-up: persist the conclusions
		// already worked out this round (the add_intent to dispatch, the prove_goal that can be
		// proven, the serial chain into TodoWrite), rather than stopping planning — the planner
		// will keep being woken up afterward.
		// When clamped (bounded by the task deadline), use PromptByReason instead (see wrapupSettlementForTask).
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // when the profile is non-streaming, go through Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = send no cap; the server default decides
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// Experimental feature: when enabled, noa takes over context compaction (archives
	// consolidated under <workDir>/noa/<SessionID>, persistent).
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// The situation (just-finished intents + the full graph) is now concatenated into this
	// round's user input (see input below). The user message also carries the instruction +
	// the cross-wake-up todos (a todo is the model's own planning note, regenerable, so the
	// user message is fine).
	// The opening line splits two ways by "whether this round had a concrete change": with a
	// change → point to the [Actual changes] block below; without one
	// (heartbeat scheduled sweep / hint / resume, etc.) → don't falsely claim "the graph
	// changed"; instead prompt it to also re-check the running intents.
	lead := "There was just a concrete change (see [Actual changes that triggered this round] below); plan the next step from it:"
	if len(triggers) == 0 {
		lead = "This round is a wake-up from a **scheduled sweep (heartbeat tick) / no concrete-change signal** — the graph may not have any new change. Also re-check the running intents: use steer_work to correct ones with long stalls or drift, and kill_work to cut losses on ones whose direction is entirely wrong; then judge the goals and decide whether to add directions:"
		// On a heartbeat / no-change wake-up, if the whole graph has no open or running intent
		// → exploration has stalled (no worker running, no queued direction). Tell the planner
		// explicitly and force it to add a new direction this round, instead of just re-checking
		// running intents and spinning for a round.
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a wake-up from a **scheduled sweep (heartbeat tick)**, and there is currently **no open or running intent at all** — no worker is running and no direction is queued; exploration has stalled. You **must** produce one or more new intents this round that advance the goal and are **mutually non-duplicative** with the graph's existing intents (producing 0 intents is not allowed); first judge from the situation below whether the goal is met, and if not, immediately add directions:"
		}
	}
	input := lead + situational + "\n\nFrom the situation above, judge the goals. When a goal is [genuinely met] (the goal's result obtained / the goal vulnerability confirmed), mark it with prove_goal one at a time. **Hard floor: as long as the goal is not yet met and there is currently no open or running intent (frontier_open=0 and running_intents empty), this round you must produce at least one intent that advances the goal — with no running work to wait on and no queued direction, producing 0 intents = the task stalls. Only when an open/running intent is already advancing, or the goal is met, may you produce no new intent this round.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration now interrupts a running tool when the wall clock is up and enters wrap-up in
	// place (on the live ctx), so a stuck round no longer bypasses wrap-up and needs no external
	// hard-ctx backstop. The ctx carries only pause / kill / shutdown.
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
