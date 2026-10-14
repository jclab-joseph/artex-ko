package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), "tavily"
// (TavilyKey required), or "deepseek" (DeepSeek* required, filled from the
// active LLM profile). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
//
// Note that the deepseek backend differs in nature from the other three: DeepSeek has
// no directly callable search endpoint; search exists only inside its Anthropic-compatible
// messages endpoint (the web_search_20250305 server tool), so each search consumes a model
// call, and the search request is issued by DeepSeek's server — it doesn't go through the
// local Proxy and leaves no traffic trace.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
	// DeepSeek* come from the currently active LLM configuration (only the anthropic-format
	// official DeepSeek endpoint), are not configured separately, and change as the LLM
	// configuration is switched.
	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
}

type Worker struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	workDir         string
	proxyAddr       string
	proxyCACert     string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	recording       bool              // traffic capture active (local MITM OR sandbox Agent) → inject the traffic-tool note
	webSearch       WebSearchOpts     // web_search tool backend selection (off by default)
	tx              *transcript.Store // raw LLM conversation persistence (nil = off)
	window          int               // context window in tokens (for compaction)
	windowFn        func() int        // optional dynamic task-chain minimum
	maxTurns        int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// injectConstraints resolves whether this task's operation constraints get
	// injected into the worker system prompt. Read per run so the settings toggle
	// takes effect without rebuilding the agent. nil = inject (default).
	injectConstraints func() bool
	// nonStreamingFn resolves whether this run uses the non-streaming (Complete)
	// path. Read per run so a profile/task toggle takes effect without rebuilding
	// the agent. nil = streaming (default).
	nonStreamingFn func() bool
	// noaEnabledFn resolves whether this run uses the experimental noa context-
	// compression mechanism. Read per run, like nonStreaming. nil = off (built-in
	// compaction).
	noaEnabledFn func() bool
	// maxTokensFn resolves the per-reply output cap in tokens, on the same
	// per-run basis. nil or 0 = send no cap and let the endpoint decide.
	maxTokensFn func() int
}

// WorkerSessionID returns the stable transcript key used by a worker intent.
// Worker slots are reusable, so the intent id (rather than work#N) is the
// session identity. Keep this helper public so the Worker message API and UI
// can refer to exactly the conversation that will be resumed.
func WorkerSessionID(explorationID, intentID int64) string {
	return fmt.Sprintf("exp%d-worker-i%d", explorationID, intentID)
}

const workerChatMarkerPrefix = "<!-- ARTEX_WORKER_CHAT:"

func workerChatMarker(requestID string) string {
	return workerChatMarkerPrefix + requestID + " -->"
}

func hasWorkerChatMessage(messages []llm.Message, requestID string) bool {
	marker := workerChatMarker(requestID)
	for _, message := range messages {
		if message.Role == llm.RoleUser && strings.Contains(message.Text(), marker) {
			return true
		}
	}
	return false
}

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default). Read per
// run so a profile or task-chain toggle takes effect without rebuilding.
func (w *Worker) SetNonStreaming(fn func() bool) { w.nonStreamingFn = fn }

func (w *Worker) nonStreaming() bool { return w.nonStreamingFn != nil && w.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (w *Worker) SetNoaEnabled(fn func() bool) { w.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (w *Worker) SetMaxTokens(fn func() int) { w.maxTokensFn = fn }

func (w *Worker) maxTokens() int {
	if w.maxTokensFn == nil {
		return 0
	}
	return w.maxTokensFn()
}

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the worker system prompt. nil = inject (default).
func (w *Worker) SetConstraintInject(fn func() bool) { w.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (w *Worker) wantConstraints() bool { return w.injectConstraints == nil || w.injectConstraints() }

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "이번 실행이 예산 소진으로 곧 종료됩니다. 더 이상 어떤 명령이나 탐지도 실행하지 마십시오. 다음 순서대로 처리하십시오. (1) 위에서 이미 식별했지만 아직 기록하지 않은 내용을 하나씩 기록합니다. 새 자산은 insert_assets, 탐색 결론과 사실은 record_fact, 확인된 취약점은 report_finding 으로 기록합니다. (2) **맨 마지막에 한 문장짜리 순수 텍스트로만** 무엇을 했고 어떤 핵심 결론을 얻었는지 한국어로 요약합니다. 이 한 문장이 이번 실행의 결과로 사용자에게 표시되므로 반드시 출력해야 합니다."

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// defaultToolsExcept returns actool.DefaultTools() minus the named tools (by
// CoreTool.Name()). Used to trim SDK default tools an agent shouldn't have.
func defaultToolsExcept(exclude ...string) []actool.CoreTool {
	drop := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		drop[n] = true
	}
	all := actool.DefaultTools()
	out := make([]actool.CoreTool, 0, len(all))
	for _, t := range all {
		if !drop[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}

func (w *Worker) SetCompactionWindowResolver(fn func() int) { w.windowFn = fn }

func (w *Worker) compactionWindow() int {
	if w.windowFn != nil {
		return w.windowFn()
	}
	return w.window
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetRecording marks whether target traffic is being recorded for this run, so the
// worker injects the traffic-tool note even when the recorder is NOT a local MITM
// (split mode: the recorder lives in the sandbox Agent, so there is no local CA to
// infer it from). Defaults false; a local MITM still implies recording via its CA.
func (w *Worker) SetRecording(on bool) { w.recording = on }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the egress proxy (the recording MITM when capture is on, or the global proxy
// directly when it is off) and, only when a MITM CA is present, makes the common
// toolchain trust it — so tools need no manual -x/--proxy/-k. Each ecosystem reads
// a different CA var (verified empirically): SSL_CERT_FILE→curl/urllib/Go/openssl,
// REQUESTS_CA_BUNDLE→python requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl,
// GIT_SSL_CAINFO→git, NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+
// honor the proxy vars. ALL_PROXY is set too so a socks5 egress proxy (which curl
// only reads from ALL_PROXY, not HTTP(S)_PROXY) works in the capture-off path.
// Empty proxyAddr → nil (direct, unchanged env).
// remoteBashEnv returns the Bash egress env for the control plane. When a sandboxed
// Agent runs Bash, the control plane sends no egress env at all — the Agent injects
// its own, pointing at its local recording proxy — so target traffic is captured in
// the sandbox and no Management-side network hint crosses the boundary. Otherwise it
// is the ordinary in-process proxyEnv.
func remoteBashEnv(backend remoteexec.Backend, proxyAddr, caCert string) []string {
	if backend.IsRemote() && backend.Executes("Bash") {
		return nil
	}
	return proxyEnv(proxyAddr, caCert)
}

func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr, // socks5 egress: curl reads only this
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (segment [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the intermediate-artifact
// output spec are NOT here — they are code-owned and appended by workerSystem after
// rendering (segments [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `You are the "executor" (work agent) of an authorized penetration-testing system on a cybersecurity platform. You've been handed [one intent] (a one-sentence exploration direction); your sole duty: **complete this one intent, write the findings back to the knowledge graph, then stop and return.**

**Boundaries (red lines)**:
1. **Do only the one intent you were handed**. **If, while exploring this intent, you glimpse a lead worth digging into beyond it** (a path leaked by an error, a point that might chain with other assets, a suspected entry to another exploit chain), **note it in one line in the fact's summary and hand it to the planner.**
2. Hitting a wall the first time (payload filtered / 404 / injection with no echo) doesn't mean you've explored it fully — exhaust all the bypass techniques for this intent before outputting a conclusion;
3. Operate only within the authorized scope. If [operational constraints] are attached at the top of the system prompt, they are the highest-priority red line: self-check before every command/probe, and if it would violate one, don't do it (even if it falls within the intent you were handed).

**Write back as you discover** (only what's written into the graph counts, not what's in your head or prose; write each result the moment you get it, don't save it to the end and lose it when steps run out). Three kinds of write-back; don't cross the graphs:
- **New asset/resource → insert_assets (asset graph)**: any asset [itself] — subdomain / service / endpoint / fingerprint / credential, etc. **Register only assets here; exploration conclusions/judgments don't go here — use record_fact.**
- **Exploration conclusion/fact → record_fact (exploration graph, pass intent_id)**: use it for all of these. **Aggregate multiple observations into [one] fact** (summary = a one-sentence summary + detail = an expansion that matches the summary, grounded in the real execution process); don't make one per attribute — usually one per intent — because splitting them up bloats the graph without limit. **By default write one, and fold everything that can go into detail into it**; use the facts array to split into entries only when there genuinely are [fully independent, unmergeable] conclusions — a rare exception, not the norm. **Write only increments**: record only what you [newly obtained] this time, and don't re-record existing facts in different words (if you only corroborated existing ones with nothing new, there's no need to record). **Write only what you actually saw**: give evidence (one line: the command + the one or two output lines that best prove it, concise, with details in detail) and mark confidence (observed = seen directly / inferred = deduced from a phenomenon).
- **Confirmed vuln → report_finding (exploration graph, with PoC, pass intent_id)**: **use it only for something you actually triggered this time and for which you obtained reproducible evidence (request/response or command output)**. Never treat "a version/fingerprint matched a CVE", "the parameter looks injectable", or "inferred from an external vuln database / changelog / code diff" as confirmed, and don't substitute querying a CVE database or comparing patch versions for an actual trigger. Can't trigger it but have a suspicion → record an inferred fact with record_fact (the suspected point + why it wasn't triggered) and hand it to the planner; don't force it into a finding.


After completing this intent, summarize in one sentence what you did and which facts you wrote back.`

// workerTrafficBlock is segment [B]: the traffic-tool note, code-injected only when
// traffic capture (recording) is on — i.e. the traffic_* tools actually exist.
// Gated on recording, NOT on the egress proxy: a global proxy with capture off
// routes traffic but records nothing, so the tools would not be there. Not stored,
// not editable.
func workerTrafficBlock(recording bool) string {
	if !recording {
		return ""
	}
	return "\n\n**Traffic tools**:\n- traffic_search / traffic_get / traffic_blob: review responses and find resources you already visited; **check the traffic first, don't re-curl the same URL**. traffic_search **must specify a host** and by default returns only 3 extremely lightweight index entries (id/method/url/status/resp_len, no response body); raise limit explicitly when you need more; use body_contains for a full-text search within the request/response body (at least 3 characters; supports substrings and non-ASCII text such as CJK, e.g. finding passwords/keys/errors/internal addresses); to read one entry's original, use traffic_get(id), where an oversized body is shown as @blob sha256:<hash> — use traffic_blob(hash) to fetch the full text in segments."
}

// artifactSpec is segment [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(dir string) string {
	return "\n\n**Intermediate-artifact output spec**: scripts, payloads, captured response bodies, temporary data, and all other intermediate artifacts **must be written to this task's working directory " + dir + "** (a relative path writes here, or use this absolute path) — **don't write to /tmp, don't use any other absolute path**."
}

// workerArtifactSpec is the worker's segment [C]: its per-intent run dir is pre-created
// by the engine (ensureRunDir), so it just writes relative paths there — no manual
// mkdir, no cross-worker name collisions.
func workerArtifactSpec(runDir string) string {
	return "\n\n**Intermediate-artifact output spec**: scripts, payloads, captured response bodies, temporary data, and all other intermediate artifacts **must be written to this intent's dedicated working directory " + runDir + "** (already created automatically; just write with a relative path here, no need to mkdir manually) — **don't write to /tmp, don't use any other absolute path**."
}

// ensureRunDir builds and creates an agent's working directory under base:
// <base>/tasks/<taskID> for planner/main; <base>/tasks/<taskID>/i<intentID> for a
// worker (intentID<=0 → task dir only). The "tasks/" segment groups per-task dirs
// symmetrically with the chat agent's "sessions/<sessionID>". Best-effort mkdir — on
// failure, writes fail the same way an unwritable CWD would.
func ensureRunDir(base string, taskID, intentID int64) string {
	dir := filepath.Join(base, "tasks", strconv.FormatInt(taskID, 10))
	if intentID > 0 {
		dir = filepath.Join(dir, "i"+strconv.FormatInt(intentID, 10))
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// cmdOutDir is the SDK large-tool-output spill dir under an agent's run dir.
func cmdOutDir(dir string) string { return filepath.Join(dir, "cmd-output") }

func workerSystem(proxyAddr, caCert, dataDir, runDir string, recording bool) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr, DataDir: dataDir, Now: nowStr()})
	// A local recording MITM is inferred from its CA (caCert); split mode records in
	// the sandbox Agent with no local CA, so the server sets `recording` explicitly.
	// Either way the traffic_* tools are registered, so the note must appear.
	// Optional finding guidance is added for every role after tool resolution.
	return body + workerTrafficBlock(recording || caCert != "") + workerArtifactSpec(runDir) + langDirective(resolveOutputLang())
}

// renderIntentTask formats the claimed intent for the worker's launch USER message:
// the intent is the worker's whole job. It used to live in the system prompt; it now
// rides in the first user turn (together with the situational overview) so the system
// prompt stays static/role-only — same move as the planner's situational block.
// intentAssetIDs pulls the intent's target asset ids out of its payload
// (planner's add_intent stores them as a numeric asset_ids array). nil on absence
// or malformed payload.
func intentAssetIDs(intent *db.Node) []int64 {
	if intent == nil {
		return nil
	}
	var p struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return nil
	}
	return p.AssetIDs
}

func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n[The intent you were handed (your only task this time: do just this one, produce only facts, stop when done)]:\n%s\nintent id: %d (pass it when writing back via record_fact / report_finding)", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// launch USER message for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	// coverage is a signal for the planner to judge "which kinds are under-tested / whether to
	// widen scope", which conflicts with the worker's duty boundary ("do only the one intent
	// you were handed, don't chase uncovered points") → remove it from the worker's view. data
	// is a fresh map specific to this worker, so deleting the key doesn't affect the planner.
	delete(data, "coverage")
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration situation (read-only, to help you place your own intent in the big picture)]:\n" +
		"Below is the whole task's current exploration overview. It serves two purposes: one, to know what others have already found so you don't duplicate it; two, so that while exploring your own intent you can relate it to the global picture.\n" +
		"**Diverging is good**: while exploring this intent, think deeply and associate freely. The only line is — don't actually go off and execute another intent (that's another worker's job, scheduled by the planner). Whenever you associate a valuable lead (a cross-asset interaction, a suspected entry to another exploit chain, a globally suspicious point), **be sure to write it into a fact and hand it to the planner** — that's an important output of yours, not optional. Better to report one more for the planner to judge than to swallow it yourself.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// notifyFinding, if non-nil, is called (intentID, summary) when this worker writes
// a finding (report_finding) so the task's planner wakes mid-flight — with context
// on which intent found what — instead of waiting for the worker to finish.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string)) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, "", "")
}

// ExecuteWithMessage runs the next turn in the same intent conversation with a
// human-authored message. The HTTP handler does not edit the transcript;
// agentcore records the message as a normal user turn when this Worker starts.
// This keeps Worker continuation identical to the regular agent chat flow.
func (w *Worker) ExecuteWithMessage(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, strings.TrimSpace(requestID), strings.TrimSpace(message))
}

func (w *Worker) execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetTaskID(taskID)
	coverageEnabled := as == nil || as.CoverageEnabled(taskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID)         // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)                  // async DNS/HTTP auto-completion for assets this worker writes
	tsx.SetNotifyFinding(notifyFinding) // wake the planner on the spot when report_finding persists, carrying "which intent + finding"
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	// The worker deliberately omits MultiEdit/Glob/Grep: precise file edits go through Edit and
	// search goes through Bash (grep/find), narrowing the tool surface and cutting low-value calls.
	// The other SDK default tools (Read/Write/Edit/LS/Bash/Sleep) are as usual.
	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	// Execution-plane split: when a sandboxed Agent handles WebFetch, inject a plain
	// WebFetch tool so AugmentTools wraps it into a remote proxy, and disable norma's
	// built-in WebFetch below (it would otherwise egress from the control plane).
	remoteWebFetch := RemoteWebFetchActive(ctx)
	base = InjectRemoteWebFetch(ctx, base)
	// Execution-plane split: background/interactive shells are Agent-hosted — inject them via the
	// remote proxy and turn off the SDK's local injection below with DisableBackgroundTasks
	// (security review F1/F5).
	base = InjectRemoteBackgroundTools(ctx, base)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// The intent is the worker's [sole duty, an invariant that spans the whole run] → it, together
	// with the launch instruction and the raw data of the intent-anchored target assets, goes into
	// the system prompt: the system prompt is reassembled on every run and is never compacted away,
	// so the intent is always present in a long run, and continuation doesn't depend on whether the
	// transcript history kept that first message. The cost is that the system prompt mixes in
	// per-intent volatile data and loses cross-intent cache reuse; this is a deliberate trade-off
	// (losing the intent is far worse than saving tokens).
	// The divergence from the planner's "situation block in the user turn" is intentional: the
	// planner is itself the one that produces intents and has no single mandate, whereas the worker
	// does. Only the [global situation overview] stays in the launch user message — it can degrade,
	// tolerates staleness, and can be compacted away without harm.
	// This intent's dedicated working directory <workDir>/tasks/<taskID>/i<intentID>, pre-created on
	// the engine side.
	runDir := ensureRunDir(w.workDir, taskID, intent.ID)
	// The run-wide intent is not the current tool action. Do not forward it or
	// inherit a parent run's background into the action reviewer.
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	sysBody := workerSystem(w.proxyAddr, w.proxyCACert, w.workDir, runDir, w.recording)
	if w.wantConstraints() {
		sysBody += constraintBlock(ts) // inject operational constraints (if any) into the system prompt; the worker strictly obeys them when executing
	}
	// intent block → intent-anchored asset block → launch instruction, appended to the end of the system prompt in order (same append pattern as constraintBlock).
	sysBody += renderIntentTask(intent)
	if as != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDs(ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					sysBody += "\n\nTarget assets corresponding to this intent's asset_ids:\n" + string(b)
				}
				// These assets the intent explicitly targets → automatically folded into the task
				// test scope (same conservative granularity as insertAssets). upsertTaskScope's
				// ON CONFLICT DO NOTHING + the uq_task_scope unique index guarantee no duplicate
				// inserts; a re-run/retry is likewise an idempotent no-op.
				// When asset-coverage is disabled, the test scope (the denominator) is no longer accumulated.
				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	sysBody += "\n\nStart executing the intent above: do just it, produce only facts, assets, findings, and stop when done."
	system, boundary := deferredSystem(sysBody, def)
	// The task-level deadline (injected via ctx) clamps this run's wall-clock budget + decides the wrap-up phrasing (see taskclock.go).
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch goes through the recording proxy, so its HTTP is traced just like curl; loading
		// the proxy CA lets HTTPS certificates re-signed by the MITM [pass validation normally]
		// (rather than disabling validation). An empty proxy means a direct connection.
		// On execution-plane split (remoteWebFetch), the built-in WebFetch is turned off in favor
		// of the remote proxy tool injected above, which the Agent side points at its local recording proxy.
		EnableWebFetch: !remoteWebFetch,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// On execution-plane split, the background manager lives only on the Agent → turn off the
		// SDK's local Monitor/Task* injection (preventing shell spawning on the control plane) and
		// replace it with the remote proxy injected above.
		DisableBackgroundTasks: remoteWebFetch,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a standalone egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty means a direct connection.
		EnableWebSearch:       w.webSearch.Enabled,
		WebSearchBackend:      w.webSearch.Backend,
		BraveSearchAPIKey:     w.webSearch.BraveKey,
		TavilySearchAPIKey:    w.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: w.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  w.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   w.webSearch.DeepSeekModel,
		WebSearchProxy:        w.webSearch.Proxy,
		// Bash subcommands' HTTP goes through the recording proxy by default and trusts its CA (tools need no -x/-k).
		// On execution-plane split, Bash runs on the Agent side and the egress environment is injected
		// locally by the Agent (pointing at its local recording proxy); the control plane does not push
		// proxy settings, avoiding carrying management-side network information across the boundary.
		BashEnv:    ExecBashEnv(ctx, w.proxyAddr, w.proxyCACert),
		WorkingDir: runDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// Wall-clock budget, judged at round boundaries, doesn't interrupt midway; 0 = unlimited. With a
		// task-level deadline, clamp to min(own budget, time remaining until the deadline) so this run
		// naturally enters wrap-up when the task hits its deadline (see taskclock.go).
		MaxDuration: maxDur,
		// Hitting the budget (rounds OR duration) → the SDK runs one wrap-up round (Bash hidden) to write
		// back what's been identified, avoiding a botched ending.
		// When clamped (bounded by the task deadline), use PromptByReason: by timeout = the task hit its
		// deadline → task-timeout phrasing; by step count = steps within the clamped window ran out first
		// → fall back to per-run phrasing. When not clamped, keep pure per-run.
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. The truncation cap uses the SDK default (30000 characters).
		ToolOutputDir: cmdOutDir(runDir),
		Compaction:    compactionConfig(w.compactionWindow()), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),                  // session-scoped temporary todos (TodoWrite), purely for planning, discarded on exit
		NonStreaming:  w.nonStreaming(),                       // when the profile is non-streaming, go through Provider.Complete
		MaxTokens:     w.maxTokens(),                          // 0 = send no cap; the server default decides
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// The intent / launch instruction / intent-anchored assets have been delivered with the
	// system prompt (see sysBody assembly above). This launch user message carries only the
	// [global situation overview] — degradable big-picture info, fine to compact away.
	// In the rare case the overview fails to marshal and is empty, fall back to a launch
	// sentence to avoid an empty first-turn user message.
	input := overview
	if strings.TrimSpace(input) == "" {
		input = "Start executing the intent you were handed in the system prompt: do just it, produce only facts, assets, findings, and stop when done."
	}

	// Experimental feature: when enabled, noa takes over context compaction (archives consolidated under <workDir>/noa/<SessionID>, persistent).
	noaSession := WorkerSessionID(ts.ID(), intent.ID)
	enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	ctx, endExec := beginExecSession(ctx) // split mode: isolate + tear down this intent run's Agent-hosted state
	defer endExec()
	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Resume prior conversation if this intent was paused/blocked/exhausted and is
	// being re-run. The transcript ID is deterministic per intent, so if a prior
	// session exists the worker continues from where it left off instead of
	// restarting from scratch.
	alreadyRecorded := false
	if w.tx != nil {
		_ = s.Resume(opts.SessionID)
		alreadyRecorded = requestID != "" && hasWorkerChatMessage(s.Messages(), requestID)
		if len(s.Messages()) > 0 && message == "" {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "Continue executing."
		} else if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
		}
	}
	if message != "" {
		if alreadyRecorded {
			input = "Continue executing the new intent from the last manual conversation input. Don't repeat actions already completed."
		} else if len(s.Messages()) > 0 {
			input = workerChatMarker(requestID) + "\n[New intent from manual conversation input]\n" + message +
				"\n\nExecute this manual input right away, then decide from the context whether the original task still needs to continue."
		} else {
			input += "\n\n" + workerChatMarker(requestID) + "\n[New intent from manual conversation input]\n" + message +
				"\n\nPrioritize executing this manual input."
		}
	}

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// MaxDuration now interrupts an in-flight tool at the wall-clock deadline and
	// enters the wrap-up phase on the live ctx, so a run whose tool overran the budget
	// still settles (no external hard-timeout backstop needed). ctx itself carries only
	// pause / planner kill / shutdown, which the engine distinguishes and re-queues/stops.
	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
