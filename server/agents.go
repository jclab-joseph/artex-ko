package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agentctl"
	"github.com/Autumn-27/artex/enrich"
	"github.com/Autumn-27/artex/execsvc"
	"github.com/Autumn-27/artex/remoteexec"
)

// Execution-plane split (Management ↔ sandboxed Agent). Configuration is via env so no
// DB migration is needed for the first cut:
//
//	ARTEX_AGENT_LISTEN   address to accept Agents dialing in (ModeAgentDials), e.g. ":8790".
//	                     Empty → do not listen (use ModeMgmtDials via POST /api/agents/dial).
//	ARTEX_AGENT_OFFLOAD  "off" (default) | "auto" | "require" | "pinned":
//	                       off     — run tools in-process (monolith behavior).
//	                       auto    — offload to a connected Agent when one is present, else local.
//	                       require — all execution MUST run in a sandbox; block (fail-closed)
//	                                 when no Agent is connected (any connected Agent will do).
//	                       pinned  — strictest: every task MUST have an explicitly selected
//	                                 Agent and runs ONLY on it. No auto-pick, no local fallback.
//	                                 A task whose Agent is unselected/disconnected does not even
//	                                 start (its planner stays idle) — see execReady.
const (
	envAgentListen  = "ARTEX_AGENT_LISTEN"
	envAgentOffload = "ARTEX_AGENT_OFFLOAD"
)

// offloadMode is the resolved execution policy.
func (s *Server) offloadMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envAgentOffload))) {
	case "pinned":
		return "pinned"
	case "require":
		return "require"
	case "auto":
		return "auto"
	default:
		return "off"
	}
}

// initAgentControl builds the agent-control manager, starts the inbound listener when
// configured, and wires the engine's execution-backend resolver. Failure is non-fatal:
// the control plane keeps working in-process (unless offload is "require", in which
// case execution fails closed — the whole point of the secure posture).
func (s *Server) initAgentControl(ctx context.Context, dataDir string) {
	mgr, err := agentctl.NewManager(dataDir)
	if err != nil {
		log.Printf("[agentctl] 초기화 실패(실행 플레인 분리 비활성): %v", err)
		return
	}
	s.agents = mgr

	if addr := strings.TrimSpace(os.Getenv(envAgentListen)); addr != "" {
		if err := mgr.StartListener(ctx, addr); err != nil {
			log.Printf("[agentctl] Agent 수신 리스너 시작 실패(%s): %v", addr, err)
		}
	}

	mode := s.offloadMode()
	log.Printf("[agentctl] 실행 플레인 오프로드 모드=%s", mode)
	s.engine.SetExecBackendResolver(func(t *Task) remoteexec.Backend {
		return s.resolveExecBackend(t, mode)
	})
	// "pinned" mode gates task start on the selected Agent being connected.
	s.engine.SetExecReadyResolver(s.execReadyFor)

	// Restore persisted task→Agent selections into the runtime pin map so "pinned"
	// tasks re-bind to their chosen Agent across a control-plane restart.
	if s.m != nil && s.m.pg != nil {
		if sel, err := s.m.pg.TaskExecAgents(); err == nil {
			for taskID, agentID := range sel {
				s.agents.PinTask(taskID, agentID)
			}
			if len(sel) > 0 {
				log.Printf("[agentctl] 복원된 작업→Agent 선택 %d건", len(sel))
			}
		} else {
			log.Printf("[agentctl] 작업→Agent 선택 복원 실패: %v", err)
		}
	}

	// enrich(DNS/HTTP 자산 프로브)의 네트워크 I/O 도 표적 지향이므로 Agent 로 보낸다.
	// off = 종전대로 in-process. auto/require = Agent 사용(require 는 미연결 시 skip).
	if mode != "off" && s.m != nil && s.m.enrich != nil {
		s.m.enrich.SetProber(&agentProber{agents: mgr, mode: mode})
	}
}

// agentProber implements enrich.Prober by running the sandbox's __artex_dns /
// __artex_httpprobe services over the agent channel. It owns the offload semantics:
// no Agent + auto → ErrProbeLocally (in-process fallback); no Agent + require → a hard
// error so no target I/O happens on the control plane.
type agentProber struct {
	agents *agentctl.Manager
	mode   string
}

func (p *agentProber) noAgent() error {
	if p.mode == "auto" {
		return enrich.ErrProbeLocally
	}
	return errors.New("no sandbox agent for enrich probe")
}

func (p *agentProber) ResolveDNS(ctx context.Context, host string) (*enrich.DNSData, error) {
	if !p.agents.HasLive() {
		return nil, p.noAgent()
	}
	in, _ := json.Marshal(map[string]string{"host": host})
	res, err := p.agents.ExecAny(ctx, execsvc.ToolDNS, in)
	if err != nil {
		return nil, err
	}
	var out execsvc.DNSResult
	if e := json.Unmarshal([]byte(resultText(res)), &out); e != nil {
		return nil, e
	}
	return &enrich.DNSData{A: out.A, AAAA: out.AAAA, CNAME: out.CNAME}, nil
}

func (p *agentProber) ProbeHTTP(ctx context.Context, rawURL string) (*enrich.HTTPData, error) {
	if !p.agents.HasLive() {
		return nil, p.noAgent()
	}
	in, _ := json.Marshal(map[string]string{"url": rawURL})
	res, err := p.agents.ExecAny(ctx, execsvc.ToolHTTPProbe, in)
	if err != nil {
		return nil, err
	}
	var out execsvc.ProbeResult
	if e := json.Unmarshal([]byte(resultText(res)), &out); e != nil {
		return nil, e
	}
	return &enrich.HTTPData{Status: out.Status, ContentLength: out.ContentLength, Title: out.Title}, nil
}

func resultText(res *remoteexec.WireResult) string {
	if res == nil {
		return ""
	}
	var s string
	for _, b := range res.Content {
		s += b.Text
	}
	return s
}

// resolveExecBackend picks a task's execution backend per the offload policy. A task
// pinned to a specific Agent always routes there; otherwise the newest connected Agent
// is used. Under "require", a missing (or disconnected-pinned) Agent fails closed.
func (s *Server) resolveExecBackend(t *Task, mode string) remoteexec.Backend {
	if mode == "off" {
		return remoteexec.LocalBackend{}
	}
	// "pinned": the task runs ONLY on its explicitly selected Agent — no auto-pick, no
	// local fallback. Unselected or disconnected → fail-closed (and execReady keeps the
	// task from even starting, so this is the belt to execReady's suspenders).
	if mode == "pinned" {
		if t != nil {
			if b, pinned := s.agents.PinnedBackend(t.ID); pinned && b != nil {
				return b
			}
			if _, pinned := s.agents.PinnedBackend(t.ID); pinned {
				return remoteexec.NewFailClosedBackend("이 작업에 선택된 샌드박스 Agent 가 연결되어 있지 않습니다")
			}
		}
		return remoteexec.NewFailClosedBackend("이 작업에는 실행할 샌드박스 Agent 가 선택되어 있지 않습니다")
	}
	// Pinned task: route to its Agent, or fail closed / fall back if it is down.
	if t != nil {
		if b, pinned := s.agents.PinnedBackend(t.ID); pinned {
			if b != nil {
				return b
			}
			if mode == "require" {
				return remoteexec.NewFailClosedBackend("이 작업에 지정된 샌드박스 Agent 가 연결되어 있지 않습니다")
			}
			return remoteexec.LocalBackend{} // auto: pinned agent down → local fallback
		}
	}
	if b := s.agents.AnyBackend(); b != nil {
		return b
	}
	if mode == "require" {
		// No sandbox connected but policy requires one → fail closed so a dangerous
		// tool is never run on the control plane.
		return remoteexec.NewFailClosedBackend("실행 정책이 샌드박스 Agent 를 요구하지만 연결된 Agent 가 없습니다")
	}
	return remoteexec.LocalBackend{}
}

// execReadyFor reports whether a task may start/continue planning. Only "pinned" mode
// gates this: the task runs only when its explicitly selected Agent is connected. Other
// modes always return true (their start behavior is unchanged). Keeping the gate here —
// not in resolveExecBackend — means an unselected task never burns an LLM planning round.
func (s *Server) execReadyFor(t *Task) bool {
	if s.offloadMode() != "pinned" {
		return true
	}
	if t == nil || s.agents == nil {
		return false
	}
	b, pinned := s.agents.PinnedBackend(t.ID)
	return pinned && b != nil // selected AND connected
}

// --- HTTP handlers -------------------------------------------------------------

func (s *Server) agentsReady(w http.ResponseWriter) bool {
	if s.agents == nil {
		writeErr(w, http.StatusServiceUnavailable, "에이전트 제어가 비활성화되어 있습니다")
		return false
	}
	return true
}

// agentsList returns the live Agents plus the current offload mode and listener state.
func (s *Server) agentsList(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"offload_mode": s.offloadMode(),
		"listen_addr":  os.Getenv(envAgentListen),
		"agents":       s.agents.List(),
		"pins":         s.agents.Pins(),
	})
}

type issueBundleReq struct {
	Mode    string `json:"mode"`     // "agent-dials-mgmt" | "mgmt-dials-agent"
	Address string `json:"address"`  // agent-dials: Management's reachable addr; mgmt-dials: Agent's listen addr
	AgentID string `json:"agent_id"` // optional
}

// agentsIssueBundle mints a connection bundle for a new sandbox Agent. ARTEX only
// produces the bundle; the operator injects it into their own sandbox and launches
// `artex-agent --bundle <file>`.
func (s *Server) agentsIssueBundle(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	var req issueBundleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "요청 본문을 해석할 수 없습니다")
		return
	}
	mode := remoteexec.ConnMode(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = remoteexec.ModeAgentDials
	}
	bundle, err := s.agents.IssueBundle(mode, strings.TrimSpace(req.Address), strings.TrimSpace(req.AgentID), s.agentHostedMCPConfigs())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := bundle.Marshal()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Return the bundle as a downloadable JSON the operator saves into the sandbox.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"artex-agent-"+bundle.AgentID+".json\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type dialReq struct {
	AgentID string `json:"agent_id"`
	Address string `json:"address"`
}

// agentsDial connects out to a listening Agent (ModeMgmtDials). The Agent must have
// been launched with a mgmt-dials bundle at that address.
func (s *Server) agentsDial(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	var req dialReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "요청 본문을 해석할 수 없습니다")
		return
	}
	if req.AgentID == "" || req.Address == "" {
		writeErr(w, http.StatusBadRequest, "agent_id 와 address 가 필요합니다")
		return
	}
	a, err := s.agents.DialAgent(r.Context(), req.AgentID, req.Address)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type pinReq struct {
	TaskID string `json:"task_id"`
}

// agentsPin binds a task to a specific execution Agent (multi-agent routing). The
// task's subsequent tool calls route to that Agent.
func (s *Server) agentsPin(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	id := r.PathValue("id")
	var req pinReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.TaskID) == "" {
		writeErr(w, http.StatusBadRequest, "task_id 가 필요합니다")
		return
	}
	taskID := strings.TrimSpace(req.TaskID)
	// Validate the target Agent is actually connected and the task exists, so a typo
	// (or a stale/non-existent task id) is rejected instead of silently "succeeding".
	if !s.agents.Has(id) {
		writeErr(w, http.StatusNotFound, "에이전트가 연결되어 있지 않습니다: "+id)
		return
	}
	task := s.m.ResolveTask(taskID)
	if task == nil {
		writeErr(w, http.StatusNotFound, "작업을 찾을 수 없습니다: "+taskID)
		return
	}
	s.agents.PinTask(taskID, id)
	if tid, err := strconv.ParseInt(task.ID, 10, 64); err == nil {
		if err := s.m.pg.SetTaskExecAgent(tid, id); err != nil {
			log.Printf("[agentctl] 작업 %s Agent 선택 영속화 실패: %v", task.ID, err)
		}
	}
	// A newly selected Agent may unblock a "pinned" task that was idling — nudge a round.
	task.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"task_id": taskID, "agent_id": id})
}

// agentsUnpin clears a task's Agent pin (falls back to any-agent routing).
func (s *Server) agentsUnpin(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	var req pinReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.TaskID) == "" {
		writeErr(w, http.StatusBadRequest, "task_id 가 필요합니다")
		return
	}
	taskID := strings.TrimSpace(req.TaskID)
	s.agents.UnpinTask(taskID)
	if tid, err := strconv.ParseInt(taskID, 10, 64); err == nil {
		if err := s.m.pg.SetTaskExecAgent(tid, ""); err != nil {
			log.Printf("[agentctl] 작업 %s Agent 선택 해제 영속화 실패: %v", taskID, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"task_id": taskID, "unpinned": true})
}

type execReq struct {
	Tool  string          `json:"tool"`
	Input json.RawMessage `json:"input"`
}

// agentsExec runs one tool on a connected Agent — a health/diagnostic hook and the
// path the docker-compose e2e exercises. It bypasses the LLM entirely.
func (s *Server) agentsExec(w http.ResponseWriter, r *http.Request) {
	if !s.agentsReady(w) {
		return
	}
	id := r.PathValue("id")
	var req execReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "요청 본문을 해석할 수 없습니다")
		return
	}
	if req.Tool == "" {
		writeErr(w, http.StatusBadRequest, "tool 이 필요합니다")
		return
	}
	res, err := s.agents.Exec(r.Context(), id, req.Tool, req.Input)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	text := ""
	if res != nil {
		for _, b := range res.Content {
			text += b.Text
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tool":     req.Tool,
		"is_error": res != nil && res.IsError,
		"output":   text,
	})
}
