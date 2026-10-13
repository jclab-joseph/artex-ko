package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Autumn-27/artex/agentctl"
	"github.com/Autumn-27/artex/remoteexec"
)

// Execution-plane split (Management ↔ sandboxed Agent). Configuration is via env so no
// DB migration is needed for the first cut:
//
//	ARTEX_AGENT_LISTEN   address to accept Agents dialing in (ModeAgentDials), e.g. ":8790".
//	                     Empty → do not listen (use ModeMgmtDials via POST /api/agents/dial).
//	ARTEX_AGENT_OFFLOAD  "off" (default) | "auto" | "require":
//	                       off     — run tools in-process (monolith behavior).
//	                       auto    — offload to a connected Agent when one is present, else local.
//	                       require — all execution MUST run in a sandbox; block (fail-closed)
//	                                 when no Agent is connected. This is the secure posture.
const (
	envAgentListen  = "ARTEX_AGENT_LISTEN"
	envAgentOffload = "ARTEX_AGENT_OFFLOAD"
)

// offloadMode is the resolved execution policy.
func (s *Server) offloadMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envAgentOffload))) {
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
		log.Printf("[agentctl] 초기화 실패(실행면 분리 비활성): %v", err)
		return
	}
	s.agents = mgr

	if addr := strings.TrimSpace(os.Getenv(envAgentListen)); addr != "" {
		if err := mgr.StartListener(ctx, addr); err != nil {
			log.Printf("[agentctl] Agent 수신 리스너 시작 실패(%s): %v", addr, err)
		}
	}

	mode := s.offloadMode()
	log.Printf("[agentctl] 실행면 오프로드 모드=%s", mode)
	s.engine.SetExecBackendResolver(func(t *Task) remoteexec.Backend {
		return s.resolveExecBackend(t, mode)
	})
}

// resolveExecBackend picks a task's execution backend per the offload policy. Per-task
// Agent pinning can be layered on later (read a task setting here); for now it is the
// process-wide policy with "auto"/"require" choosing the newest connected Agent.
func (s *Server) resolveExecBackend(_ *Task, mode string) remoteexec.Backend {
	switch mode {
	case "off":
		return remoteexec.LocalBackend{}
	case "auto":
		if b := s.agents.AnyBackend(); b != nil {
			return b
		}
		return remoteexec.LocalBackend{}
	case "require":
		if b := s.agents.AnyBackend(); b != nil {
			return b
		}
		// No sandbox connected but policy requires one → fail closed so a dangerous
		// tool is never run on the control plane.
		return remoteexec.NewFailClosedBackend("실행 정책이 샌드박스 Agent 를 요구하지만 연결된 Agent 가 없습니다")
	default:
		return remoteexec.LocalBackend{}
	}
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
	bundle, err := s.agents.IssueBundle(mode, strings.TrimSpace(req.Address), strings.TrimSpace(req.AgentID))
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
