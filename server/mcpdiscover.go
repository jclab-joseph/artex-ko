package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcpconn"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP 이 돌려주는 전송 설정 검증 오류 네 가지는 사용자 노출이다 —
// pgRefreshMCP(server_mgmt.go) 가 discoverAndCacheMCP 실패를
// writeErr(502, errMgmtToolDiscoverFail+err.Error()) 로 응답 본문에 그대로 싣는다.
// 다른 호출처(assembly.go 의 에이전트 조립·discoverEmptyMCPsOnStartup 시작 자동 발견·
// sync_scopesentry.go 동기화·pgSaveMCP 추가 직후 발견)는 전부 log.Printf 로만 남기거나
// 버려서 에이전트 두뇌 입력이 아니다. 그래서 한국어화한다. 전송 방식 enum
// (stdio/http/sse)과 URL 은 와이어 식별자라 원문을 유지하고, UI mcpPage(전송 방식·명령·
// 원격 URL)와 표기를 맞춘다.
const (
	errMCPStdioNoCommand      = "stdio 전송 방식에 명령이 없습니다"
	errMCPHTTPNoURL           = "http 전송 방식에 URL 이 없습니다"
	errMCPSSENoURL            = "sse 전송 방식에 URL 이 없습니다"
	errMCPUnknownTransportFmt = "알 수 없는 전송 방식입니다: %q"
	// Agent-hosted MCP discovery needs a connected Agent (it comes from the Agent's
	// announced tool metadata, never a control-plane connection). Surfaced to the user by
	// pgRefreshMCP when they refresh an agent-hosted server with no Agent connected.
	errMCPAgentHostedNoAgentFmt = "agent-hosted MCP %q: 연결된 샌드박스 Agent 가 없어 도구를 발견할 수 없습니다(Agent 연결 후 다시 시도하세요)"
	// Strict offload (require/pinned) forbids connecting ANY non-agent-hosted MCP on the
	// control plane: a stdio server is a local child process and an http/sse server is
	// local egress — both the dangerous ops the split keeps off Management. Surfaced when
	// the user refreshes such a server under a strict posture.
	errMCPStrictNotHostedFmt = "MCP %q: 엄격 오프로드(require/pinned)에서는 Agent 호스팅이 아닌 MCP 를 제어 플레인에서 연결할 수 없습니다(해당 MCP 를 agent_hosted 로 설정하세요)"
)

// mcpConfigFromDB projects a stored MCP row into the db-free mcpconn.Config shared
// with the Agent (bundle). Env doubles as HTTP headers for http/sse transports.
func mcpConfigFromDB(m *db.MCPServer) mcpconn.Config {
	return mcpconn.Config{
		Name:      m.Name,
		Transport: m.Transport,
		Command:   m.Command,
		Args:      jsonStrSlice(m.Args),
		Env:       jsonStrMap(m.Env),
		URL:       m.URL,
		Insecure:  m.Insecure,
	}
}

// agentHostedMCPConfigs returns the enabled MCP servers flagged agent_hosted, in the
// db-free form carried by the connection bundle so the sandbox Agent hosts them.
func (s *Server) agentHostedMCPConfigs() []mcpconn.Config {
	all, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] agent-hosted 목록 조회 실패: %v", err)
		return nil
	}
	var out []mcpconn.Config
	for _, m := range all {
		if m.Enabled && m.AgentHosted {
			out = append(out, mcpConfigFromDB(m))
		}
	}
	return out
}

// mcpDisposition classifies how one MCP server is handled under the current offload policy.
type mcpDisposition int

const (
	mcpConnectLocal  mcpDisposition = iota // connect on the control plane (monolith / auto / non-strict)
	mcpAgentHosted                         // runs in the sandbox Agent; use announced metas, never local
	mcpBlockedStrict                       // strict posture + not agent-hosted: a local connection is forbidden
)

// dispositionOfMCP decides whether an MCP server runs in the sandbox Agent, is blocked,
// or is connected locally. agent_hosted servers (in any non-off mode) run in the Agent.
// Otherwise require/pinned forbid connecting ANY MCP on the control plane — a stdio
// server spawns a local child process and an http/sse server is local egress, both the
// dangerous ops the split keeps off Management — so a non-hosted MCP is BLOCKED there
// rather than connected, and the isolation no longer depends on the per-MCP agent_hosted
// checkbox being set (보안 리뷰: 엄격 모드에서도 MCP 로 로컬 명령 실행). off/auto keep the
// pre-split local connect (auto's local path is its intended fallback).
func (s *Server) dispositionOfMCP(m *db.MCPServer) mcpDisposition {
	if m == nil {
		return mcpConnectLocal
	}
	if m.AgentHosted && s.offloadMode() != "off" {
		return mcpAgentHosted
	}
	if strictOffload() {
		return mcpBlockedStrict
	}
	return mcpConnectLocal
}

// announcedHostedTools builds the Management-side placeholder tools for an agent-hosted
// MCP from the connected Agents' announced metadata. Empty when no Agent is connected or
// no control registry exists yet — the caller treats that as "hosted but unavailable".
func (s *Server) announcedHostedTools(m *db.MCPServer) []actool.CoreTool {
	if s.agents == nil {
		return nil
	}
	metas := s.agents.AnnouncedMetas()
	prefix := "mcp__" + m.Name + "__"
	var out []actool.CoreTool
	for name, meta := range metas {
		if strings.HasPrefix(name, prefix) {
			out = append(out, remoteexec.CoreToolFromMeta(meta))
		}
	}
	return out
}

// mcpHostedTools reports, for the agent tool-assembly seam, whether an MCP server must
// NOT be connected on the control plane (handled=true) and, when agent-hosted, the
// placeholder tools from the Agent's announce. handled=true with no tools means either
// agent-hosted-but-no-Agent or strict-mode-blocked: assembly injects nothing and skips
// the local connect either way. handled=false → a normal control-plane MCP (connect as
// before).
func (s *Server) mcpHostedTools(m *db.MCPServer) ([]actool.CoreTool, bool) {
	switch s.dispositionOfMCP(m) {
	case mcpAgentHosted:
		return s.announcedHostedTools(m), true
	case mcpBlockedStrict:
		return nil, true
	default:
		return nil, false
	}
}

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, errors.New(errMCPStdioNoCommand)
		}
		return mcp.NewStdioClient(ctx, m.Name, m.Command, jsonStrMap(m.Env), jsonStrSlice(m.Args)...)
	case "http":
		if m.URL == "" {
			return nil, errors.New(errMCPHTTPNoURL)
		}
		// env map doubles as HTTP headers (e.g. Authorization).
		return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	case "sse":
		if m.URL == "" {
			return nil, errors.New(errMCPSSENoURL)
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	default:
		return nil, fmt.Errorf(trMsg(errMCPUnknownTransportFmt), m.Transport)
	}
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	// Agent-hosted servers run INSIDE the sandbox: never connect them on the control
	// plane (that would spawn the stdio child / open the endpoint here — 보안 리뷰 F6).
	// Discover from the Agent's announced tool metadata instead. In strict offload a
	// non-hosted MCP is likewise refused, never connected locally. This covers startup
	// auto-discovery and manual refresh, which previously both called connectMCP locally.
	switch s.dispositionOfMCP(m) {
	case mcpBlockedStrict:
		return fmt.Errorf(trMsg(errMCPStrictNotHostedFmt), m.Name)
	case mcpAgentHosted:
		tools := s.announcedHostedTools(m)
		if len(tools) == 0 {
			return fmt.Errorf(trMsg(errMCPAgentHostedNoAgentFmt), m.Name)
		}
		cached := make([]db.MCPTool, 0, len(tools))
		for _, t := range tools {
			cached = append(cached, db.MCPTool{Name: t.Name(), Description: t.Description()})
		}
		if err := s.m.pg.SaveMCPTools(m.ID, cached); err != nil {
			return err
		}
		log.Printf(logT("[mcp] %s(agent-hosted) announce 에서 도구 %d개를 캐시했습니다"), m.Name, len(cached))
		return nil
	}
	cl, err := connectMCP(ctx, m)
	if err != nil {
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		return err
	}
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf(logT("[mcp] %s 에서 도구 %d개를 발견해 캐시했습니다"), m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers (npx) at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf(logT("[mcp] 시작 시 자동 발견: 목록을 읽지 못했습니다: %v"), err)
		return
	}
	for _, m := range servers {
		if !m.Enabled || len(m.Tools) > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf(logT("[mcp] 시작 시 %s 자동 발견에 실패했습니다: %v"), m.Name, err)
		}
		cancel()
	}
}
