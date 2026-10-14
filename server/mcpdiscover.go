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

// mcpHostedTools decides, for one MCP server, whether it is hosted by the sandbox
// Agent (split mode) and if so returns the Management-side placeholder tools built
// from the Agent's announced metadata. The second return reports "handled": when true
// the caller must NOT connect the server locally (it runs in the sandbox), even if the
// placeholder set is currently empty (no Agent connected yet). When false, the server
// is a normal control-plane MCP and the caller connects it as before.
func (s *Server) mcpHostedTools(m *db.MCPServer) ([]actool.CoreTool, bool) {
	if m == nil || !m.AgentHosted || s.offloadMode() == "off" {
		return nil, false
	}
	// Agent-hosted + offload on: this MCP runs INSIDE the sandbox. Report "handled"
	// (hosted=true) even when no Agent control registry exists yet — control-plane
	// init failed, or it is not ready — or when none has announced. "handled" is what
	// stops the caller from connecting the server locally (discoverAndCacheMCP /
	// assembly.go), which would spawn the stdio child or open the endpoint ON the
	// control plane. The old `s.agents == nil → hosted=false` fell back to exactly that
	// local connect on the init-failure path. With no registry there are no placeholder
	// tools to offer: return (nil, true) so discovery reports "no Agent connected" and
	// assembly injects nothing — fail closed, never local (보안 리뷰: init 실패 경로).
	if s.agents == nil {
		return nil, true
	}
	metas := s.agents.AnnouncedMetas()
	prefix := "mcp__" + m.Name + "__"
	var out []actool.CoreTool
	for name, meta := range metas {
		if strings.HasPrefix(name, prefix) {
			out = append(out, remoteexec.CoreToolFromMeta(meta))
		}
	}
	return out, true
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
	// Discover from the Agent's announced tool metadata instead. This covers both startup
	// auto-discovery and manual refresh, which previously both called connectMCP locally.
	if tools, hosted := s.mcpHostedTools(m); hosted {
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
