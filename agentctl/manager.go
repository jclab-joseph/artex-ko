// Package agentctl is the control-plane side of ARTEX's execution-plane split. It
// owns the mTLS certificate authority, issues short-lived connection bundles for
// sandboxed Agents, tracks live Agent connections (dialed in either direction), and
// hands the engine a remoteexec.Backend that routes a task's tool calls to a sandbox.
//
// It deliberately knows nothing about the LLM: it moves tool calls and results, never
// prompts or secrets. The server package wires it to its HTTP API and to the engine's
// execution-backend resolver.
package agentctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Autumn-27/artex/mcpconn"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/google/uuid"
)

// Agent is one live execution-plane connection.
type Agent struct {
	ID          string              `json:"id"`
	Mode        remoteexec.ConnMode `json:"mode"`
	Tools       []string            `json:"tools"`
	ConnectedAt time.Time           `json:"connected_at"`
	RemoteAddr  string              `json:"remote_addr,omitempty"`

	sess      *remoteexec.Session
	backend   *remoteexec.RemoteBackend
	toolMetas []remoteexec.WireToolMeta // announced metadata (for tools Mgmt can't build locally, e.g. Agent-hosted MCP)
}

// Manager is the control-plane agent registry + CA.
type Manager struct {
	dataDir string
	ca      *remoteexec.CA
	mgmtID  remoteexec.Identity

	mu     sync.RWMutex
	agents map[string]*Agent // by agent id, live connections only
	// issued records agent ids we handed out a bundle for but have not yet seen
	// connect — purely informational for the UI.
	issued map[string]time.Time
	// pins binds a task id to a specific Agent id, so a task's execution always lands
	// in one chosen sandbox (multi-agent routing). Absent → "any connected Agent".
	pins map[string]string

	listener *remoteexec.AgentListener
}

// NewManager loads (or creates) the control-plane CA and management identity under
// dataDir and returns a ready Manager. The CA private key never leaves the control
// plane; Agents receive only the CA certificate and their own short-lived leaf.
func NewManager(dataDir string) (*Manager, error) {
	m := &Manager{
		dataDir: dataDir,
		agents:  map[string]*Agent{},
		issued:  map[string]time.Time{},
		pins:    map[string]string{},
	}
	if err := m.loadOrInitPKI(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) caCertPath() string   { return filepath.Join(m.dataDir, "agent-ca.crt") }
func (m *Manager) caKeyPath() string    { return filepath.Join(m.dataDir, "agent-ca.key") }
func (m *Manager) mgmtCertPath() string { return filepath.Join(m.dataDir, "agent-mgmt.crt") }
func (m *Manager) mgmtKeyPath() string  { return filepath.Join(m.dataDir, "agent-mgmt.key") }

func (m *Manager) loadOrInitPKI() error {
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return err
	}
	caCert, errC := os.ReadFile(m.caCertPath())
	caKey, errK := os.ReadFile(m.caKeyPath())
	if errC == nil && errK == nil {
		ca, err := remoteexec.LoadCA(caCert, caKey)
		if err != nil {
			return fmt.Errorf("agentctl: load CA: %w", err)
		}
		m.ca = ca
	} else {
		ca, err := remoteexec.NewCA()
		if err != nil {
			return fmt.Errorf("agentctl: create CA: %w", err)
		}
		m.ca = ca
		if err := writeSecret(m.caCertPath(), ca.CertPEM); err != nil {
			return err
		}
		if err := writeSecret(m.caKeyPath(), ca.KeyPEM); err != nil {
			return err
		}
		log.Printf("[agentctl] 신규 제어 플레인 CA 생성: %s", m.caCertPath())
	}

	mgmtCert, errMC := os.ReadFile(m.mgmtCertPath())
	mgmtKey, errMK := os.ReadFile(m.mgmtKeyPath())
	if errMC == nil && errMK == nil {
		m.mgmtID = remoteexec.Identity{CertPEM: mgmtCert, KeyPEM: mgmtKey}
	} else {
		id, err := m.ca.IssueManagement()
		if err != nil {
			return fmt.Errorf("agentctl: issue management cert: %w", err)
		}
		m.mgmtID = id
		_ = writeSecret(m.mgmtCertPath(), id.CertPEM)
		_ = writeSecret(m.mgmtKeyPath(), id.KeyPEM)
	}
	return nil
}

// IssueBundle mints a connection bundle for a new (or named) Agent. mode selects who
// dials; address is where the Agent listens (ModeMgmtDials) or dials (ModeAgentDials).
// agentID may be empty to auto-generate one.
func (m *Manager) IssueBundle(mode remoteexec.ConnMode, address, agentID string, mcp []mcpconn.Config) (*remoteexec.Bundle, error) {
	if mode != remoteexec.ModeAgentDials && mode != remoteexec.ModeMgmtDials {
		return nil, fmt.Errorf("agentctl: invalid mode %q", mode)
	}
	if agentID == "" {
		agentID = "agent-" + uuid.NewString()[:8]
	}
	identity, err := m.ca.IssueAgent(agentID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	b := &remoteexec.Bundle{
		Version:  1,
		Mode:     mode,
		AgentID:  agentID,
		Address:  address,
		CACert:   m.ca.CertPEM,
		Identity: identity,
		Issued:   now,
		Expires:  now.Add(remoteexec.AgentCertTTL),
		MCP:      mcp,
	}
	m.mu.Lock()
	m.issued[agentID] = now
	m.mu.Unlock()
	return b, nil
}

// StartListener opens the Management-side mTLS listener for Agents that dial in
// (ModeAgentDials) and registers each connection. Runs until ctx is cancelled.
func (m *Manager) StartListener(ctx context.Context, addr string) error {
	ln, err := remoteexec.ListenForAgents(addr, m.mgmtID, m.ca.CertPEM)
	if err != nil {
		return err
	}
	m.listener = ln
	log.Printf("[agentctl] Agent 접속 수신 대기: %s (agent-dials 모드)", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			acceptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			sess, hello, err := ln.Accept(acceptCtx)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// transient accept/hello error (e.g. a bad client); keep serving
				continue
			}
			m.register(sess, hello, remoteexec.ModeAgentDials)
		}
	}()
	return nil
}

// DialAgent connects out to a listening Agent (ModeMgmtDials) and registers it.
func (m *Manager) DialAgent(ctx context.Context, agentID, address string) (*Agent, error) {
	sess, hello, err := remoteexec.DialAgent(ctx, address, m.mgmtID, string(m.ca.CertPEM), agentID)
	if err != nil {
		return nil, err
	}
	return m.register(sess, hello, remoteexec.ModeMgmtDials), nil
}

func (m *Manager) register(sess *remoteexec.Session, hello *remoteexec.Frame, mode remoteexec.ConnMode) *Agent {
	a := &Agent{
		ID:          hello.AgentID,
		Mode:        mode,
		Tools:       hello.Tools,
		ConnectedAt: time.Now(),
		sess:        sess,
		backend:     remoteexec.NewRemoteBackend(sess, hello.Tools),
		toolMetas:   hello.ToolMetas,
	}
	m.mu.Lock()
	// If an agent id reconnects, replace the stale entry.
	if old := m.agents[a.ID]; old != nil {
		old.sess.Close()
	}
	m.agents[a.ID] = a
	delete(m.issued, a.ID)
	m.mu.Unlock()
	log.Printf("[agentctl] Agent 연결됨: id=%s mode=%s tools=%v", a.ID, mode, a.Tools)

	// Reap the registry entry when the session ends.
	go func() {
		<-sess.Done()
		m.mu.Lock()
		if cur := m.agents[a.ID]; cur == a {
			delete(m.agents, a.ID)
		}
		m.mu.Unlock()
		log.Printf("[agentctl] Agent 연결 종료: id=%s (%v)", a.ID, sess.Err())
	}()
	return a
}

// Backend returns the remote backend for a specific agent id, or nil if not connected.
func (m *Manager) Backend(agentID string) remoteexec.Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a := m.agents[agentID]; a != nil {
		return a.backend
	}
	return nil
}

// PinTask binds a task to a specific Agent id (multi-agent routing). Pass an empty
// agentID (or call UnpinTask) to clear.
func (m *Manager) PinTask(taskID, agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if agentID == "" {
		delete(m.pins, taskID)
		return
	}
	m.pins[taskID] = agentID
}

// UnpinTask clears a task's Agent pin.
func (m *Manager) UnpinTask(taskID string) { m.PinTask(taskID, "") }

// Has reports whether an Agent with this id is currently connected.
func (m *Manager) Has(agentID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.agents[agentID] != nil
}

// Pins returns a snapshot of the task→Agent pin map (task id → agent id).
func (m *Manager) Pins() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.pins))
	for k, v := range m.pins {
		out[k] = v
	}
	return out
}

// PinnedAgentID returns the Agent id pinned to a task, or "".
func (m *Manager) PinnedAgentID(taskID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pins[taskID]
}

// PinnedBackend returns (backend, true) when the task is pinned to a specific Agent;
// backend is nil within that pair when the pinned Agent is not currently connected.
// (ok=false means no pin — the caller should fall back to AnyBackend.)
func (m *Manager) PinnedBackend(taskID string) (remoteexec.Backend, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agentID, ok := m.pins[taskID]
	if !ok {
		return nil, false
	}
	if a := m.agents[agentID]; a != nil {
		return a.backend, true
	}
	return nil, true // pinned but disconnected
}

// AnyBackend returns the backend of the most-recently connected live Agent, or nil.
// Used by the "auto" task→agent binding when no explicit agent is selected.
func (m *Manager) AnyBackend() remoteexec.Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var newest *Agent
	for _, a := range m.agents {
		if newest == nil || a.ConnectedAt.After(newest.ConnectedAt) {
			newest = a
		}
	}
	if newest != nil {
		return newest.backend
	}
	return nil
}

// Exec runs one tool on a connected Agent — a diagnostic/health hook (and the path the
// docker-compose e2e drives). Returns the agent's result text.
func (m *Manager) Exec(ctx context.Context, agentID, tool string, input json.RawMessage) (*remoteexec.WireResult, error) {
	m.mu.RLock()
	a := m.agents[agentID]
	m.mu.RUnlock()
	if a == nil {
		return nil, errors.New("agentctl: agent not connected: " + agentID)
	}
	return a.sess.Call(ctx, tool, input, &remoteexec.WireToolCtx{WorkingDir: "diag"}, nil)
}

// ExecAny runs one tool on the most-recently connected Agent — used by process-global
// consumers (the enrich pool) that are not bound to a specific task/agent. Returns an
// error when no Agent is connected.
func (m *Manager) ExecAny(ctx context.Context, tool string, input json.RawMessage) (*remoteexec.WireResult, error) {
	m.mu.RLock()
	var newest *Agent
	for _, a := range m.agents {
		if newest == nil || a.ConnectedAt.After(newest.ConnectedAt) {
			newest = a
		}
	}
	m.mu.RUnlock()
	if newest == nil {
		return nil, errors.New("agentctl: no agent connected")
	}
	return newest.sess.Call(ctx, tool, input, &remoteexec.WireToolCtx{WorkingDir: "enrich"}, nil)
}

// List returns a snapshot of live agents (no secrets).
func (m *Manager) List() []Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Agent, 0, len(m.agents))
	for _, a := range m.agents {
		out = append(out, Agent{ID: a.ID, Mode: a.Mode, Tools: a.Tools, ConnectedAt: a.ConnectedAt, RemoteAddr: a.RemoteAddr})
	}
	return out
}

// AnnouncedMetas returns announced tool metadata across connected agents, keyed by
// tool name (newest-connected agent wins on conflict). Management uses it to build
// placeholders for tools it has no local definition of — notably Agent-hosted MCP
// tools, whose schemas live only on the Agent that connected to the MCP server.
func (m *Manager) AnnouncedMetas() map[string]remoteexec.WireToolMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Fill oldest-first so a newer agent's meta overwrites an older one's.
	agents := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ConnectedAt.Before(agents[j].ConnectedAt) })
	out := map[string]remoteexec.WireToolMeta{}
	for _, a := range agents {
		for _, meta := range a.toolMetas {
			out[meta.Name] = meta
		}
	}
	return out
}

// HasLive reports whether at least one Agent is connected.
func (m *Manager) HasLive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.agents) > 0
}

// CACertPEM returns the CA certificate (safe to expose; it is in every bundle).
func (m *Manager) CACertPEM() []byte { return m.ca.CertPEM }

func writeSecret(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
