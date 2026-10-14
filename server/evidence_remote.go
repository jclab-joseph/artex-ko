package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Autumn-27/artex/agentctl"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/artex/traffic"
)

// splitEvidenceSource reads a finding's captured traffic bytes from wherever the task that
// produced them actually recorded them. The recorder may live in the sandbox Agent (split
// mode) or in-process (monolith), and in a multi-Agent deployment each Agent is its own
// tenant — so the source must be chosen per call, never "whatever Agent is connected".
// ReadEvidence picks, in order:
//
//  1. The executing Agent's backend bound to the ctx. During an agent run (finding recorder,
//     bind_finding_traffic tool) this is the Agent that ran the task and therefore holds its
//     capture — authoritative in EVERY offload mode, with no dependence on task pins and no
//     cross-tenant risk (it is the task's own executor).
//  2. The local in-process recorder, when one exists (monolith, or a task that executed on
//     the control plane).
//  3. Otherwise (e.g. a manual bind with no run context, in split mode): the task's pinned
//     Agent, failing CLOSED when the task has no pin or its Agent is offline. Never the
//     newest/any Agent — that would read another tenant's capture (wrong data + leak).
type splitEvidenceSource struct {
	local  evidence.TrafficEvidence // in-process recorder (s.m.traffic); nil in strict split mode
	agents *agentctl.Manager        // nil when the agent control plane is disabled
	taskID string                   // pin-key of the owning task (for path 3)
}

var _ evidence.TrafficEvidence = (*splitEvidenceSource)(nil)

func (r *splitEvidenceSource) ReadEvidence(ctx context.Context, ids []string, consume func(traffic.EvidenceExchange) error) error {
	// (1) The executing Agent is bound to the ctx during a run — authoritative in all modes.
	if rb, ok := remoteexec.BackendFrom(ctx).(*remoteexec.RemoteBackend); ok {
		if sess := rb.Session(); sess != nil {
			return r.readVia(ctx, ids, consume, func(c context.Context, in json.RawMessage) (*remoteexec.WireResult, error) {
				return sess.Call(c, traffic.EvidenceToolName, in, &remoteexec.WireToolCtx{WorkingDir: "enrich"}, nil)
			})
		}
	}
	// (2) Local recorder: monolith, or a task that executed in-process.
	if r.local != nil {
		return r.local.ReadEvidence(ctx, ids, consume)
	}
	// (3) No run context in split mode: route to the task's OWN Agent; fail closed otherwise.
	if r.agents == nil {
		return errors.New("트래픽 녹화가 격리된 샌드박스 Agent 에서 실행되지만, 실행 플레인 제어가 초기화되지 않아 증거를 동기화할 수 없습니다.")
	}
	agentID := r.agents.PinnedAgentID(r.taskID)
	if r.taskID == "" || agentID == "" {
		return errors.New("이 작업에 고정된 실행 Agent 가 없어 증거 출처 Agent 를 특정할 수 없습니다; 교차 테넌트 유출을 막기 위해 증거 동기화를 거부합니다(작업을 실행 Agent 에 고정하세요).")
	}
	if !r.agents.Has(agentID) {
		return fmt.Errorf("이 작업을 실행한 샌드박스 Agent(%s)가 연결되어 있지 않아 증거를 동기화할 수 없습니다", agentID)
	}
	return r.readVia(ctx, ids, consume, func(c context.Context, in json.RawMessage) (*remoteexec.WireResult, error) {
		return r.agents.ExecOn(c, agentID, traffic.EvidenceToolName, in)
	})
}

// readVia pulls each id's exchange via call (one id per RPC frame keeps req+resp base64 well
// under the transport limit) and feeds decoded exchanges to consume. Lengths are the decoded
// body lengths — equal to the original capture since non-oversize bodies cross whole, so the
// snapshot stays byte-identical to the in-process path.
func (r *splitEvidenceSource) readVia(ctx context.Context, ids []string, consume func(traffic.EvidenceExchange) error, call func(context.Context, json.RawMessage) (*remoteexec.WireResult, error)) error {
	for _, id := range ids {
		in, _ := json.Marshal(map[string][]string{"ids": {id}})
		res, err := call(ctx, in)
		if err != nil {
			return err
		}
		if res != nil && res.IsError {
			return errors.New(resultText(res))
		}
		var out traffic.EvidenceWireResult
		if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
			return err
		}
		for _, wx := range out.Exchanges {
			if wx.ReqOversize || wx.RespOversize {
				return traffic.ErrEvidenceOversize
			}
			req, err := base64.StdEncoding.DecodeString(wx.ReqB64)
			if err != nil {
				return err
			}
			resp, err := base64.StdEncoding.DecodeString(wx.RespB64)
			if err != nil {
				return err
			}
			if err := consume(traffic.EvidenceExchange{
				ID: wx.ID, TS: wx.TS, URL: wx.URL, Method: wx.Method, Status: wx.Status,
				ContentType: wx.ContentType, ReqHead: wx.ReqHead, RespHead: wx.RespHead,
				ReqLen: int64(len(req)), RespLen: int64(len(resp)),
				Request: bytes.NewReader(req), Response: bytes.NewReader(resp),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
