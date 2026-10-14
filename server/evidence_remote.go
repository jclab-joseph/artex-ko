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
	"github.com/Autumn-27/artex/traffic"
)

// remoteEvidenceSource is the split-mode evidence source: the recorder lives in the
// sandbox Agent, so the bytes a finding cites are pulled out of it over the channel
// (via the Agent's __artex_traffic_evidence service) exactly when the finding is
// bound, then snapshotted into Management's own evidence store like any other. Report
// rendering afterwards never touches the Agent — the snapshot is self-contained.
//
// It implements evidence.TrafficEvidence. One id per call bounds each RPC frame
// (req+resp base64) well under the transport limit; bindings cite only a handful of
// exchanges, so the extra round-trips are negligible.
type remoteEvidenceSource struct {
	agents *agentctl.Manager
	// taskID is the pin-key of the task that owns these findings. Evidence MUST be pulled
	// from the sandbox Agent that executed that task (and therefore recorded the traffic),
	// not from "whatever Agent is connected" — see ReadEvidence.
	taskID string
}

var _ evidence.TrafficEvidence = (*remoteEvidenceSource)(nil)

func (r *remoteEvidenceSource) ReadEvidence(ctx context.Context, ids []string, consume func(traffic.EvidenceExchange) error) error {
	if r.agents == nil {
		return errors.New("流量录制运行在隔离沙箱 Agent 中，但执行面控制未初始化；无法同步证据。")
	}
	// A task's captured traffic lives in the recorder of the ONE Agent that executed it.
	// Routing to the newest-connected Agent (or any other) would, in a multi-Agent /
	// multi-tenant deployment where agent == tenant, read a different tenant's capture —
	// wrong evidence and a cross-tenant data leak. Resolve the task's pinned Agent and fail
	// closed when it is unknown or disconnected; never fall back to another Agent.
	agentID := r.agents.PinnedAgentID(r.taskID)
	if r.taskID == "" || agentID == "" {
		return errors.New("이 작업에 고정된 실행 Agent 가 없어 증거 출처 Agent 를 특정할 수 없습니다; 교차 테넌트 유출을 막기 위해 증거 동기화를 거부합니다(작업을 실행 Agent 에 고정하세요).")
	}
	if !r.agents.Has(agentID) {
		return fmt.Errorf("이 작업을 실행한 샌드박스 Agent(%s)가 연결되어 있지 않아 증거를 동기화할 수 없습니다", agentID)
	}
	for _, id := range ids {
		in, _ := json.Marshal(map[string][]string{"ids": {id}})
		res, err := r.agents.ExecOn(ctx, agentID, traffic.EvidenceToolName, in)
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
			// Length is the decoded body length — equal to the original capture, since
			// non-oversize bodies cross whole. writeBody enforces n == ReqLen/RespLen,
			// so this keeps the snapshot byte-identical to the in-process path.
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
