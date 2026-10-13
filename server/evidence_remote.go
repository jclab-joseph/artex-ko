package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

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
}

var _ evidence.TrafficEvidence = (*remoteEvidenceSource)(nil)

func (r *remoteEvidenceSource) ReadEvidence(ctx context.Context, ids []string, consume func(traffic.EvidenceExchange) error) error {
	if r.agents == nil || !r.agents.HasLive() {
		return errors.New("流量录制运行在隔离沙箱 Agent 中，但当前没有连接的 Agent；无法同步证据。")
	}
	for _, id := range ids {
		in, _ := json.Marshal(map[string][]string{"ids": {id}})
		res, err := r.agents.ExecAny(ctx, traffic.EvidenceToolName, in)
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
