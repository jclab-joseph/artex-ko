package traffic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// EvidenceToolName is the db-free execution service the Agent hosts so the control
// plane can SYNC captured evidence out of the sandbox at finding-bind time. It is
// invoked programmatically over the channel (never shown to the model), analogous to
// the execsvc __artex_* services. The store itself stays in the sandbox; only the
// exact bytes a finding cites cross, and only when the finding is bound.
const EvidenceToolName = "__artex_traffic_evidence"

// maxInlineEvidenceBody caps one body transferred inline per call so the single RPC
// frame stays well under the transport's 64 MiB limit (base64 inflates ~4/3, and a
// call carries at most req+resp). Bodies above this are flagged oversize rather than
// truncated — evidence must never be silently shortened — and the control plane
// surfaces a clear error directing the operator to generate the report in-sandbox.
const maxInlineEvidenceBody = 8 << 20

// EvidenceWireExchange is one captured exchange serialized for cross-channel evidence
// sync. Bodies are base64; Oversize marks a side that exceeded maxInlineEvidenceBody
// (its *_b64 is then empty). Shared by the Agent service (encode) and the control
// plane adapter (decode) so the two cannot drift.
type EvidenceWireExchange struct {
	ID           string `json:"id"`
	TS           int64  `json:"ts"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	Status       int    `json:"status"`
	ContentType  string `json:"content_type"`
	ReqHead      string `json:"req_head"`
	RespHead     string `json:"resp_head"`
	ReqLen       int64  `json:"req_len"`
	RespLen      int64  `json:"resp_len"`
	ReqB64       string `json:"req_b64"`
	RespB64      string `json:"resp_b64"`
	ReqOversize  bool   `json:"req_oversize,omitempty"`
	RespOversize bool   `json:"resp_oversize,omitempty"`
}

// EvidenceWireResult is the service's JSON result: one entry per requested id.
type EvidenceWireResult struct {
	Exchanges []EvidenceWireExchange `json:"exchanges"`
}

// readCappedBody reads up to maxInlineEvidenceBody+1 bytes; the extra byte lets the
// caller detect (without allocating the whole thing) that a body is oversize.
func readCappedBody(r io.Reader) (data []byte, oversize bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, maxInlineEvidenceBody+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxInlineEvidenceBody {
		return nil, true, nil
	}
	return data, false, nil
}

// EvidenceService builds the __artex_traffic_evidence tool bound to this store. The
// Agent hosts it only when it runs the recorder; the control plane calls it with
// {"ids":[...]} and reconstructs finding-evidence snapshots from the result.
func (t *Traffic) EvidenceService() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        EvidenceToolName,
		Description: "internal: export captured traffic evidence by id (control-plane use only)",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []any{"ids"},
		},
		ReadOnly: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				IDs []string `json:"ids"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t == nil {
				return actool.Errorf("流量录制存储不可用"), nil
			}
			var out EvidenceWireResult
			err := t.ReadEvidence(ctx, a.IDs, func(e EvidenceExchange) error {
				wx := EvidenceWireExchange{
					ID: e.ID, TS: e.TS, URL: e.URL, Method: e.Method, Status: e.Status,
					ContentType: e.ContentType, ReqHead: e.ReqHead, RespHead: e.RespHead,
					ReqLen: e.ReqLen, RespLen: e.RespLen,
				}
				req, over, err := readCappedBody(e.Request)
				if err != nil {
					return err
				}
				wx.ReqOversize = over
				if !over {
					wx.ReqB64 = base64.StdEncoding.EncodeToString(req)
				}
				resp, over, err := readCappedBody(e.Response)
				if err != nil {
					return err
				}
				wx.RespOversize = over
				if !over {
					wx.RespB64 = base64.StdEncoding.EncodeToString(resp)
				}
				out.Exchanges = append(out.Exchanges, wx)
				return nil
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, err := json.Marshal(out)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(string(b)), nil
		},
	})
}

// ErrEvidenceOversize is returned by the control-plane adapter when a cited body
// exceeds the inline transfer cap and therefore cannot be synced out of the sandbox.
var ErrEvidenceOversize = errors.New("流量证据正文超过同步上限，无法从沙箱导出；请在沙箱内生成报告")
