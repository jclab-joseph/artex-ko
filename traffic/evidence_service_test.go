package traffic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// TestEvidenceServiceRoundTrip proves the Agent-side __artex_traffic_evidence service
// and the control-plane wire types agree: an exchange recorded in a store, exported
// through the service, and reconstructed exactly as remoteEvidenceSource does yields
// the same bytes and lengths ReadEvidence gives locally — so the split-mode snapshot
// is byte-identical to the in-process one (writeBody enforces n == len).
func TestEvidenceServiceRoundTrip(t *testing.T) {
	tr, _ := openTraffic(t)
	reqBody := []byte(`{"user":"admin","password":"P@ssw0rd"}`)
	respBody := []byte(`{"token":"abc123","note":"内网测试账号"}`)
	tr.record(newFlow("api.example.com", "POST", "/v1/login", reqBody, respBody))
	id := onlyExchangeID(t, tr)

	// Ground truth: read the evidence directly, as the monolith would.
	var wantReq, wantResp []byte
	var wantReqHead, wantRespHead string
	if err := tr.ReadEvidence(context.Background(), []string{id}, func(e EvidenceExchange) error {
		var err error
		if wantReq, err = io.ReadAll(e.Request); err != nil {
			return err
		}
		if wantResp, err = io.ReadAll(e.Response); err != nil {
			return err
		}
		wantReqHead, wantRespHead = e.ReqHead, e.RespHead
		return nil
	}); err != nil {
		t.Fatalf("ReadEvidence: %v", err)
	}

	// Export through the service (what the Agent serves over the channel).
	raw, _ := json.Marshal(map[string][]string{"ids": {id}})
	res, err := tr.EvidenceService().Call(context.Background(), raw, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("EvidenceService call: %v", err)
	}
	if res.IsError {
		t.Fatalf("EvidenceService reported error: %s", res.Flatten())
	}

	// Reconstruct exactly as the control-plane adapter does.
	var out EvidenceWireResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("result not JSON: %q", res.Flatten())
	}
	if len(out.Exchanges) != 1 {
		t.Fatalf("expected 1 exchange, got %d", len(out.Exchanges))
	}
	wx := out.Exchanges[0]
	if wx.ReqOversize || wx.RespOversize {
		t.Fatalf("small bodies must not be flagged oversize: %+v", wx)
	}
	gotReq, err := base64.StdEncoding.DecodeString(wx.ReqB64)
	if err != nil {
		t.Fatalf("req b64: %v", err)
	}
	gotResp, err := base64.StdEncoding.DecodeString(wx.RespB64)
	if err != nil {
		t.Fatalf("resp b64: %v", err)
	}

	if string(gotReq) != string(wantReq) {
		t.Fatalf("request mismatch:\n got=%q\nwant=%q", gotReq, wantReq)
	}
	if string(gotResp) != string(wantResp) {
		t.Fatalf("response mismatch:\n got=%q\nwant=%q", gotResp, wantResp)
	}
	if wx.ReqHead != wantReqHead || wx.RespHead != wantRespHead {
		t.Fatalf("head mismatch: req %q/%q resp %q/%q", wx.ReqHead, wantReqHead, wx.RespHead, wantRespHead)
	}
	// Lengths must equal the delivered bytes so writeBody's n==expectedLength holds.
	if int64(len(gotReq)) != int64(len(wantReq)) || int64(len(gotResp)) != int64(len(wantResp)) {
		t.Fatalf("length mismatch: req %d/%d resp %d/%d", len(gotReq), len(wantReq), len(gotResp), len(wantResp))
	}
}

// TestEvidenceServiceNilSafe: a zero/absent store must error cleanly, never panic.
func TestEvidenceServiceNilSafe(t *testing.T) {
	var tr *Traffic
	raw, _ := json.Marshal(map[string][]string{"ids": {"nope"}})
	res, err := tr.EvidenceService().Call(context.Background(), raw, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("call errored: %v", err)
	}
	if !res.IsError {
		t.Fatalf("nil store should report a tool error, got: %s", res.Flatten())
	}
}
