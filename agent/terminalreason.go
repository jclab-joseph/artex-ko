package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/harness"
)

// runTrace retains the latest tool call so an interrupted run can identify the
// operation that was still in flight.
type runTrace struct {
	startedAt time.Time
	id        string
	name      string
	input     string
	at        time.Time
	pending   bool
}

func (t *runTrace) start(id, name, input string) {
	t.id, t.name, t.input, t.at, t.pending = id, name, input, time.Now(), true
}

func (t *runTrace) done(id string) {
	if id == t.id {
		t.pending = false
	}
}

var reasonHint = map[harness.TerminalReason]string{
	harness.ReasonCompleted:         "The model ended this turn normally but left no text summary; take the facts and assets from this turn's tool-call records",
	harness.ReasonMaxTurns:          "Step limit reached (MaxTurns): the SDK has run settling and written facts and assets back, and the intent is marked exhausted so the planner can continue in a new direction rather than treating it as a failure",
	harness.ReasonTimeout:           "Single-run wall-clock budget reached (MaxDuration): at the deadline the running tool is interrupted and settling happens in place, the identified facts and assets are written back, and the intent is marked exhausted",
	harness.ReasonModelError:        "The model or API call failed (network, auth, rate limit, provider 5xx, etc.); after retries are exhausted the intent is marked blocked — a transport-layer failure means this intent barely got anywhere; check its execution trace (get_worker_trace) before deciding whether to reassign it or try a different approach",
	harness.ReasonBlockingLimit:     "The context length hit the hard limit and the request was blocked before being sent; narrow the intent's scope or compress tool output",
	harness.ReasonPromptTooLong:     "The prompt is too long and the context-compaction retries are already exhausted, so execution cannot continue",
	harness.ReasonImageError:        "The current model does not support this turn's multimodal content; switch to a vision-capable model or avoid tools that return images",
	harness.ReasonStopHookPrevented: "The Stop hook prevented this turn from ending and it could not continue afterward; check whether the task's Guard rules are too strict",
	harness.ReasonHookStopped:       "A tool or hook deliberately stopped execution, for example an out-of-scope target or a forbidden command; check the interception note on the last tool_result",
	harness.ReasonAbortedStreaming:  "The run was cancelled during the model's streaming-output phase",
	harness.ReasonAbortedTools:      "The run was cancelled during the tool-execution phase",
}

// terminalText renders a terminal event with no final text into a compact summary
// and a Markdown detail block.
func terminalText(ctx context.Context, term *harness.Terminal, tr *runTrace) (string, string) {
	reason := term.Reason
	aborted := reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools
	// Prompt may return ctx.Err directly without a terminal event. Preserve the
	// cancellation cause instead of falling back to an empty/unknown terminal reason.
	if reason == "" && ctx.Err() != nil {
		aborted = true
	}

	var sum string
	if aborted {
		_, short, _, ok := AbortReason(ctx)
		if !ok {
			short = "could not determine the cancellation cause"
		}
		stage := "mid-execution"
		switch reason {
		case harness.ReasonAbortedStreaming:
			stage = "in the model-output phase"
		case harness.ReasonAbortedTools:
			stage = "in the tool-execution phase"
		}
		sum = "(run interrupted: " + short + "; stopped " + stage + progressSuffix(term, tr) + ", incomplete)"
	} else if reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout {
		sum = "(run budget limit reached (" + string(reason) + "), settled and wrote facts back" + progressSuffix(term, tr) + "; no text summary this run)"
	} else {
		hint := terminalReasonHint(reason)
		sum = "(no text summary, terminal reason " + terminalReasonLabel(reason) + ": " + firstLine(hint, 80) + ")"
	}

	var b strings.Builder
	b.WriteString(sum)
	b.WriteString("\n\n")
	displayReason := terminalReasonLabel(reason)
	fmt.Fprintf(&b, "- **Terminal reason**: `%s` - %s\n", displayReason, terminalReasonHint(reason))
	if aborted {
		code, _, why, ok := AbortReason(ctx)
		if ok {
			fmt.Fprintf(&b, "- **Interruption cause** (`%s`): %s\n", code, why)
		} else {
			b.WriteString("- **Interruption cause**: unavailable; the canceller may not have attached a named cause via context.WithCancelCause\n")
		}
	}
	if term.Err != nil {
		fmt.Fprintf(&b, "- **Underlying error**: `%v`\n", term.Err)
	}
	if aborted && strings.TrimSpace(term.Text) != "" {
		b.WriteString("- **Partial output generated before cancellation**:\n\n")
		b.WriteString(term.Text)
		b.WriteString("\n\n")
	}
	if term.Turns > 0 {
		fmt.Fprintf(&b, "- **Executed**: %d model turns\n", term.Turns)
	}
	if !tr.startedAt.IsZero() {
		fmt.Fprintf(&b, "- **Run duration**: %s\n", roundDur(time.Since(tr.startedAt)))
	}
	if u := term.Usage; u.InputTokens+u.OutputTokens+u.CacheReadTokens+u.CacheWriteTokens > 0 {
		fmt.Fprintf(&b, "- **Cumulative tokens**: input %d / output %d / cache read %d / cache write %d\n",
			u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	if tr.name == "" {
		b.WriteString("- **Tool calls**: this run ended before issuing any tool call\n")
	} else if tr.pending {
		fmt.Fprintf(&b, "- **Tool running at interruption**: `%s` (running for %s, **no result returned**)\n\n  ```json\n  %s\n  ```\n",
			tr.name, roundDur(time.Since(tr.at)), firstLine(tr.input, 300))
	} else {
		fmt.Fprintf(&b, "- **Last tool before interruption**: `%s` (returned normally)\n", tr.name)
	}
	return sum, b.String()
}

func terminalReasonLabel(reason harness.TerminalReason) string {
	if reason == "" {
		return "context_canceled"
	}
	return string(reason)
}

func terminalReasonHint(reason harness.TerminalReason) string {
	if hint := reasonHint[reason]; hint != "" {
		return hint
	}
	if reason == "" {
		return "the run's context was cancelled, but no Terminal event was produced underneath"
	}
	return "unknown terminal reason; the harness may have added a new TerminalReason — please add it to reasonHint"
}

func progressSuffix(term *harness.Terminal, tr *runTrace) string {
	var parts []string
	if term.Turns > 0 {
		parts = append(parts, fmt.Sprintf("%d turns", term.Turns))
	}
	if !tr.startedAt.IsZero() {
		parts = append(parts, roundDur(time.Since(tr.startedAt)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", ran for " + strings.Join(parts, " / ")
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
