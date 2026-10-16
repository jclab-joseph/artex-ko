package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "user paused the task",
		"The user paused the task via the task control endpoint (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was cancelled deliberately; in-flight intents return to frontier(open) and, once the task resumes, are reclaimed and re-executed from the start")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "orchestrator Agent paused the task",
		"The orchestrator Agent called the pause_task tool to pause this task. This Planner/Worker run was cancelled deliberately; in-flight intents return to frontier(open) and are re-executed once resumed")
	AbortTaskDeleted = cause("task_deleted", "task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the delete barrier cancelled this task's running Planner, Worker and main Agent; this run's result will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the paused state",
		"On startup the backend restored the task's pause from the state persisted in the database. This run was cancelled; normally no Agent is running during the recovery phase")
	AbortPausedByRunWindow = cause("paused_by_run_window", "task is outside its allowed run window",
		"The task has a per-task run window (allowed hours) and the current time is outside it, so the scheduler auto-paused it. This Planner/Worker run was cancelled deliberately; in-flight intents return to frontier(open) and are reclaimed and re-executed once the window reopens and the task auto-resumes")
	AbortGoalMet = cause("goal_met", "planner judged the task goal met",
		"The planner judged the task goal met and set the task to done, then cancelled the Workers still running; these intents are marked stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "timeout settle-drain window exhausted",
		"After the task hit timeout it waited for running Workers to settle gracefully, but the 90-second drain grace period was still not enough, so a hard cancel was applied; intents are marked exhausted, and facts and assets already written during settling are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "planner killed this intent",
		"The planner called kill_work to deliberately terminate this intent, usually because the direction went off track or had no further value; the intent is marked stopped and will not be reclaimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "user paused this Worker intent",
		"The user paused the running Worker. This call was cancelled and the intent moved to paused; the intents, facts, findings and activity records already recorded are all kept, and execution restarts from the beginning once resumed")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "user deleted this Worker intent",
		"The user deleted the running Worker. This call was cancelled; after the Worker leaves the write section, the server handles the intent according to the delete mode the user chose — a soft delete only marks it deleted and keeps all output, while a hard delete cascades to remove the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished and released context",
		"The Worker finished normally, and the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, the cancel raced with the teardown event")
	AbortPausedRaceGuard = cause("paused_race_guard", "refused to start a run while paused",
		"While the task is paused, the engine refuses to issue a new execution context, to prevent a race between claim and pause from letting a Worker start anyway; already-claimed intents return to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "user stopped this conversation turn",
		"The user clicked stop, deliberately aborting this main Agent or conversation Agent run. The activity records already produced are kept, and you can go on to send the next message")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task pause aborted main Agent chat",
		"When the user paused the task, the running main Agent conversation was cancelled along with it. The activity records already produced are kept; resuming the task will not replay this turn's message automatically")
	AbortChatTurnFinished = cause("chat_turn_finished", "conversation turn finished normally",
		"This conversation turn finished normally, and the server is releasing the turn's context resources. This is not a run interruption; if it appears in an interruption message, the cancel raced with the teardown event")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running Agents are cancelled; after the restart, leftover running intents are reset to open and re-executed")
	AbortRunHardTimeout = cause("run_hard_timeout", "single-run hard-timeout backstop fired",
		"A single run exceeded the soft wall-clock budget plus the extra grace period, meaning the model request or some tool did not return for a long time, so the normal turn-boundary settling could not run. Focus your check on the last tool call before the interruption that never returned")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "upstream context hit its deadline",
			"upstream context hit its deadline, but the setter did not attach a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "canceller attached no named cause",
			"upstream context was cancelled, but the canceller did not attach a named cause via context.WithCancelCause; register the cause in agent/cancelcause.go and wire it into this cancellation point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
