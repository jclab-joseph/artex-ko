package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// goals_api.go 가 사용자에게 돌려주는 오류 응답 문구. 명령·요청 필드명(text·vulnclass·
// gid)·enum 은 원문 그대로 두고, 사람이 읽는 메시지만 한국어로 둔다. 영어 writeErr
// (task not found·invalid JSON·bad goal id)는 F3b 중국어 전용 범위라 보존한다.
const (
	errGoalTaskDeletingAdd    = "작업을 삭제하는 중이라 목표를 추가할 수 없습니다"
	errGoalTaskDeletingEdit   = "작업을 삭제하는 중이라 목표를 수정할 수 없습니다"
	errGoalTaskDeletingDelete = "작업을 삭제하는 중이라 목표를 삭제할 수 없습니다"
	errGoalTextEmpty          = "목표 내용은 비워 둘 수 없습니다"
	errGoalNotFound           = "목표를 찾을 수 없습니다"
	errGoalReadAfterAdd       = "목표를 저장한 뒤 읽지 못했습니다"
	errGoalReadAfterEdit      = "목표를 수정한 뒤 읽지 못했습니다"
)

// The overview "goal management" manual CRUD API. Writes the same batch of goal nodes as the agent-side set_goals tool,
// but the entry point is the human adding/editing/deleting directly in the UI; after an add/edit it reuses the "revive task" logic (admitTask resume:
// terminal → running, clear pause, queue if needed); a delete does not revive (a product decision). Every change handler goes through
// beginTaskOperation/decInflight to avoid racing with task deletion (consistent with the intent CRUD).

// listGoals returns all goals for this task (text/vulnclass/state split out), for the goal-management card to render.
func (s *Server) listGoals(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 10000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"goals": goalDTOs(goals)})
}

// addGoal manually adds one goal: persist it (hung under the task root's spawns) → record an "added a goal" trigger to wake the
// planner → revive the task, so the planner re-judges whether it is met based on the new goal.
func (s *Server) addGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingAdd)
		return
	}
	defer s.engine.decInflight(t.ID)

	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	payload := map[string]any{"text": text}
	if vc := strings.TrimSpace(body.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	id, err := t.Store.AddGoal(payload, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if of, _ := t.Store.OriginFactID(); of > 0 && id > 0 {
		_ = t.Store.Link(of, db.RelSpawns, id) // goal descends from the task root (origin fact)
	}
	t.NotifyGoal([]string{text}) // record a "human added a goal: …" trigger and wake the planner
	s.reviveTask(t)              // pull a completed/paused task back into the running state to keep going
	node, _ := t.Store.GetNode(id)
	if node == nil {
		writeErr(w, 500, errGoalReadAfterAdd)
		return
	}
	writeJSON(w, 200, goalDTO(node))
}

// editGoal manually edits one goal's text (and vulnclass): update the DB → record a "user changed the goal from old to new"
// trigger to wake the planner → revive the task, so the planner adjusts direction based on the new goal.
func (s *Server) editGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingEdit)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	oldText := goalDTO(node).Text
	if err := t.Store.UpdateGoalPayload(gid, text, strings.TrimSpace(body.VulnClass)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalEdited(oldText, text) // record a "human changed the goal from old to new" trigger and wake the planner
	s.reviveTask(t)                   // same as add: revive the task and re-judge based on the new goal
	updated, _ := t.Store.GetNode(gid)
	if updated == nil {
		writeErr(w, 500, errGoalReadAfterEdit)
		return
	}
	writeJSON(w, 200, goalDTO(updated))
}

// deleteGoal manually deletes one goal (hard delete, cascading edge/anchor removal): delete from the DB → record a "user deleted the goal X"
// trigger to wake the planner and re-judge the remaining goals accordingly. By product decision, a delete does [not] revive the task.
func (s *Server) deleteGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingDelete)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	text := goalDTO(node).Text
	if err := t.Store.DeleteGoal(gid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalDeleted(text) // record a "human deleted the goal: …" trigger and wake the planner (does not revive the task)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
