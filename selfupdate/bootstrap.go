package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// smokeEnv makes the child process launched by the smoke test skip Bootstrap entirely.
//
// Strictly speaking it would be harmless to omit it: the child's os.Executable() is
// artex.new, so every derived path carries the .new prefix and never touches the real
// update files. But relying on that coincidence is too fragile; an explicit short-circuit
// is obvious at a glance and also saves the child a pointless disk probe.
const smokeEnv = "ARTEX_SELFUPDATE_SMOKE"

// Action is the instruction Bootstrap gives main.
type Action int

const (
	// Continue: start the server as usual.
	Continue Action = iota
	// Restart: exit immediately with ExitRestart so the supervisor script relaunches.
	Restart
)

// State describes the update status at this startup, so /api/update/check can honestly
// tell the frontend "whether the last update succeeded or was rolled back".
type State struct {
	Pending     bool   // swapped but not yet confirmed stable
	RolledBack  bool   // this startup just performed an auto-rollback
	FailedStage bool   // staged file failed verification/smoke test and was discarded
	Detail      string // one-line explanation for the user
}

// Bootstrap runs at the very start of main; it must be called before any port is bound or the database is opened.
//
// Three situations:
//
//	① staged file artex.new exists → verify + smoke test; on success swap and request a restart, on failure discard and keep running the old version
//	② only the marker file remains → means a swap just finished; record one attempt, and roll back after enough consecutive failures
//	③ nothing at all               → normal startup
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] skipping bootstrap: %v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged handles the "a staged file exists" situation: swap on successful verification, discard on failure.
//
// This is the only place in the whole update path that overwrites the executable, and the
// last gate — the smoke test catches problems like a corrupted download, the wrong
// architecture, or a missing dynamic link. Once a binary that won't run is let through, the
// supervisor script relaunches it tirelessly while the Go code never gets to run, so auto-rollback is off the table.
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] staged new version failed verification; discarded, continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "새 버전 검증에 실패해 폐기했습니다: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] swap failed, continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "버전 교체에 실패했습니다: " + err.Error()}
	}

	// Swap succeeded. Keep the marker and let the next startup (which runs the new version) confirm whether it is stable.
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to write the update marker (auto-rollback capability lost): %v", err)
	}
	log.Printf("[update] swapped to %s, exiting to restart (exit %d)", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback handles "the startup after a swap": it accumulates the attempt count and swaps the old version back once the limit is exceeded.
//
// The count is only incremented after the Go code is running, so it covers failures of the
// "executes but crashes during initialization" kind (incompatible config, port already in
// use, a DB migration blowing up); "cannot exec at all" is caught by the pre-swap smoke test, and only together are the two complete.
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// If even the rollback fails, don't restart again or it spirals into an infinite
			// restart loop. Clear the marker and let the process start in its current state — if it won't come up, the user can at least see why in the logs.
			log.Printf("[update] new version failed to start %d times in a row, and rollback failed too: %v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "새 버전 시작에 실패하고 롤백도 실패했습니다: " + err.Error()}
		}
		log.Printf("[update] new version failed to start %d times in a row; rolled back to %s, exiting to restart (exit %d)",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("새 버전 시작에 실패해 이전 버전으로 롤백했습니다(%s)", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to update the update marker: %v", err)
	}
	log.Printf("[update] new version is starting (attempt %d/%d); the update will be confirmed once it runs stably",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle confirms the new version is running stably and clears the update marker.
//
// main calls it on a delay after the HTTP listener is up: only surviving this long counts;
// otherwise the marker stays in place and the next startup keeps accumulating attempts until a rollback is triggered.
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // not a post-update startup, nothing to do
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] failed to clear the update marker: %v", err)
		return
	}
	log.Printf("[update] new version is running stably, update complete (previous version kept as %s)", p.Old)
}

// SettleDelay is how long the process must run to be judged "the new version survived".
const SettleDelay = 30 * time.Second

// verifyStaged verifies the staged file: first compare SHA256, then actually launch it once.
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("체크섬 읽기 실패: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("체크섬 계산 실패: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 이 일치하지 않습니다(다운로드가 손상됐거나 변조됨)")
	}
	return smokeTest(p.New)
}

// smokeTest launches the new binary with -h to confirm it really executes on this system.
// This catches a large class of problems: a truncated download, the wrong architecture (exec format error), missing dependencies, and so on.
func smokeTest(bin string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("실행 권한 부여 실패: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-h")
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("스모크 테스트 시간 초과(새 바이너리가 응답하지 않음)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("스모크 테스트 실패: %v: %s", err, snippet)
	}
	return nil
}

// swap replaces the current binary with the staged new version.
//
// Both Unix and Windows allow renaming a running executable (Windows forbids deleting and
// overwriting, but not renaming), so this needs no per-platform branch and no stopping of the process first.
func swap(p Paths) error {
	// Windows's rename won't overwrite an existing target, so a .old left by the previous update must be cleared first.
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("이전 백업 %s 정리 실패: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("현재 버전 백업 실패: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// The swap failed but the current version has already been moved away, so it must be put back as-is, or the next startup has no executable.
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("새 버전 설치 실패(%v), 현재 버전 복구도 실패: %w", err, rerr)
		}
		return fmt.Errorf("새 버전 설치 실패: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback swaps back the old version that swap backed up.
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("롤백할 백업이 없습니다(%s): %w", p.Old, err)
	}
	// Move the new version that won't start to .failed for investigation, rather than deleting it outright.
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("실패한 버전 이동 실패: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("이전 버전 복구 실패: %w", err)
	}
	return nil
}

// Rollback is the implementation of /api/update/rollback: proactively revert to the previous version.
// It only does the swap; the restart is likewise left to the supervisor script (the caller then exits with ExitRestart).
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("롤백할 이전 버전이 없습니다(" + p.Old + " 없음)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("이전 버전을 실행할 수 없어 롤백을 거부합니다: %w", err)
	}
	// Swap current and backup: after a rollback you can still roll forward again.
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("현재 버전 이동 실패: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("이전 버전 설치 실패: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] failed to tidy up the backup after rollback (does not affect operation): %v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup reports whether a rollbackable previous version exists, so the frontend can decide whether to show the rollback button.
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "알 수 없는 버전"
	}
	return s
}
