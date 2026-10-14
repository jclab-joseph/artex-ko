// Package selfupdate implements ARTEX's one-click in-page update: it pulls the new
// binary from a GitHub Release, verifies it, stages it, and atomically swaps it in on
// the next startup.
//
// Overall division of labor (see start.sh / start.bat):
//
//	startup script = a dumb supervisor loop whose only job is "after the process exits, decide by exit code whether to relaunch it"
//	this package   = all the error-prone logic (download / SHA256 verify / smoke test / swap / rollback on failure)
//
// The swap lives in Go rather than the scripts because the sha256 verification and smoke
// test would otherwise need two implementations across sh and bat (sha256sum / shasum /
// certutil), and this is exactly the step that must never go wrong — swap in a binary that
// won't run and the supervisor faithfully relaunches it over and over, leaving the user to rescue it by hand.
//
// A full update goes through three process launches:
//
//	① old server receives /api/update/apply → download & verify → stage artex.new → exit 75
//	② script relaunches the old version → Bootstrap finds artex.new → verify + smoke test → swap → exit 75
//	③ script relaunches, now the new version → Bootstrap records an attempt → clears the marker after a successful start
//
// Any failing step reverts to the old version: in ②, a failed verification deletes the
// staged file and keeps running the old version; in ③, failing to survive to the marker
// clear 3 times in a row (crashing before it comes up) automatically swaps artex.old back in.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExitRestart is the "please, supervisor, relaunch me" exit code (EX_TEMPFAIL). When the
// startup script sees it, it reruns immediately, without counting toward crash backoff. 0
// means a normal user-initiated stop (the script leaves the loop); anything else counts as a crash.
const ExitRestart = 75

// maxAttempts is how many start attempts are allowed after a swap. Each start of the new
// version increments the counter by 1, and surviving past settleDelay clears the marker;
// crashing maxAttempts times in a row means the new version simply won't come up, so it auto-rolls back.
const maxAttempts = 3

// Paths is every file involved in an update, all rooted under **the executable's own
// directory**. It deliberately avoids CWD: when run as a service the working directory
// may be / or any path, and using CWD would drop the staged file elsewhere, breaking the swap logic outright.
type Paths struct {
	Dir     string // directory containing the executable
	Current string // currently running binary        artex      / artex.exe
	New     string // staged new version              artex.new  / artex.new.exe
	Sum     string // sha256 of the new version (hex) artex.new.sha256 / artex.new.exe.sha256
	Old     string // old version backed up before the swap  artex.old / artex.old.exe
	Marker  string // update-state marker             artex.upgrade.json
}

// ResolvePaths derives all update paths from the current executable.
//
// On Windows the .new/.old files must also carry the .exe suffix, or the smoke test and
// post-swap execution both fail, so the suffix is stripped first and then re-appended,
// making the naming symmetric across both platforms.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("실행 파일 위치 확인 실패: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // ".exe" on Windows, usually empty on Unix
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker records the progress of a swap, used to trigger an auto-rollback when the new version won't start.
type marker struct {
	From     string `json:"from"`     // version before the update
	To       string `json:"to"`       // target version
	Attempts int    `json:"attempts"` // start attempts made since the swap
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes the staged files. A successful swap, a failed verification, and a
// user cancel all go through it, so a leftover artex.new is not retried on the next startup.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// CompareVersions compares two version numbers, returning -1/0/1 (a<b / a==b / a>b).
// ok=false means at least one side is not a comparable version number (e.g. a local dev
// build's "dev", or git describe output like "0.3.7-2-gabc1234-dirty"); in that case the
// caller should disable one-click updates, or a dev build would be "upgraded" to a stable release and overwrite uncommitted changes.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses a version number of the form "v0.3.7" / "0.3.7" into a [3]int.
//
// It only accepts a clean three-part form: on non-tag builds build.sh uses git describe
// to produce suffixed versions like "0.3.7-2-gabc1234", which must be judged incomparable
// rather than treated as 0.3.7 — otherwise a dev build would be mistaken for "already latest" or overwritten by a stable release.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker reports whether the process is running in a container. Under Docker a swap
// writes to the container's writable layer, and `docker compose up -d` rebuilding the
// container reverts to the version baked into the image — this is expected behavior (the
// user is pulling a new image anyway), but the frontend needs to be able to say so clearly.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
