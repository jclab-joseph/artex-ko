package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

// The HTTP surface for one-click page updates. The actual download/verify/swap logic all lives in the selfupdate package;
// this only handles the auth boundary, concurrency mutex, progress broadcast, and telling main "time to exit".
//
// The restart is not done by this process: after staging the new version the process exits with selfupdate.ExitRestart,
// and a supervisor script (start.sh / start.bat, or the ENTRYPOINT under Docker) brings it back up.

// 사용자에게 노출되는 업데이트 메시지(SSE 진행 메시지·검사 사유·에러 응답).
// 프런트엔드(system/settings 의 update-card)가 progress.message·reason·writeErr
// 본문을 그대로 렌더하므로 한국어로 둔다. 로그·중국어 주석은 Z2(로그 최하위)라 범위 밖.
const (
	updateMsgPreparing          = "준비 중…"
	updateMsgFailed             = "업데이트 실패"
	updateMsgStaged             = "새 버전이 준비되었습니다. 재시작 중…"
	updateErrNotReleaseFmt      = "현재 버전 %q 은(는) 정식 릴리스 버전이 아니므로 원클릭 업데이트를 사용할 수 없습니다"
	updateErrAlreadyLatestFmt   = "이미 최신 버전입니다 (%s)"
	updateErrInProgress         = "이미 업데이트가 진행 중입니다"
	updateErrRollbackInProgress = "업데이트가 진행 중이어서 롤백할 수 없습니다"
)

// restartCh is closed once an upgrade is ready or a rollback completes; main then exits with ExitRestart.
var (
	restartOnce sync.Once
	restartCh   = make(chan struct{})
)

// RestartRequested returns a channel that is closed when "please exit and let the supervisor bring me back up".
func RestartRequested() <-chan struct{} { return restartCh }

func requestRestart() { restartOnce.Do(func() { close(restartCh) }) }

// bootState is selfupdate.Bootstrap's conclusion for this startup (upgrade succeeded / just rolled back /
// staged file discarded), injected by main, so /api/update/check can faithfully tell the frontend how the last upgrade ended.
var (
	bootStateMu sync.Mutex
	bootState   selfupdate.State
)

// SetBootUpdateState is called once by main at startup.
func SetBootUpdateState(st selfupdate.State) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState = st
}

func bootUpdateState() selfupdate.State {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	return bootState
}

// releaseCache caches the result of the latest-version query against GitHub.
//
// The top-bar "new version available" hint queries once on every full page load, and the unauthenticated GitHub API is
// 60 per IP per hour — without caching, opening a few tabs or refreshing a few times exhausts the quota,
// and then a real update query can't get through. When the user explicitly clicks "check for updates" they can force past the cache.
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch is the data-fetch function, an injection point kept only for tests; when nil it goes through the real GitHub query.
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// Failure results are cached briefly too, otherwise every page load would wait out a timeout while GitHub is unreachable;
	// but the TTL is short so it recovers on its own soon after the network comes back.
	releaseErrTTL = 2 * time.Minute
	// the timeout for queries. NewClient's 30-minute timeout is for downloading the full package; checking the version must not wait that long.
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get returns the latest Release, hitting the cache instead of the network when possible.
//
// Holds the lock throughout the fetch: concurrent requests queue for the result of the same query rather than each hitting GitHub
// (multiple tabs querying at once right after a page load is exactly when rate limiting is most likely).
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// A cancelled request (the user closed the tab) does not mean GitHub has a problem, so do not write it into the cache,
	// otherwise the next visitor gets a baffling "cancelled" error.
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateProgress is one progress update pushed to the frontend.
type updateProgress struct {
	Phase   selfupdate.Phase `json:"phase"`
	Percent int              `json:"percent"` // meaningful only during the download phase; -1 otherwise
	Message string           `json:"message"`
	Version string           `json:"version,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// updateHub holds the progress of one upgrade and broadcasts it to SSE subscribers.
//
// running also acts as a mutex: a second POST /api/update/apply during an upgrade gets a 409 directly,
// avoiding two goroutines writing to the same artex.new at once.
type updateHub struct {
	mu      sync.Mutex
	running bool
	cur     updateProgress
	subs    map[chan updateProgress]struct{}
}

var updHub = &updateHub{
	cur:  updateProgress{Phase: selfupdate.PhaseIdle, Percent: -1},
	subs: map[chan updateProgress]struct{}{},
}

// begin claims the upgrade permit, returning false if one is already in progress.
func (h *updateHub) begin(version string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return false
	}
	h.running = true
	h.cur = updateProgress{Phase: selfupdate.PhaseDownload, Percent: 0, Message: updateMsgPreparing, Version: version}
	h.fanout(h.cur)
	return true
}

// finish ends an upgrade. A nil err means staging succeeded and it is waiting for restart.
func (h *updateHub) finish(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	if err != nil {
		h.cur = updateProgress{Phase: selfupdate.PhaseFailed, Percent: -1, Message: updateMsgFailed, Error: err.Error(), Version: h.cur.Version}
	} else {
		h.cur = updateProgress{Phase: selfupdate.PhaseStaged, Percent: 100, Message: updateMsgStaged, Version: h.cur.Version}
	}
	h.fanout(h.cur)
}

func (h *updateHub) publish(ph selfupdate.Phase, pct int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = updateProgress{Phase: ph, Percent: pct, Message: msg, Version: h.cur.Version}
	h.fanout(h.cur)
}

// fanout must be called while holding h.mu. Subscriber channels are buffered and dropped when full —
// progress is discardable transient info, and a stuck SSE connection must never block the upgrade itself.
func (h *updateHub) fanout(p updateProgress) {
	for ch := range h.subs {
		select {
		case ch <- p:
		default:
		}
	}
}

func (h *updateHub) snapshot() (updateProgress, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.running
}

func (h *updateHub) subscribe() (<-chan updateProgress, func()) {
	ch := make(chan updateProgress, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// updateCheck queries the latest stable release on GitHub and compares it with the current version.
//
// The frontend also hits api.github.com directly (GitHub's CORS is *), but **this API is authoritative**:
// the download is done by the backend, and an update is only possible if the backend can reach GitHub. The browser connecting while
// the server cannot is common (the server is on an internal network, or the proxy is configured only in the browser), and then an update is bound to fail,
// so it is better to report the error honestly at this check step.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	boot := bootUpdateState()
	out := map[string]any{
		"current":     current,
		"mode":        mode,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"has_backup":  selfupdate.HasBackup(),
		"repo":        selfupdate.Repo,
		"boot_notice": boot.Detail,
		"rolled_back": boot.RolledBack,
	}

	// the top-bar hint uses the cache (default); when the user clicks "check for updates" it passes force=1 to force a refresh from the source.
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	asset := selfupdate.AssetName(latest, runtime.GOOS, runtime.GOARCH)
	out["asset"] = asset
	if a, ok := rel.FindAsset(asset); ok {
		out["asset_available"] = true
		out["size"] = a.Size
	} else {
		out["asset_available"] = false
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// A development build (dev / a git-describe suffix) has no comparable version number. Allowing it would only
		// overwrite the locally debugged binary with a stable release, so updating is simply disallowed.
		out["reason"] = fmt.Sprintf(updateErrNotReleaseFmt, current)
	}
	writeJSON(w, 200, out)
}

// updateApply downloads and stages the new version, then exits the process and leaves the restart to the supervisor script.
//
// Returns 202 immediately, with the real work running on a background goroutine: downloading the full package may take minutes,
// and hanging it on the request would be cut off by a reverse-proxy timeout. Progress goes through /api/update/stream.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion

	// use the cache: ensure the installed version is the one the user saw and confirmed in the UI.
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, false)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	cmp, comparable := selfupdate.CompareVersions(current, rel.TagName)
	if !comparable {
		writeErr(w, 400, fmt.Sprintf(updateErrNotReleaseFmt, current))
		return
	}
	if cmp >= 0 {
		writeErr(w, 400, fmt.Sprintf(updateErrAlreadyLatestFmt, current))
		return
	}
	if !updHub.begin(rel.TagName) {
		writeErr(w, 409, updateErrInProgress)
		return
	}

	go func() {
		// Deliberately uses s.ctx rather than the request's ctx: the request ends as soon as the HTTP response returns,
		// and a download hung on it would be cancelled immediately.
		err := selfupdate.Stage(s.ctx, client, rel, current, func(ph selfupdate.Phase, pct int, msg string) {
			updHub.publish(ph, pct, msg)
		})
		updHub.finish(err)
		if err != nil {
			log.Printf("[update] update failed: %v", err)
			return
		}
		log.Printf("[update] %s → %s staged, exiting to complete the swap", current, rel.TagName)
		// leave a little time to push the last progress to the frontend before triggering the exit.
		time.Sleep(1500 * time.Millisecond)
		requestRestart()
	}()

	writeJSON(w, 202, map[string]any{"ok": true, "target": rel.TagName})
}

// updateRollback actively reverts to the previous version (artex.old backed up before the swap).
func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if _, running := updHub.snapshot(); running {
		writeErr(w, 409, updateErrRollbackInProgress)
		return
	}
	if err := selfupdate.Rollback(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[update] manually rolled back to the previous version, exiting to complete the switch")
	writeJSON(w, 202, map[string]any{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		requestRestart()
	}()
}

// updateStream pushes update progress via SSE.
func (s *Server) updateStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := updHub.subscribe()
	defer unsub()

	send := func(p updateProgress) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	// send the current state first, so a page refresh immediately shows an in-progress upgrade.
	cur, _ := updHub.snapshot()
	send(cur)

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			send(p)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
