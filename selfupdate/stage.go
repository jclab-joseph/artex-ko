package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

// sumsAsset is the checksum manifest produced by release.yml, covering every zip in the Release.
const sumsAsset = "SHA256SUMS"

// maxBinarySize caps the size of the extracted binary, so a malformed zip cannot fill the disk.
const maxBinarySize = 512 << 20 // 512 MiB

// Phase is a stage of the update process, used directly as the phase field in SSE events.
type Phase string

const (
	PhaseIdle     Phase = "idle"
	PhaseDownload Phase = "downloading"
	PhaseVerify   Phase = "verifying"
	PhaseExtract  Phase = "extracting"
	PhaseStaged   Phase = "staged"
	PhaseFailed   Phase = "failed"
)

// Progress is supplied by the caller to push progress to the frontend. pct is only
// meaningful during the download phase (0-100); other phases pass -1.
type Progress func(ph Phase, pct int, msg string)

// Stage downloads the current platform's release package for the given Release,
// verifies it, and stages the new binary as artex.new.
//
// It uses the full zip instead of a bare binary, for two reasons: the existing Release's
// SHA256SUMS already covers only the zip, so using the zip needs no CI change and stays
// compatible with already-published historical versions; and the zip also carries skills/,
// leaving room to sync built-in skills later. The only cost is the extra few hundred KB for skills.
//
// A return means staging is complete; the caller then shuts down gracefully and exits with ExitRestart.
func Stage(ctx context.Context, c *http.Client, rel *Release, currentVersion string, prog Progress) error {
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if err := checkWritable(p.Dir); err != nil {
		return err
	}

	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return fmt.Errorf("이 버전은 %s/%s 용 릴리스 패키지를 제공하지 않습니다(%s 누락)", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "체크섬 목록을 가져오는 중…")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return err
	}
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s 에 %s 항목이 없어 검증되지 않은 바이너리 설치를 거부합니다", sumsAsset, name)
	}

	// All temp files live in the target directory, so the final rename is an atomic
	// operation within the same filesystem (a cross-device rename fails, and /tmp is often a separate mount point).
	zipPath := p.New + ".zip.part"
	binPath := p.New + ".part"
	defer func() {
		_ = os.Remove(zipPath)
		_ = os.Remove(binPath)
	}()

	prog(PhaseDownload, 0, fmt.Sprintf("%s 내려받는 중(%s)…", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		return err
	}

	prog(PhaseVerify, -1, "SHA256 검증 중…")
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA256 이 일치하지 않습니다: 기대값 %s, 실제값 %s(다운로드가 손상됐거나 변조됨)", short(want), short(got))
	}

	prog(PhaseExtract, -1, "압축을 풀고 스모크 테스트 중…")
	if err := extractBinary(zipPath, binPath); err != nil {
		return err
	}
	if err := smokeTest(binPath); err != nil {
		return fmt.Errorf("새 버전이 현재 시스템에서 실행되지 않습니다: %w", err)
	}

	// Store the staged file's own sha256 separately: it gets verified again before the
	// next startup swaps it in, guarding against the file being modified or corrupted between staging and restart.
	binSum, err := fileSHA256(binPath)
	if err != nil {
		return fmt.Errorf("새 바이너리 체크섬 계산 실패: %w", err)
	}
	if err := os.WriteFile(p.Sum, []byte(binSum), 0o644); err != nil {
		return fmt.Errorf("체크섬 기록 실패: %w", err)
	}
	if err := os.Rename(binPath, p.New); err != nil {
		_ = os.Remove(p.Sum)
		return fmt.Errorf("새 버전 준비 실패: %w", err)
	}

	if err := writeMarker(p.Marker, marker{
		From:     currentVersion,
		To:       strings.TrimPrefix(rel.TagName, "v"),
		StagedAt: time.Now().Unix(),
	}); err != nil {
		// The marker only affects auto-rollback capability; the staged file itself is already in place, so this does not abort the update.
		prog(PhaseStaged, -1, "경고: 업데이트 표시 파일 기록에 실패해 이번 업데이트는 자동 롤백 보호를 받지 못합니다")
	}

	prog(PhaseStaged, 100, "새 버전이 준비되었습니다. 재시작 중…")
	return nil
}

// fetchSums downloads and parses SHA256SUMS, returning filename → hex digest.
func fetchSums(ctx context.Context, c *http.Client, rel *Release) (map[string]string, error) {
	asset, ok := rel.FindAsset(sumsAsset)
	if !ok {
		return nil, fmt.Errorf("이 릴리스에 %s 항목이 없어 무결성을 검증할 수 없으므로 업데이트를 거부합니다", sumsAsset)
	}
	body, err := get(ctx, c, asset.URL)
	if err != nil {
		return nil, fmt.Errorf("%s 내려받기 실패: %w", sumsAsset, err)
	}
	defer body.Close()

	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%s 읽기 실패: %w", sumsAsset, err)
	}
	out := parseSums(string(raw))
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 내용이 비어 있거나 형식을 인식할 수 없습니다", sumsAsset)
	}
	return out, nil
}

// parseSums parses a sha256sum-style manifest, returning filename → hex digest.
//
// A line is only accepted if its first field is 64 hex characters. Checking for
// "exactly two fields" is not enough — any line with two words of description would
// be treated as a valid entry, injecting garbage into the digest table and letting a
// real asset match the wrong digest.
func parseSums(raw string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(raw) {
		// The format is "<sha256>  <filename>" (sha256sum uses two spaces; shasum's binary
		// mode prefixes the filename with *).
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || !isHexSHA256(fields[0]) {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == "" {
			continue
		}
		out[name] = strings.ToLower(fields[0])
	}
	return out
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// download writes the asset to dst while computing its SHA256 and reporting progress against Content-Length.
func download(ctx context.Context, c *http.Client, a Asset, dst string, prog Progress) (string, error) {
	body, err := get(ctx, c, a.URL)
	if err != nil {
		return "", fmt.Errorf("%s 내려받기 실패: %w", a.Name, err)
	}
	defer body.Close()

	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("임시 파일 생성 실패: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	pw := &progressWriter{total: a.Size, prog: prog, name: a.Name, last: time.Now()}
	if _, err := io.Copy(io.MultiWriter(f, h, pw), body); err != nil {
		return "", fmt.Errorf("다운로드가 중단되었습니다: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("디스크 기록 실패: %w", err)
	}
	if a.Size > 0 && pw.written != a.Size {
		return "", fmt.Errorf("다운로드가 완전하지 않습니다: 기대 %d바이트, 실제 %d바이트", a.Size, pw.written)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// get issues an allowlist-constrained GET and returns the response body.
func get(ctx context.Context, c *http.Client, rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artex-selfupdate")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractBinary pulls the artex executable out of the release package.
//
// The in-package layout is artex-<version>-<os>-<arch>/artex, but this matches by
// **base name** rather than building the full path: the version appears once in the
// package name, and a single wrong character would fail the whole update, so matching
// by base name is more robust.
func extractBinary(zipPath, dst string) error {
	want := "artex"
	if runtime.GOOS == "windows" {
		want = "artex.exe"
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("릴리스 패키지 열기 실패: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), want) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("%s 읽기 실패: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("새 바이너리 쓰기 실패: %w", err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("%s 압축 해제 실패: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("릴리스 패키지 안의 실행 파일이 %s 보다 커서 압축 해제를 거부합니다", humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("릴리스 패키지 안의 %s 파일이 비어 있습니다", want)
		}
		return f.Sync()
	}
	return fmt.Errorf("릴리스 패키지에서 %s 파일을 찾지 못했습니다", want)
}

// checkWritable confirms the directory is writable up front. Without this, running as
// non-root, or with the binary placed in a system directory, would only fail at the
// swap moment, after tens of MB have already been downloaded.
func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".artex-update-probe-*")
	if err != nil {
		return fmt.Errorf("프로그램 디렉터리 %s 에 쓸 수 없어 자동 업데이트를 할 수 없습니다(권한을 확인하거나 수동 업데이트를 사용하세요): %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// progressWriter counts bytes written and rate-limits reporting, so it does not push an SSE event for every 32KiB chunk.
type progressWriter struct {
	total   int64
	written int64
	name    string
	prog    Progress
	last    time.Time
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.written += int64(len(b))
	if time.Since(w.last) < 300*time.Millisecond {
		return len(b), nil
	}
	w.last = time.Now()
	pct := -1
	if w.total > 0 {
		pct = int(w.written * 100 / w.total)
	}
	w.prog(PhaseDownload, pct, fmt.Sprintf("내려받는 중 %s / %s", humanSize(w.written), humanSize(w.total)))
	return len(b), nil
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12] + "…"
	}
	return sum
}
