// Package execsvc holds the db-free execution services the sandboxed Agent hosts
// beyond norma's built-in tools: a script runner, a raw HTTP client, a DNS resolver,
// and an HTTP prober. They back ARTEX features whose engine stays on the control plane
// (custom script/http tools, the enrich asset-probe pool) but whose actual network /
// process I/O must happen in the sandbox.
//
// These tools are addressed by reserved names ("__artex_*") and are NOT shown to the
// model — the control plane invokes them programmatically over the remoteexec channel.
// The package imports no artex control-plane code (no db, no server), so it links into
// the Agent binary without pulling in the LLM or the datastore.
package execsvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Reserved tool names. Kept in one place so the control-plane callers and the Agent
// host agree.
const (
	ToolScript    = "__artex_script"
	ToolHTTP      = "__artex_http"
	ToolDNS       = "__artex_dns"
	ToolHTTPProbe = "__artex_httpprobe"
)

func allow(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}

// ---- Script executor (custom "script" tools) ----

// ScriptInput is the wire contract for __artex_script.
type ScriptInput struct {
	Interp    string         `json:"interp"`     // preferred interpreter; resolved against PATH, falls back to python3/python
	Code      string         `json:"code"`       // program source
	Params    map[string]any `json:"params"`     // passed as JSON on stdin + scalar values as TOOL_<KEY> env
	Key       string         `json:"key"`        // tool key, used only to name the temp file
	TimeoutMs int            `json:"timeout_ms"` // 0 → 120s
}

// ScriptTool runs a short program in the sandbox. Mirrors the monolith's execPython.
func ScriptTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        ToolScript,
		Description: "internal: run a user script in the sandbox",
		Schema:      objSchema(),
		Permissions: allow,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var sp ScriptInput
			_ = json.Unmarshal(in, &sp)
			if strings.TrimSpace(sp.Code) == "" {
				return actool.Errorf("script code 为空"), nil
			}
			interp := resolveInterp(sp.Interp)
			if interp == "" {
				return actool.Errorf("샌드박스에 python 인터프리터가 없습니다(python3/python)"), nil
			}
			workDir := workingDir(tc)
			body, err := runScript(ctx, interp, sp.Key, sp.Code, sp.Params, workDir, envOf(tc), timeoutOr(sp.TimeoutMs, 120000))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(actool.Capture(tc, body)), nil
		},
	})
}

func resolveInterp(pref string) string {
	cands := []string{}
	if pref != "" {
		cands = append(cands, pref)
	}
	cands = append(cands, "python3", "python")
	for _, c := range cands {
		if filepath.IsAbs(c) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// scriptWaitDelay caps how long CombinedOutput waits for the stdout/stderr pipe to close
// after the script process exits or is cancelled, so a child that inherited the pipe and
// keeps it open cannot hang the call indefinitely (the process group is killed regardless).
const scriptWaitDelay = 2 * time.Second

func runScript(ctx context.Context, interp, key, code string, params map[string]any, workDir string, sessionEnv []string, timeout time.Duration) (string, error) {
	toolsDir := filepath.Join(workDir, ".tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return "", err
	}
	if key == "" {
		key = "script"
	}
	f, err := os.CreateTemp(toolsDir, key+"-*.py")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(code); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(runCtx, interp, tmp)
	c.Dir = workDir
	c.Env = append(os.Environ(), sessionEnv...)
	for k, v := range params {
		if sv, ok := scalarStr(v); ok {
			c.Env = append(c.Env, "TOOL_"+strings.ToUpper(k)+"="+sv)
		}
	}
	pj, _ := json.Marshal(params)
	c.Stdin = bytes.NewReader(pj)
	// Run the script in its own process group so the WHOLE tree — including anything it
	// detaches with subprocess.Popen / `&` / nohup — can be killed as a unit. Two things
	// matter for isolation (보안 리뷰: 출력 파이프 상속 시 그룹 정리·타임아웃 지연):
	//
	//   - On timeout/cancel, kill the GROUP (the default CommandContext cancel kills only
	//     the leader, leaving a detached child running).
	//   - Do NOT let output collection wait on the stdout/stderr pipe being closed by every
	//     holder: a child that inherited the pipe would keep the call blocked long past the
	//     timeout (and keep writing/egressing). So the child's stdout/stderr is a real
	//     os.Pipe file — Wait then returns when the MAIN process exits, not when the orphan
	//     closes the fd — and we kill the group the instant Wait returns, reaping the orphan
	//     before it can act, then drain whatever output was produced (bounded).
	setProcGroup(c)
	c.Cancel = func() error { killProcGroup(c); return nil }

	pr, pw, err := os.Pipe()
	if err != nil {
		return "", err
	}
	c.Stdout, c.Stderr = pw, pw
	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, pr); close(copyDone) }()

	startErr := c.Start()
	_ = pw.Close() // the parent keeps no write end; only the child(ren) hold it now
	if startErr != nil {
		_ = pr.Close()
		return "", startErr
	}
	waitErr := c.Wait() // returns at MAIN process exit (stdout is a real file → no I/O wait)
	killProcGroup(c)    // reap any detached child immediately, before it can write/egress
	_ = pr.Close()      // unblock the copy if a (now-killed) child still held the write fd
	select {
	case <-copyDone:
	case <-time.After(scriptWaitDelay): // backstop; the group is already dead
	}

	body := buf.String()
	if runCtx.Err() == context.DeadlineExceeded {
		body += "\n... [超时终止] ..."
	} else if waitErr != nil {
		body += "\n[exit: " + waitErr.Error() + "]"
	}
	return body, nil
}

// ---- HTTP client (custom "http" tools) ----

// HTTPInput is the wire contract for __artex_http.
type HTTPInput struct {
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	TimeoutMs         int               `json:"timeout_ms"`
	Proxy             string            `json:"proxy"`               // explicit proxy URL; overrides UseRecordingProxy
	UseRecordingProxy bool              `json:"use_recording_proxy"` // route through the Agent's local recording proxy
}

// HTTPResult is returned as JSON text.
type HTTPResult struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// HTTPTool performs a raw HTTP request from the sandbox. egressProxy/egressCA are the
// Agent's local recording proxy, applied when UseRecordingProxy is set and no explicit
// proxy is given.
func HTTPTool(egressProxy, egressCA string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        ToolHTTP,
		Description: "internal: perform an HTTP request from the sandbox",
		Schema:      objSchema(),
		Permissions: allow,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var sp HTTPInput
			_ = json.Unmarshal(in, &sp)
			method := strings.ToUpper(strings.TrimSpace(sp.Method))
			if method == "" {
				method = "GET"
			}
			if strings.TrimSpace(sp.URL) == "" {
				return actool.Errorf("http url 为空"), nil
			}
			var bodyReader io.Reader
			if sp.Body != "" {
				bodyReader = strings.NewReader(sp.Body)
			}
			runCtx, cancel := context.WithTimeout(ctx, timeoutOr(sp.TimeoutMs, 30000))
			defer cancel()
			req, err := http.NewRequestWithContext(runCtx, method, sp.URL, bodyReader)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			for k, v := range sp.Headers {
				req.Header.Set(k, v)
			}
			client := &http.Client{Timeout: timeoutOr(sp.TimeoutMs, 30000)}
			proxyStr := strings.TrimSpace(sp.Proxy)
			caFile := ""
			if proxyStr == "" && sp.UseRecordingProxy && egressProxy != "" {
				proxyStr = egressProxy
				caFile = egressCA
			}
			if tr := proxyTransport(proxyStr, caFile); tr != nil {
				client.Transport = tr
			}
			resp, err := client.Do(req)
			if err != nil {
				return actool.Errorf("请求失败: " + err.Error()), nil
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			b, _ := json.Marshal(HTTPResult{Status: resp.StatusCode, Body: string(respBody)})
			return actool.Text(actool.Capture(tc, string(b))), nil
		},
	})
}

// ---- DNS resolver (enrich) ----

// DNSResult is returned as JSON text.
type DNSResult struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
}

// DNSTool resolves a host's A/AAAA/CNAME records from the sandbox.
func DNSTool() actool.CoreTool {
	var resolver *dnsx.DNSX
	if r, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    2,
		QuestionTypes: dnsx.DefaultOptions.QuestionTypes,
	}); err == nil {
		resolver = r
	}
	return actool.Build(actool.Spec{
		Name:        ToolDNS,
		Description: "internal: resolve DNS records from the sandbox",
		Schema:      objSchema(),
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var sp struct {
				Host string `json:"host"`
			}
			_ = json.Unmarshal(in, &sp)
			if resolver == nil || strings.TrimSpace(sp.Host) == "" {
				b, _ := json.Marshal(DNSResult{})
				return actool.Text(string(b)), nil
			}
			data, err := resolver.QueryMultiple(sp.Host)
			res := DNSResult{}
			if err == nil && data != nil {
				res.A = data.A
				res.AAAA = data.AAAA
				res.CNAME = data.CNAME
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		},
	})
}

// ---- HTTP prober (enrich) ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ProbeResult is returned as JSON text.
type ProbeResult struct {
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
	Title         string `json:"title"`
}

// HTTPProbeTool fetches a URL from the sandbox and reports status/length/title, routed
// through the Agent's local recording proxy when one is configured.
func HTTPProbeTool(egressProxy, egressCA string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        ToolHTTPProbe,
		Description: "internal: probe an HTTP service from the sandbox",
		Schema:      objSchema(),
		Permissions: allow,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var sp struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(in, &sp)
			res := ProbeResult{}
			if strings.TrimSpace(sp.URL) == "" {
				b, _ := json.Marshal(res)
				return actool.Text(string(b)), nil
			}
			runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(runCtx, "GET", sp.URL, nil)
			if err != nil {
				b, _ := json.Marshal(res)
				return actool.Text(string(b)), nil
			}
			req.Header.Set("User-Agent", "artex-enrich/1.0")
			client := &http.Client{Timeout: 15 * time.Second}
			if tr := proxyTransport(egressProxy, egressCA); tr != nil {
				client.Transport = tr
			}
			resp, err := client.Do(req)
			if err != nil {
				b, _ := json.Marshal(res)
				return actool.Text(string(b)), nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			res.Status = resp.StatusCode
			res.ContentLength = int64(len(body))
			res.Title = extractTitle(body)
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		},
	})
}

// Tools returns every execsvc tool, configured with the Agent's local egress proxy, for
// the Agent to host alongside norma's built-ins.
func Tools(egressProxy, egressCA string) []actool.CoreTool {
	return []actool.CoreTool{
		ScriptTool(),
		HTTPTool(egressProxy, egressCA),
		DNSTool(),
		HTTPProbeTool(egressProxy, egressCA),
	}
}

// ---- helpers ----

func objSchema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

func proxyTransport(proxyStr, caFile string) *http.Transport {
	proxyStr = strings.TrimSpace(proxyStr)
	if proxyStr == "" {
		return nil
	}
	pu, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	if caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	return tr
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func workingDir(tc *actool.ToolContext) string {
	if tc != nil && tc.WorkingDir != "" {
		return tc.WorkingDir
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func envOf(tc *actool.ToolContext) []string {
	if tc != nil {
		return tc.Env
	}
	return nil
}

func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case float64:
		// integers come through as float64 from encoding/json
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), true
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

func timeoutOr(ms int, def int) time.Duration {
	if ms <= 0 {
		ms = def
	}
	return time.Duration(ms) * time.Millisecond
}
