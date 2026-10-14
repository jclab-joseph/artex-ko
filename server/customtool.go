package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/execsvc"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// This file implements the custom-tool executor (docs/custom-tool-design.md). tools rows with system=false are
// dispatched by kind: command (render the command → reuse Bash's underlying run), script (Python only; writes a temp file,
// stdin=the args JSON + env TOOL_*, using the configured interpreter), http (a native request + optional proxy). Like the
// traffic/orchestration tools, these need no seeding (they are already in the tools table); they are injected via hostTools and filtered by binding.

// ---------- custom-tool CRUD ----------

type customToolReq struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"` // command | script | http
	Exec        json.RawMessage `json:"exec"`
	Deferred    bool            `json:"deferred"`
}

var reToolKey = reAgentKey // same rule as the agent key: starts with a lowercase letter + lowercase letters/digits/underscores

// 사용자 지정 도구 CRUD·시험 실행 엔드포인트가 writeErr 로 사용자에게 돌려주는 검증
// 오류 응답을 한국어로 고정한다. 에이전트가 읽는 도구 실행 결과(actool.Errorf)와 도구
// 스키마 description 은 두뇌 경계라 중국어 원문을 보존한다(BRIEF 성능 보존 방침).
const (
	errCustomToolKeyFormat          = "key는 소문자로 시작하고 소문자·숫자·밑줄만 사용할 수 있습니다"
	errCustomToolKindInvalid        = "kind 값은 command, script, http, shell 중 하나여야 합니다"
	errCustomToolHTTPSchemaRequired = "http 도구에는 매개변수 JSON Schema를 반드시 지정해야 합니다(비워 둘 수 없습니다)"
	errCustomToolKeyExists          = "이미 존재하는 key입니다(내장 또는 사용자 지정 도구)"
	errCustomToolEditCustomOnly     = "사용자 지정 도구만 편집할 수 있습니다"
	errCustomToolBadBody            = "요청 본문이 올바르지 않습니다"
	errCustomToolShellNoExec        = "shell 유형 도구는 bash 환경 선언이므로 실행할 내용이 없습니다"
	errCustomToolUnknownKindPrefix  = "알 수 없는 도구 유형입니다: "
)

func (s *Server) pgCreateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if !reToolKey.MatchString(req.Key) {
		writeErr(w, 400, errCustomToolKeyFormat)
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, errCustomToolKindInvalid)
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, errCustomToolHTTPSchemaRequired)
		return
	}
	if exist, _ := pg.GetTool(req.Key); exist != nil {
		writeErr(w, 409, errCustomToolKeyExists)
		return
	}
	if err := pg.CreateCustomTool(&db.Tool{
		Key: req.Key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"key": req.Key})
}

func (s *Server) pgUpdateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	existing, err := pg.GetTool(key)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if existing == nil || existing.System {
		writeErr(w, 400, errCustomToolEditCustomOnly)
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, errCustomToolKindInvalid)
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, errCustomToolHTTPSchemaRequired)
		return
	}
	if err := pg.UpdateCustomTool(&db.Tool{
		Key: key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) pgDeleteCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	if err := pg.DeleteCustomTool(key); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": key})
}

// testToolReq is a dry-run request from the editor: run the given (possibly unsaved)
// exec spec with sample params, without persisting the tool. Same executor path as a
// real tool call — it runs arbitrary command/script/http on the server, which the
// custom-tool feature already allows, so no new capability is granted.
type testToolReq struct {
	Kind   string          `json:"kind"` // command | script | http
	Exec   json.RawMessage `json:"exec"`
	Params map[string]any  `json:"params"`
}

// pgTestCustomTool executes an exec spec once and returns its raw output + error
// flag, so the editor can debug a tool before saving it. Per-kind timeouts still
// apply from the exec spec (with defaults); the outer ceiling is a hard backstop.
func (s *Server) pgTestCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req testToolReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, errCustomToolBadBody)
		return
	}
	params := req.Params
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// Test runs obey the same isolation policy as real calls: in split mode command/
	// script/http route to the sandbox Agent (or fail closed when none is selected/
	// connected), never on the control plane (보안 리뷰 F4). Taskless → nil task.
	ctx = s.bindExecCtx(ctx, nil)
	tc := &actool.ToolContext{WorkingDir: s.m.dir} // run in the project dir, like a real call
	var res actool.Result
	switch req.Kind {
	case "command":
		res, _ = s.runCommandTool(ctx, req.Exec, params, tc)
	case "script":
		res, _ = s.runScriptTool(ctx, "test", req.Exec, params, tc)
	case "http":
		res, _ = s.runHTTPTool(ctx, req.Exec, params, tc)
	case "shell":
		writeErr(w, 400, errCustomToolShellNoExec)
		return
	default:
		writeErr(w, 400, errCustomToolUnknownKindPrefix+req.Kind)
		return
	}
	writeJSON(w, 200, map[string]any{"output": res.Flatten(), "is_error": res.IsError})
}

// ---------- Python interpreter (detect + store + override) ----------

const settingPythonInterp = "python_interpreter"

// detectPython finds a python interpreter absolute path (python3 preferred).
func detectPython() string {
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// pythonInterpreter resolves the interpreter: user-set > stored auto-detect > live
// detect. "" only when truly none found.
func (s *Server) pythonInterpreter() string {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return detectPython()
}

// seedPythonInterpreter stores the auto-detected interpreter on startup if unset
// (never clobbers a user-set value).
func (s *Server) seedPythonInterpreter() {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return
	}
	if p := detectPython(); p != "" {
		_ = s.m.pg.SetSetting(settingPythonInterp, p)
		log.Printf(logT("[custom-tool] python 인터프리터 자동 감지: %s"), p)
	}
}

// ---------- exec spec ----------

type commandExec struct {
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
}
type scriptExec struct {
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
}
type httpExec struct {
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	TimeoutMs         int               `json:"timeout_ms"`
	Proxy             string            `json:"proxy"`
	UseRecordingProxy bool              `json:"use_recording_proxy"`
}

func timeoutOr(ms, def int) time.Duration {
	if ms <= 0 {
		return time.Duration(def) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// ---------- generic tool construction ----------

// customTools builds CoreTools for every user-defined (system=false) tool row.
// shell-kind tools are environment hints only — they surface in the Bash tool
// description via ToolResolve and do NOT create callable tool entries here.
func (s *Server) customTools() ([]actool.CoreTool, error) {
	rows, err := s.m.pg.ListCustomTools()
	if err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(rows))
	for _, t := range rows {
		if t.Kind == "shell" {
			continue // shell hints are handled by ToolResolve → Bash description
		}
		out = append(out, s.buildCustomTool(t))
	}
	return out, nil
}

// buildCustomTool turns one custom-tool row into a CoreTool. Empty schema → a thin
// {args:string} (thin-shell tool), so command/http templates can use {args}.
func (s *Server) buildCustomTool(t *db.Tool) actool.CoreTool {
	schema := ensureSchema(t.Schema)
	key, kind, execRaw := t.Key, t.Kind, t.Exec
	run := func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var params map[string]any
		if len(in) > 0 {
			_ = json.Unmarshal(in, &params)
		}
		if params == nil {
			params = map[string]any{}
		}
		switch kind {
		case "command":
			return s.runCommandTool(ctx, execRaw, params, tc)
		case "script":
			return s.runScriptTool(ctx, key, execRaw, params, tc)
		case "http":
			return s.runHTTPTool(ctx, execRaw, params, tc)
		default:
			return actool.Errorf("unknown custom tool type: " + kind), nil
		}
	}
	return actool.Build(actool.Spec{
		Name: key, Description: t.Description, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: run,
	})
}

// hasSchemaProps reports whether raw is a JSON-Schema object with ≥1 property.
// http tools require an explicit schema (the auto {args} shell can't name the
// {param} placeholders in URL/headers/body), so an empty schema is rejected.
func hasSchemaProps(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	props, _ := m["properties"].(map[string]any)
	return len(props) > 0
}

// ensureSchema returns the tool's schema, or a thin {args:string} when none given.
func ensureSchema(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	props, _ := m["properties"].(map[string]any)
	if len(props) > 0 {
		return m
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"args": map[string]any{"type": "string", "description": "command/arguments (free text)"},
		},
	}
}

// ---------- command: render the command → reuse Bash's underlying run ----------

func (s *Server) runCommandTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec commandExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Command) == "" {
		return actool.Errorf("command is empty"), nil
	}
	cmd := renderTemplate(spec.Command, params, shellQuote)
	// Reuse the same underlying run Bash uses (via Bash CoreTool.Call): automatically inherits the security floor/timeout/
	// proxy env/output overflow. This tool is a peer of Bash sharing the same underlying run, not routed through the Bash tool for the model to call.
	bashIn, _ := json.Marshal(map[string]any{"command": cmd})
	if spec.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 120000))
		defer cancel()
	}
	// Execution-plane split: the underlying Bash of command-type custom tools must also run in the sandbox Agent (an arbitrary shell command is
	// the most dangerous surface). The backend routes Bash.Call to the Agent; when not bound (single process) LocalBackend
	// returns as-is, behavior unchanged.
	bash := remoteexec.BackendFrom(ctx).Wrap(actool.NewBash())
	return bash.Call(ctx, bashIn, tc)
}

// ---------- script (Python only): temp file + stdin JSON + env ----------

func (s *Server) runScriptTool(ctx context.Context, key string, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec scriptExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Code) == "" {
		return actool.Errorf("script code is empty"), nil
	}
	// 실행 플레인 분리: split 모드(IsRemote)면 스크립트 실행을 execsvc 로 넘긴다. Agent 가 이
	// 서비스를 announce 했으면 원격 실행(인터프리터 선호값만 전달; 실제 실행·탐색은 Agent),
	// announce 안 했거나 미연결(fail-closed)이면 Wrap 이 차단한다 — 제어 플레인 로컬 실행
	// 로 절대 폴백하지 않는다(보안 리뷰 F3). off/단일 프로세스(IsRemote=false)일 때만 아래
	// 로컬 경로.
	if be := remoteexec.BackendFrom(ctx); be.IsRemote() {
		in, _ := json.Marshal(execsvc.ScriptInput{
			Interp: s.pythonInterpreter(), Code: spec.Code, Params: params, Key: key, TimeoutMs: spec.TimeoutMs,
		})
		return be.Wrap(execsvc.ScriptTool()).Call(ctx, in, tc)
	}
	interp := s.pythonInterpreter()
	if interp == "" {
		return actool.Errorf("no python interpreter configured or detected (set it in the system configuration)"), nil
	}
	workDir := s.m.dir
	var sessionEnv []string
	if tc != nil {
		if tc.WorkingDir != "" {
			workDir = tc.WorkingDir
		}
		sessionEnv = tc.Env
	}
	body, err := execPython(ctx, interp, key, spec.Code, params, workDir, sessionEnv, timeoutOr(spec.TimeoutMs, 120000))
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(actool.Capture(tc, body)), nil
}

// execPython writes the code to a temp .py under workDir/.tools, runs it via interp
// with the params JSON on stdin + scalar params mirrored to TOOL_<NAME> env, and
// returns combined stdout+stderr (with a timeout/exit note). Standalone + testable.
func execPython(ctx context.Context, interp, key, code string, params map[string]any, workDir string, sessionEnv []string, timeout time.Duration) (string, error) {
	toolsDir := filepath.Join(workDir, ".tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return "", err
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
	c.Env = append(os.Environ(), sessionEnv...) // session proxy env
	for k, v := range params {                  // scalar params mirrored into TOOL_<NAME>
		if sv, ok := scalarStr(v); ok {
			c.Env = append(c.Env, "TOOL_"+strings.ToUpper(k)+"="+sv)
		}
	}
	pj, _ := json.Marshal(params)
	c.Stdin = bytes.NewReader(pj) // the args JSON goes through stdin
	out, err := c.CombinedOutput()
	body := string(out)
	if runCtx.Err() == context.DeadlineExceeded {
		body += "\n... [terminated on timeout] ..."
	} else if err != nil {
		body += "\n[exit: " + err.Error() + "]"
	}
	return body, nil
}

// ---------- http: native request + proxy ----------

func (s *Server) runHTTPTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec httpExec
	_ = json.Unmarshal(execRaw, &spec)
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	rawURL := renderTemplate(spec.URL, params, identity)
	if strings.TrimSpace(rawURL) == "" {
		return actool.Errorf("http url is empty"), nil
	}
	// 실행 플레인 분리: split 모드(IsRemote)면 HTTP 요청을 execsvc 로 넘긴다 — announce 됐으면
	// Agent 에서 전송, 아니면 Wrap 이 차단(로컬 폴백 없음, 보안 리뷰 F3). use_recording_proxy
	// 는 Agent 가 자신의 로컬 기록 프록시로 해석한다(제어 플레인 프록시 주소를 넘기지 않음).
	if be := remoteexec.BackendFrom(ctx); be.IsRemote() {
		hdrs := map[string]string{}
		for k, v := range spec.Headers {
			hdrs[k] = renderTemplate(v, params, identity)
		}
		body := ""
		if spec.Body != "" {
			body = renderTemplate(spec.Body, params, identity)
		}
		in, _ := json.Marshal(execsvc.HTTPInput{
			Method: spec.Method, URL: rawURL, Headers: hdrs, Body: body,
			TimeoutMs: spec.TimeoutMs, Proxy: strings.TrimSpace(spec.Proxy), UseRecordingProxy: spec.UseRecordingProxy,
		})
		return be.Wrap(execsvc.HTTPTool("", "")).Call(ctx, in, tc)
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(renderTemplate(spec.Body, params, identity))
	}
	runCtx, cancel := context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 30000))
	defer cancel()
	req, err := http.NewRequestWithContext(runCtx, method, rawURL, bodyReader)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, renderTemplate(v, params, identity))
	}
	client := &http.Client{Timeout: timeoutOr(spec.TimeoutMs, 30000)}
	if tr := s.httpProxyTransport(spec); tr != nil {
		client.Transport = tr
	}
	resp, err := client.Do(req)
	if err != nil {
		return actool.Errorf("request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{"status": resp.StatusCode, "body": string(respBody)}
	b, _ := json.Marshal(out)
	return actool.Text(actool.Capture(tc, string(b))), nil
}

// httpProxyTransport builds a Transport for the http tool's proxy config, or nil
// (direct). use_recording_proxy routes through the recording proxy + trusts its CA.
func (s *Server) httpProxyTransport(spec httpExec) *http.Transport {
	proxyStr := strings.TrimSpace(spec.Proxy)
	var caFile string
	if spec.UseRecordingProxy {
		if addr := s.m.ProxyAddr(); addr != "" {
			proxyStr = "http://" + addr
			caFile = s.m.ProxyCACert()
		}
	}
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

// ---------- helpers ----------

func identity(s string) string { return s }

// shellQuote single-quotes a value for safe shell interpolation.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// renderTemplate replaces {name} placeholders with each param's rendered value.
func renderTemplate(tmpl string, params map[string]any, quote func(string) string) string {
	out := tmpl
	for k, v := range params {
		out = strings.ReplaceAll(out, "{"+k+"}", quote(valToStr(v)))
	}
	return out
}

// valToStr renders a param value: scalars as-is, arrays/objects as compact JSON.
func valToStr(v any) string {
	if sv, ok := scalarStr(v); ok {
		return sv
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// scalarStr returns (string, true) for scalar values, ("", false) for arrays/objects.
func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return fmt.Sprintf("%t", x), true
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x)), true
		}
		return fmt.Sprintf("%g", x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}
