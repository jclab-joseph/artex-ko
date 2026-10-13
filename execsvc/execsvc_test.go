package execsvc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func callJSON(t *testing.T, tool actool.CoreTool, input any) (actool.Result, string) {
	t.Helper()
	raw, _ := json.Marshal(input)
	res, err := tool.Call(context.Background(), raw, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("%s call errored: %v", tool.Name(), err)
	}
	return res, res.Flatten()
}

func TestHTTPTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Probe") != "yes" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello-from-test"))
	}))
	defer srv.Close()

	_, out := callJSON(t, HTTPTool("", ""), HTTPInput{
		Method:  "GET",
		URL:     srv.URL,
		Headers: map[string]string{"X-Probe": "yes"},
	})
	var hr HTTPResult
	if err := json.Unmarshal([]byte(out), &hr); err != nil {
		t.Fatalf("result not JSON: %q", out)
	}
	if hr.Status != 201 || !strings.Contains(hr.Body, "hello-from-test") {
		t.Fatalf("unexpected http result: %+v", hr)
	}
}

func TestDNSToolNilSafe(t *testing.T) {
	// Empty host must return well-formed empty JSON, never panic.
	_, out := callJSON(t, DNSTool(), map[string]string{"host": ""})
	var dr DNSResult
	if err := json.Unmarshal([]byte(out), &dr); err != nil {
		t.Fatalf("dns result not JSON: %q", out)
	}
	if len(dr.A) != 0 || len(dr.AAAA) != 0 || len(dr.CNAME) != 0 {
		t.Fatalf("expected empty dns result, got %+v", dr)
	}
}

func TestScriptTool(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	_, out := callJSON(t, ScriptTool(), ScriptInput{
		Interp: "python3",
		Code:   "import os; print('TOOL_FOO=' + os.environ.get('TOOL_FOO',''))",
		Params: map[string]any{"foo": "bar"},
		Key:    "unit",
	})
	if !strings.Contains(out, "TOOL_FOO=bar") {
		t.Fatalf("script did not see param env, got: %q", out)
	}
}
