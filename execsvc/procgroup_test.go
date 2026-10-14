package execsvc

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// TestScriptKillsDetachedChildren: a script that detaches a child with subprocess.Popen
// must not leave that child running after the call returns — the whole process group is
// killed, so a scanner spawned this way cannot keep executing/egressing past the session
// (보안 리뷰: 세션 종료 후에도 Bash/Python 자식 프로세스 잔존).
func TestScriptKillsDetachedChildren(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	work := t.TempDir()
	marker := filepath.Join(work, "orphan")
	// The detached child sleeps, then writes the marker. If it is killed with its parent's
	// process group when the call returns, the marker is never written.
	code := "import subprocess\n" +
		"subprocess.Popen(['/bin/sh','-c'," +
		"\"sleep 0.5; printf child > '" + marker + "'\"]," +
		"stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n" +
		"print('started')\n"
	in, _ := json.Marshal(ScriptInput{Code: code, Key: "test"})

	res, err := ScriptTool().Call(context.Background(), in, &actool.ToolContext{WorkingDir: work})
	if err != nil {
		t.Fatalf("script call transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("script call errored: %s", res.Flatten())
	}

	time.Sleep(900 * time.Millisecond) // well past the child's 0.5s sleep
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a detached child survived the script call and wrote %s (process group not killed)", marker)
	}
}
