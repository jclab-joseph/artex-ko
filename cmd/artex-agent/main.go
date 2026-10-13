// Command artex-agent is ARTEX's execution plane: a sandboxed worker that runs the
// dangerous, side-effecting tools (Bash, file I/O, WebFetch, and scanners invoked via
// Bash) on behalf of the Management Server, over a mutually authenticated TLS channel.
//
// It deliberately imports NO LLM provider, NO LLM secret, and NO control-plane
// database. The only thing it ever receives from Management is "run this tool with
// this input"; the only thing it returns is the tool's output. The user runs this
// binary inside their own internet-isolated sandbox; ARTEX only hands them the
// connection bundle (see `artex ... issue-agent`), it never launches the sandbox.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/remoteexec"
)

// version is injected at release time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	var (
		bundlePath  = flag.String("bundle", envOr("ARTEX_AGENT_BUNDLE", ""), "path to the connection bundle JSON issued by the Management Server")
		workDir     = flag.String("work", envOr("ARTEX_AGENT_WORK", "/work"), "sandbox working directory root where all tool files land")
		egressProxy = flag.String("egress-proxy", envOr("ARTEX_AGENT_EGRESS_PROXY", ""), "optional egress proxy for Bash/WebFetch child commands (e.g. http://127.0.0.1:8788)")
		egressCA    = flag.String("egress-ca", envOr("ARTEX_AGENT_EGRESS_CA", ""), "optional PEM CA path the toolchain trusts for the egress proxy's re-signed HTTPS")
		retry       = flag.Duration("reconnect", 5*time.Second, "reconnect backoff when the control-plane connection drops (agent-dials mode)")
	)
	flag.Parse()

	fmt.Printf("ARTEX agent %s  ·  execution plane (no LLM, no secrets)\n", version)

	if *bundlePath == "" {
		log.Printf("[agent] 연결 번들이 필요합니다: --bundle <path> 또는 ARTEX_AGENT_BUNDLE")
		return 2
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		log.Printf("[agent] 번들을 읽지 못했습니다: %v", err)
		return 2
	}
	bundle, err := remoteexec.ParseBundle(raw)
	if err != nil {
		log.Printf("[agent] 번들이 올바르지 않습니다: %v", err)
		return 2
	}
	if bundle.Expired() {
		log.Printf("[agent] 번들의 인증서가 만료되었습니다(발급 %s · 만료 %s). 관리 서버에서 새 번들을 발급받아 다시 실행하십시오.",
			bundle.Issued.Format(time.RFC3339), bundle.Expires.Format(time.RFC3339))
		return 2
	}

	absWork, _ := filepath.Abs(*workDir)
	if err := os.MkdirAll(absWork, 0o755); err != nil {
		log.Printf("[agent] 작업 디렉터리를 만들지 못했습니다(%s): %v", absWork, err)
		return 2
	}

	// Build the execution tool set. WebFetch and Bash both egress through the local
	// proxy when one is configured, so target traffic is captured where it happens.
	bashEnv := remoteexec.EgressEnv(*egressProxy, *egressCA)
	tools := remoteexec.DefaultAgentTools(*egressProxy, *egressCA, false)
	exec := remoteexec.NewExecutor(tools, absWork, bashEnv)

	log.Printf("[agent] id=%s mode=%s address=%s work=%s tools=%v",
		bundle.AgentID, bundle.Mode, bundle.Address, absWork, exec.ToolNames())
	if *egressProxy != "" {
		log.Printf("[agent] egress proxy=%s ca=%s", *egressProxy, orNone(*egressCA))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		if bundle.Expired() {
			log.Printf("[agent] 인증서 만료 — 재프로비저닝이 필요합니다. 종료합니다.")
			return 2
		}
		sess, err := remoteexec.ConnectAgentSide(ctx, bundle, exec)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			log.Printf("[agent] 연결 실패: %v (%.0fs 후 재시도)", err, retry.Seconds())
			if !sleepCtx(ctx, *retry) {
				return 0
			}
			continue
		}
		log.Printf("[agent] 관리 서버와 연결되었습니다. 실행 대기 중.")
		select {
		case <-sess.Done():
			if ctx.Err() != nil {
				return 0
			}
			log.Printf("[agent] 연결이 끊어졌습니다: %v (%.0fs 후 재연결)", sess.Err(), retry.Seconds())
			if !sleepCtx(ctx, *retry) {
				return 0
			}
		case <-ctx.Done():
			sess.Close()
			return 0
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
