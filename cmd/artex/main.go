// Command artex runs the ARTEX backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/agentctl"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/mcpconn"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/artex/selfupdate"
	"github.com/Autumn-27/artex/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

const banner = `
    _    ____ _____ _______  __
   / \  |  _ \_   _| ____\ \/ /
  / _ \ | |_) || | |  _|  \  /
 / ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  AI 자율 침투 테스트 시스템")
	fmt.Printf("  버전 %s  ·  %s/%s  ·  %s  ·  수신 대기 %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	// Subcommands are dispatched before the default server flags are parsed. Keep this
	// list tiny; the primary mode is still "run the backend" (no subcommand).
	if len(os.Args) > 1 && os.Args[1] == "issue-agent" {
		os.Exit(issueAgentCmd(os.Args[2:]))
	}
	os.Exit(run())
}

// issueAgentCmd mints a sandbox-Agent connection bundle from the Management Server's
// on-disk CA (created under the data dir on first use, shared with the running server).
// ARTEX only produces this bundle; the operator injects it into their own sandbox and
// launches `artex-agent --bundle <file>`. Printing to stdout (or -out) keeps it usable
// from a container one-shot in CI/compose without going through the authenticated API.
func issueAgentCmd(args []string) int {
	fs := flag.NewFlagSet("issue-agent", flag.ExitOnError)
	dataDir := fs.String("data", filepath.Join(config.BaseDir(), "data"), "data directory holding the control-plane CA")
	mode := fs.String("mode", string(remoteexec.ModeAgentDials), "connection mode: agent-dials-mgmt | mgmt-dials-agent")
	address := fs.String("address", "", "agent-dials: Management's reachable host:port; mgmt-dials: the Agent's listen host:port")
	id := fs.String("id", "", "agent id (optional; auto-generated when empty)")
	out := fs.String("out", "", "output file for the bundle JSON (default: stdout)")
	mcpFile := fs.String("mcp", "", "optional JSON file: array of MCP server configs for the Agent to host (db-free alternative to the DB agent_hosted flag)")
	_ = fs.Parse(args)

	var mcp []mcpconn.Config
	if *mcpFile != "" {
		raw, err := os.ReadFile(*mcpFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "issue-agent: read -mcp %s: %v\n", *mcpFile, err)
			return 1
		}
		if err := json.Unmarshal(raw, &mcp); err != nil {
			fmt.Fprintf(os.Stderr, "issue-agent: parse -mcp %s: %v\n", *mcpFile, err)
			return 1
		}
	}

	mgr, err := agentctl.NewManager(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-agent: %v\n", err)
		return 1
	}
	bundle, err := mgr.IssueBundle(remoteexec.ConnMode(*mode), *address, *id, mcp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-agent: %v\n", err)
		return 1
	}
	raw, err := bundle.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-agent: %v\n", err)
		return 1
	}
	if *out == "" {
		fmt.Println(string(raw))
		return 0
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "issue-agent: write %s: %v\n", *out, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "issue-agent: bundle for %q (mode=%s, expires %s) written to %s\n",
		bundle.AgentID, bundle.Mode, bundle.Expires.Format("2006-01-02"), *out)
	return 0
}

func run() int {
	var (
		addr    = flag.String("addr", "127.0.0.1:8787", "HTTP listen address (default accepts local connections only; use :8787 to serve other hosts)")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
	)
	flag.Parse()

	// Fail closed on a misconfigured execution policy: an unrecognized ARTEX_AGENT_OFFLOAD
	// value must not silently disable the sandbox (보안 리뷰).
	if err := server.ValidateOffloadEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf(config.T("[config] 설정 파일: %s"), cfgPath)
	} else {
		log.Printf(config.T("[config] 설정 파일: %s (파일 없음 · 환경 변수 ARTEX_PG_DSN 만 사용)"), cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf(config.T("[config] skill 디렉터리: %s"), skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	srv.WarnIfExposed(*addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("ARTEX %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Two ways out: a signal (normal stop → exit 0, the start script stops looping)
	// or a staged update / rollback (→ exit 75, the script relaunches us and the
	// bootstrap above installs the new build).
	code := 0
	select {
	case <-ctx.Done():
	case <-server.RestartRequested():
		code = selfupdate.ExitRestart
		shutdown(agent.AbortShutdown)
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return code
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
