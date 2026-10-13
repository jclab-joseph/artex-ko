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
	"strings"
	"syscall"
	"time"

	"io"

	"github.com/Autumn-27/artex/execsvc"
	"github.com/Autumn-27/artex/mcpconn"
	"github.com/Autumn-27/artex/remoteexec"
	"github.com/Autumn-27/artex/traffic"
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
		trafficOn   = flag.Bool("traffic", envTrue("ARTEX_AGENT_TRAFFIC"), "host ARTEX's recording MITM proxy + evidence store in the sandbox (serves traffic_search/get/blob); the toolchain egresses through it")
		trafficAddr = flag.String("traffic-addr", envOr("ARTEX_AGENT_TRAFFIC_ADDR", "127.0.0.1:8788"), "listen address for the hosted recording proxy when --traffic is set")
		retry       = flag.Duration("reconnect", 5*time.Second, "reconnect backoff when the control-plane connection drops (agent-dials mode)")
	)
	flag.Parse()

	fmt.Printf("ARTEX agent %s  ·  execution plane\n", version)

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

	// Optionally host ARTEX's own recording MITM proxy + evidence store here in the
	// sandbox (split mode). When on, it BECOMES the toolchain's egress proxy so every
	// target exchange is captured where the dangerous I/O happens, and the control
	// plane queries it over the same channel via traffic_search/get/blob. The evidence
	// store (SQLite index + blob tree) never leaves the sandbox until report time.
	var tr *traffic.Traffic
	if *trafficOn {
		var err error
		if tr, err = traffic.Open(filepath.Join(absWork, "_traffic"), *trafficAddr); err != nil {
			log.Printf("[agent] 트래픽 레코더를 열지 못했습니다(%s): %v", *trafficAddr, err)
			return 2
		}
		go func() {
			if err := tr.Start(); err != nil {
				log.Printf("[agent] 트래픽 레코더 종료: %v", err)
			}
		}()
		defer tr.Close()
		// If the user also gave an explicit egress proxy, chain it as the recorder's
		// upstream so captured requests still exit through it; then point the toolchain
		// at the local recorder (which re-signs HTTPS with its own CA).
		if *egressProxy != "" {
			if err := tr.SetUpstreamProxy(*egressProxy); err != nil {
				log.Printf("[agent] 상위 프록시 설정 실패(%s): %v", *egressProxy, err)
				return 2
			}
			log.Printf("[agent] 트래픽 레코더 상위 프록시=%s", *egressProxy)
		}
		*egressProxy = tr.ProxyAddr()
		*egressCA = tr.CACertPath()
		waitForFile(*egressCA, 5*time.Second) // CA is written on first proxy start
		log.Printf("[agent] 트래픽 레코더 on: %s (store=%s)", tr.ProxyAddr(), filepath.Join(absWork, "_traffic"))
	}

	// Build the execution tool set. WebFetch and Bash both egress through the local
	// proxy when one is configured, so target traffic is captured where it happens.
	bashEnv := remoteexec.EgressEnv(*egressProxy, *egressCA)
	tools := remoteexec.DefaultAgentTools(*egressProxy, *egressCA, false)
	// db-free execution services: custom script/http tools and the enrich asset-probe
	// pool run their process/network I/O here in the sandbox, invoked programmatically
	// by the control plane over the same channel (not shown to the model).
	tools = append(tools, execsvc.Tools(*egressProxy, *egressCA)...)
	// When hosting the recorder, expose its query tools so Management can inspect the
	// captured evidence over the channel (traffic_search/traffic_get/traffic_blob),
	// plus the internal evidence-sync service the control plane calls at finding-bind
	// time to pull cited bytes out of the sandbox (not shown to the model).
	if tr != nil {
		tools = append(tools, tr.Tools()...)
		tools = append(tools, tr.EvidenceService())
	}
	// Agent-hosted MCP: connect the MCP servers the bundle assigns to this Agent and
	// expose their tools (mcp__server__tool). stdio servers spawn child processes INSIDE
	// the sandbox; http/sse connect to in-sandbox endpoints. The tools are announced
	// with full schemas so the control plane can proxy them (it has no local definition).
	// No LLM, no control-plane DB — only the tool-config the bundle carried.
	var mcpClosers []io.Closer
	defer func() {
		for _, c := range mcpClosers {
			_ = c.Close()
		}
	}()
	for _, cfg := range bundle.MCP {
		cl, err := mcpconn.Connect(context.Background(), cfg)
		if err != nil {
			log.Printf("[agent] MCP %q 연결 실패: %v", cfg.Name, err)
			continue
		}
		mcpClosers = append(mcpClosers, cl)
		ts, err := cl.Tools(context.Background())
		if err != nil {
			log.Printf("[agent] MCP %q tools/list 실패: %v", cfg.Name, err)
			continue
		}
		tools = append(tools, ts...)
		log.Printf("[agent] MCP %q 호스팅: %d개 도구", cfg.Name, len(ts))
	}
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

// envTrue reads a boolean-ish env var (1/true/yes/on, case-insensitive) as a flag
// default. Anything else — including unset — is false.
func envTrue(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// waitForFile polls for a path to appear, up to d. Used to let go-mitmproxy write
// its CA on first start before the first child command needs to trust it.
func waitForFile(path string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
