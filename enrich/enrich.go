// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS is ungated; HTTP probing is gated
// by RoE (§5.2).
package enrich

import (
	"context"
	"crypto/tls"
	"errors"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
)

type job struct {
	kind jobKind
	id   int64  // asset id (domain for DNS, site for HTTP)
	arg  string // host (DNS) or url (HTTP)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the worker pool.
type Engine struct {
	as     *db.AssetStore
	resolv *dnsx.DNSX
	client *http.Client

	jobs   chan job
	cool   sync.Map // dedup/cooldown: "kind:id" -> time.Time (last run)
	once   sync.Once
	closed chan struct{}

	// prober, when set, performs the DNS/HTTP network I/O in a sandboxed Agent instead
	// of in-process (execution-plane split). The engine still owns the asset-graph
	// writes; only the target-facing network calls cross the boundary. nil → in-process
	// (resolv/client), the monolith behavior.
	prober Prober
}

// DNSData / HTTPData are the results a Prober returns, mirroring exactly what the
// in-process resolver/client would have produced so the asset-graph writes are identical.
type DNSData struct {
	A, AAAA, CNAME []string
}

// HTTPData is the HTTP probe outcome used by the asset-graph writer.
type HTTPData struct {
	Status        int
	ContentLength int64
	Title         string
}

// ErrProbeLocally is returned by a Prober to ask the engine to fall back to in-process
// probing (offload=auto with no Agent connected). Any other error means skip entirely —
// used under offload=require, where in-process target I/O is forbidden.
var ErrProbeLocally = errors.New("enrich: probe in-process")

// Prober performs enrich's DNS/HTTP network I/O. The server implements it over the
// sandboxed-Agent channel; nil keeps the in-process path.
type Prober interface {
	ResolveDNS(ctx context.Context, host string) (*DNSData, error)
	ProbeHTTP(ctx context.Context, rawURL string) (*HTTPData, error)
}

// SetProber installs (or clears, with nil) the network prober. Safe to call before the
// engine does any work; wired once at startup by the server.
func (e *Engine) SetProber(p Prober) { e.prober = p }

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
)

// New builds the engine. proxy() returns the recording-proxy address to route HTTP
// probes through (so they land in the traffic store), evaluated per request so the
// runtime traffic-capture toggle takes effect live; "" = direct. Returns a usable
// engine even if the resolver fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	resolv, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
		Timeout:       4 * time.Second,
	})
	if err != nil {
		log.Printf("[enrich] dnsx 初始化失败，DNS 解析停用：%v", err)
		resolv = nil
	}
	e := &Engine{
		as:     as,
		resolv: resolv,
		client: buildClient(proxy),
		jobs:   make(chan job, queueSize),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that dials via the recording proxy (resolved
// per-request via proxy(), so the traffic-capture toggle applies live) and skips
// TLS verification (the proxy re-signs with its MITM CA; targets are often
// self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: httpTimeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := proxy()
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ResolveDomain enqueues a DNS resolution for a domain asset (ungated). host is the
// FQDN. No-op for an empty engine.
func (e *Engine) ResolveDomain(id int64, host string) { e.enqueue(job{jobDNS, id, host}) }

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL.
func (e *Engine) ProbeSite(id int64, rawURL string) { e.enqueue(job{jobHTTP, id, rawURL}) }

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || j.arg == "" {
		return
	}
	select {
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		log.Printf("[enrich] 队列已满，丢弃任务 kind=%d id=%d", j.kind, j.id)
	}
}

func id0(id int64) bool { return id <= 0 }

// Close stops the workers (idempotent).
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() { close(e.closed) })
}

func (e *Engine) worker() {
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			if e.onCooldown(j) {
				continue
			}
			switch j.kind {
			case jobDNS:
				e.doDNS(j.id, j.arg)
			case jobHTTP:
				e.doHTTP(j.id, j.arg)
			}
		}
	}
}

// onCooldown returns true (skip) if this (kind,id) ran within the cooldown window.
func (e *Engine) onCooldown(j job) bool {
	key := string(rune(j.kind)) + ":" + itoa(j.id)
	if v, ok := e.cool.Load(key); ok {
		if t, ok := v.(time.Time); ok && time.Since(t) < cooldown {
			return true
		}
	}
	e.cool.Store(key, time.Now())
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- DNS ----

func (e *Engine) doDNS(id int64, host string) {
	data := e.resolveDNS(host)
	if data == nil {
		return
	}
	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range data.A {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range data.AAAA {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range data.CNAME {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(id int64, rawURL string) {
	host := hostOf(rawURL)
	if host == "" {
		return
	}
	data := e.probeHTTP(rawURL)
	if data == nil {
		return
	}
	_, _ = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           rawURL,
		StatusCode:    &data.Status,
		ContentLength: &data.ContentLength,
		PageTitle:     data.Title,
	})
}

// resolveDNS performs the DNS lookup either in a sandboxed Agent (prober) or in-process.
// The prober may return ErrProbeLocally to request in-process fallback (offload=auto
// with no Agent connected); any other error means skip (e.g. offload=require + no Agent,
// where in-process target I/O is forbidden).
func (e *Engine) resolveDNS(host string) *DNSData {
	if e.prober != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		d, err := e.prober.ResolveDNS(ctx, host)
		cancel()
		if err == nil {
			return d
		}
		if err != ErrProbeLocally {
			return nil
		}
		// fall through to in-process
	}
	if e.resolv == nil {
		return nil
	}
	raw, err := e.resolv.QueryMultiple(host)
	if err != nil || raw == nil {
		return nil
	}
	return &DNSData{A: raw.A, AAAA: raw.AAAA, CNAME: raw.CNAME}
}

// probeHTTP performs the HTTP probe either in a sandboxed Agent or in-process, with the
// same ErrProbeLocally fallback contract as resolveDNS.
func (e *Engine) probeHTTP(rawURL string) *HTTPData {
	if e.prober != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		d, err := e.prober.ProbeHTTP(ctx, rawURL)
		cancel()
		if err == nil {
			return d
		}
		if err != ErrProbeLocally {
			return nil
		}
		// fall through to in-process
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "artex-enrich/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	return &HTTPData{Status: resp.StatusCode, ContentLength: int64(len(body)), Title: extractTitle(body)}
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isBlank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case float64:
		return x == 0
	case int:
		return x == 0
	}
	return false
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
