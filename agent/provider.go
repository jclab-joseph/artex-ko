// Package agent wires real LLM-driven planner and work agents (on top of the
// agent-core SDK) to the dual SQLite graph. See docs/ARTEX-architecture.md
// §4.3 (planner) and §4.4 (work agent).
//
// Provider configuration is read from the environment so the system runs with
// any Anthropic- or OpenAI-format endpoint. If no key is configured, FromEnv
// returns ok=false and the exploration engine stays idle (an LLM is required).
package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
)

// Config describes the LLM backend resolved from the environment.
type Config struct {
	Format  llm.Format
	BaseURL string
	APIKey  string
	Model   string
	// Proxy routes all LLM requests through the given proxy URL (http/https/socks5,
	// optionally with user:pass@ credentials). Empty means direct — it does NOT
	// fall back to the standard *_PROXY environment variables.
	Proxy string
	// RatePerSecond / RatePerMinute cap the shared request rate across ALL agents
	// using the provider (0 = that window unlimited).
	RatePerSecond float64
	RatePerMinute float64
	// ContextWindowK is the model's context window in K tokens (user-configured),
	// used to size compaction thresholds. 0 = default; see CompactionWindow.
	ContextWindowK int
	// ThinkingType independently controls the thinking "switch" field (thinking.type):
	//   "" = don't send (default, compatible with models lacking the field); "disabled" = explicitly off;
	//   "enabled" = on. Fully decoupled from ReasoningEffort — some endpoints have no thinking field
	//   and activate thinking from the effort parameter alone, so the two can be set independently.
	ThinkingType string
	// ReasoningEffort independently controls the thinking "effort" field:
	//   "" = don't send (default); "low"/"medium"/"high"/"xhigh"/"max" = the matching effort.
	//   OpenAI maps it to the top-level reasoning_effort; Anthropic to output_config.effort.
	ReasoningEffort string
	// Stream controls whether this profile uses the streaming (SSE) API. true (default) = streaming;
	// false = truly non-streaming (send stream:false, grab the full JSON at once, via Provider.Complete).
	// Non-streaming can work around some gateways' bad SSE implementations (empty frames, dropped
	// thinking-field frames), at the cost of losing live in-run progress / live token counts.
	// Maps to agentcore.Options.NonStreaming = !Stream.
	Stream bool
	// MaxTokens is the output cap for a single reply (in tokens). 0 = don't send the field and let the
	// server default decide (historical behavior). Unlike ContextWindowK: that is the model's total
	// capacity, used only locally to compute compaction thresholds and never appearing in the request;
	// this value is sent with every request. Maps to agentcore.Options.MaxTokens.
	MaxTokens int
	// MaxTokensField selects which request field name MaxTokens uses, effective only for format=openai:
	//   "" = max_tokens (default); "max_completion_tokens" = the new field.
	// OpenAI reasoning models (the o-series / GPT-5) accept only the latter and reject max_tokens with
	// unsupported_parameter, while most compatible gateways accept only the former; so we don't infer
	// automatically and leave the choice to the user per endpoint.
	MaxTokensField string
	// SessionHeaderKey, when non-empty, makes every LLM request carry a custom HTTP header whose name
	// is this value and whose value is [the current session's session id] (chat session = conv-<id>,
	// worker = exp<x>-worker-i<intent>, etc.; see WorkerSessionID). Used by gateways that do prompt
	// caching / sticky routing keyed on a session-id header. Empty = don't send. The value is attached
	// to the request context by transcript.WithSessionID and read in by the RoundTripper, so even one
	// shared provider can emit different header values per session.
	SessionHeaderKey string
	// Retry holds the resolved retry parameters for this config (profile override → global policy →
	// built-in default, resolved on the server side). See RetryConfig for what each layer means; the
	// zero value = follow the built-in defaults entirely.
	Retry RetryConfig
}

// RetryConfig holds the retry parameters that travel with an LLM config. Each layer's "attempts" has
// a uniform meaning: 0 = use the built-in default count; negative = disable that layer's retries;
// >0 = use that value. Each layer's "interval": 0 = use that layer's own exponential backoff;
// >0 = use this fixed interval instead.
type RetryConfig struct {
	// ConnectAttempts/ConnectInterval: SDK connection-retry (connection reset/timeout/429/5xx, before
	// the stream starts), mapped directly to llm.Config.MaxRetries / RetryInterval. Default 3 attempts,
	// exponential from 0.5s (capped at 8s).
	ConnectAttempts int
	ConnectInterval time.Duration
	// EmptyAttempts/EmptyInterval: SDK empty-response retry (completed but no content block, openai
	// format only), mapped to llm.Config.EmptyResponseRetries / EmptyResponseInterval.
	// Default 2 attempts, the same exponential gradient.
	EmptyAttempts int
	EmptyInterval time.Duration
	// StreamAttempts/StreamInterval: same-provider safe-window retry — a layer this project adds on top
	// of the SDK, replaying a broken stream/overload/in-stream 429 only while "no output has yet been
	// delivered to the caller". The SDK doesn't see it; it's consumed by server/task_llm.go. Default
	// 2 attempts, exponential from 0.5s (capped at 4s).
	StreamAttempts int
	StreamInterval time.Duration
}

// compaction window resolution bounds (in K tokens). Below the floor the
// threshold math (window − summary reserve − buffer) would go non-positive and
// compaction would fire every turn; above the cap it would never fire.
const (
	defaultWindowK = 200  // unset → assume a 200K window (Claude default)
	minWindowK     = 32   // floor so effectiveWindow stays comfortably positive
	maxWindowK     = 1000 // cap at 1M tokens (user request)
)

// CompactionWindow returns the model context window in TOKENS for compaction
// thresholds, resolved from the user-configured size (ContextWindowK). 0/unset →
// a 200K default; otherwise clamped to [32K, 1M] so compaction stays effective.
func (c Config) CompactionWindow() int {
	k := c.ContextWindowK
	if k <= 0 {
		k = defaultWindowK
	}
	if k < minWindowK {
		k = minWindowK
	}
	if k > maxWindowK {
		k = maxWindowK
	}
	return k * 1000
}

// compactionConfig builds the agent-core compaction config for a context window
// in tokens. agentcore.NewSession wires the summarizer (same provider) when this
// is set on Options.Compaction.
func compactionConfig(windowTokens int) *compaction.Config {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	return &compaction.Config{ContextWindow: windowTokens}
}

// FromEnv resolves the LLM provider config:
//
//	ARTEX_LLM_PROVIDER = anthropic|openai (default: inferred from keys)
//	ARTEX_LLM_MODEL    = model id        (default: per provider)
//	ARTEX_LLM_BASE_URL = endpoint        (optional)
//	ARTEX_LLM_PROXY    = proxy URL        (optional; http/https/socks5)
//	ANTHROPIC_API_KEY / OPENAI_API_KEY         = credentials
func FromEnv() (Config, bool) {
	prov := os.Getenv("ARTEX_LLM_PROVIDER")
	anthKey := os.Getenv("ANTHROPIC_API_KEY")
	oaiKey := os.Getenv("OPENAI_API_KEY")

	if prov == "" {
		switch {
		case anthKey != "":
			prov = "anthropic"
		case oaiKey != "":
			prov = "openai"
		default:
			return Config{}, false
		}
	}

	c := Config{
		BaseURL: os.Getenv("ARTEX_LLM_BASE_URL"),
		Model:   os.Getenv("ARTEX_LLM_MODEL"),
		Proxy:   strings.TrimSpace(os.Getenv("ARTEX_LLM_PROXY")),
		// Streaming by default; ARTEX_LLM_STREAM=false/0/off explicitly turns it off for non-streaming.
		Stream: !isFalsy(os.Getenv("ARTEX_LLM_STREAM")),
	}
	switch prov {
	case "openai":
		c.Format = llm.FormatOpenAI
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		c.APIKey = anthKey
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	if c.APIKey == "" {
		return Config{}, false
	}
	return c, true
}

// ConfigFrom builds a Config from UI-provided strings (provider defaults to
// anthropic; model defaults per provider). Inputs are trimmed and the base URL
// is normalized to the API base the provider expects (the provider appends the
// endpoint path itself), so a full endpoint URL is tolerated.
func ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config {
	c := Config{
		Model:   strings.TrimSpace(model),
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		Proxy:   strings.TrimSpace(proxy),
		Stream:  true, // streaming by default; callers override per profile
	}
	switch strings.TrimSpace(provider) {
	case "openai":
		c.Format = llm.FormatOpenAI
		// provider appends "/chat/completions"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		// provider appends "/responses"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/responses"), "/")
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		// provider appends "/v1/messages".
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/v1/messages"), "/")
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	return c
}

// isFalsy reports whether an env-var string explicitly requests "off". Empty or
// unrecognized → false (so an unset var keeps the streaming default).
func isFalsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Provider returns the short provider name ("anthropic"/"openai").
func (c Config) Provider() string {
	switch c.Format {
	case llm.FormatOpenAI:
		return "openai"
	case llm.FormatOpenAIResponses:
		return "openai-responses"
	}
	return "anthropic"
}

// NewProvider builds an llm.Provider from the config. When a rate is set, the
// limiter lives on the single provider instance — so planner + all workers +
// main agent (which share this provider) are bounded by one shared rate limit.
func (c Config) NewProvider() (llm.Provider, error) {
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey)
	if err != nil {
		return nil, err
	}
	lc := llm.Config{
		Format:     c.Format,
		BaseURL:    c.BaseURL,
		APIKey:     c.APIKey,
		Model:      c.Model,
		HTTPClient: client,
	}
	// The thinking switch and effort fields pass through independently (empty = don't send that field).
	// The two are decoupled: you can send only thinking.type, only effort, both, or neither.
	lc.ThinkingType = c.ThinkingType
	lc.ReasoningEffort = c.ReasoningEffort
	// Choice of the output-cap field name (empty = use max_tokens). The cap's "value" isn't here: it
	// travels each turn with agentcore.Options.MaxTokens; the provider only decides which key to put it in.
	lc.MaxTokensField = c.MaxTokensField
	// Retry parameters share the SDK's semantics (attempts 0=default/negative=off, interval 0=exponential
	// backoff/>0=fixed), passed through verbatim.
	lc.MaxRetries = c.Retry.ConnectAttempts
	lc.RetryInterval = c.Retry.ConnectInterval
	lc.EmptyResponseRetries = c.Retry.EmptyAttempts
	lc.EmptyResponseInterval = c.Retry.EmptyInterval
	if c.RatePerSecond > 0 || c.RatePerMinute > 0 {
		lc.RateLimit = &llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}
	}
	return llm.NewProvider(lc)
}

// IsQuotaExhaustedMessage deliberately recognizes only explicit balance,
// billing, credit, or quota-exhaustion signals. Generic 429/rate-limit text,
// authentication failures, network errors, and server failures are excluded.
var nonFailoverHTTPStatus = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(?:401|403|5\d\d)\b`)
var transientQuotaLimit = regexp.MustCompile(`(?i)(?:\b(?:rpm|tpm|rpd|qps)\b|quota[_\s-]*metric|rate[_\s-]*limit|too many requests|(?:requests?|tokens?)\s+(?:per|/)\s*(?:second|minute)|(?:per|/)\s*(?:second|minute)\s+(?:requests?|tokens?)|generate[_\s-]*requests[_\s-]*per[_\s-]*(?:minute|second)|tokens?[_\s-]*per[_\s-]*(?:minute|second))`)

func IsQuotaExhaustedMessage(message string) bool {
	message = strings.ToLower(message)
	// Authentication/authorization and provider-side 5xx failures never rotate,
	// even when a gateway happens to echo a quota-looking phrase in the body.
	if nonFailoverHTTPStatus.MatchString(message) {
		return false
	}
	// Provider APIs frequently describe an ordinary rate limit as "quota
	// exceeded", especially Google-style responses containing a quota metric.
	// These limits recover with time and must stay on the current provider.
	if transientQuotaLimit.MatchString(message) {
		return false
	}
	markers := []string{
		"insufficient_quota", "quota_exceeded", "quota exceeded", "quota exhausted",
		"exceeded your current quota", "billing_hard_limit_reached",
		"billing hard limit", "billing_not_active", "credit balance", "insufficient credit",
		"insufficient balance", "balance is too low", "payment required", "status 402",
		"余额不足", "额度不足", "额度已用尽", "欠费",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// gRPC RESOURCE_EXHAUSTED is overloaded for both account quota and ordinary
	// request-rate limiting. Preserve it as an explicit exhaustion signal only
	// when the same error does not identify a transient rate limit.
	return strings.Contains(message, "resource_exhausted") &&
		!strings.Contains(message, "rate limit") &&
		!strings.Contains(message, "too many requests")
}

// quotaAwareTransport preserves Norma's normal retry behavior except for a 429
// whose body explicitly says the account quota/balance is exhausted. Norma's
// retry loop treats every 429 as transient; normalizing only that response to
// 402 lets a task router fail over immediately while retaining the original
// response body for provider-specific classification and audit logs.
type quotaAwareTransport struct {
	base http.RoundTripper
	// sessionHeaderKey, when non-empty, is the HTTP header name each request
	// carries; its value is the session id read from the request context. Empty
	// disables it. See Config.SessionHeaderKey.
	sessionHeaderKey string
}

func (t quotaAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Custom session-id header: name is user-configured, value is THIS run's
	// session id (norma stashes it on the context via transcript.WithSessionID).
	// Stable across a session's turns and distinct across sessions — exactly what
	// a session-keyed prompt cache wants. Skipped when no session id is present.
	if t.sessionHeaderKey != "" {
		if sid := transcript.SessionIDFrom(req.Context()); sid != "" {
			req.Header.Set(t.sessionHeaderKey, sid)
		}
	}
	// When LLM recording is on, the Recorder puts a Capture on the context so the
	// raw wire bodies can be persisted. This is the only layer that still sees
	// them: norma builds the request body internally and decodes the SSE response
	// before either reaches the recorder.
	capt := llmrec.CaptureFrom(req.Context())
	capt.SetRequest(requestBodySnapshot(req))

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Tee rather than read: a 200 is an SSE stream that must keep streaming. The
	// 429 branch below reads through this wrapper, so its body lands in the
	// capture before being replaced.
	resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if readErr != nil {
		return resp, nil
	}
	if IsQuotaExhaustedMessage(string(body)) {
		resp.StatusCode = http.StatusPaymentRequired
		resp.Status = "402 Payment Required"
	}
	return resp, nil
}

// requestBodySnapshot copies an outgoing request body without consuming it.
// norma builds every model request from a *bytes.Reader, so net/http populates
// GetBody and the copy has no effect on what gets sent.
func requestBodySnapshot(req *http.Request) string {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

func quotaAwareHTTPClient(proxy, sessionHeaderKey string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		transport.Proxy = nil // empty = direct connection; does not fall back to the HTTP_PROXY/HTTPS_PROXY env vars
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: quotaAwareTransport{base: transport, sessionHeaderKey: strings.TrimSpace(sessionHeaderKey)}}, nil
}

// logTestConnection prints the raw HTTP status code(s) and response body of a
// connection test to the server log, so clicking "Test" leaves a diagnosable trail of
// exactly what the gateway returned — 401 bodies, quota text, empty frames — not
// just the collapsed ok/err the UI shows. Bodies are clipped to keep a chatty
// SSE stream from flooding the log.
func logTestConnection(c Config, capt *llmrec.Capture) {
	attempts := capt.Attempts()
	if len(attempts) == 0 {
		log.Printf("[llm-test] %s / %s @ %s — no HTTP request was made (config parsing or connection setup failed)",
			c.Provider(), c.Model, c.BaseURL)
		return
	}
	for i, a := range attempts {
		log.Printf("[llm-test] %s / %s @ %s — attempt %d/%d HTTP %d\nresponse body: %s",
			c.Provider(), c.Model, c.BaseURL, i+1, len(attempts), a.Status, clipBody(a.Body))
	}
}

// clipBody trims a wire body for logging. 4K is plenty to show an error JSON or
// the head of an SSE stream while bounding a runaway response.
func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	const max = 4096
	if len(s) > max {
		return s[:max] + fmt.Sprintf("…(truncated, %d bytes total)", len(s))
	}
	return s
}

// TestConnection makes a minimal real completion to verify the provider/model/
// endpoint/key actually work. Returns the round-trip latency and the model's
// reply text.
func TestConnection(ctx context.Context, c Config) (time.Duration, string, error) {
	prov, err := c.NewProvider()
	if err != nil {
		return 0, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Capture the raw wire bytes: what a connection test most needs to see is exactly what the gateway
	// returned (status code + response body), which is gone once norma decodes the response into
	// StreamEvents. quotaAwareTransport finds this Capture on the context and fills in each HTTP
	// attempt's status code and body.
	ctx, capt := llmrec.NewCapture(ctx)
	defer logTestConnection(c, capt)
	// A connection test is a single-shot path that doesn't go through agentcore's session loop, so
	// nobody attaches a session id to the context. For endpoints configured with SessionHeaderKey (e.g.
	// opencode zen requires the x-opencode-session header and returns 400 MissingSessionID without it),
	// this causes a "conversation works, but clicking Test returns 400" gap. Here we attach a one-off
	// random session id so the test and a real conversation share the same header-sending logic;
	// endpoints without SessionHeaderKey don't read it, so there's no side effect.
	ctx = transcript.WithSessionID(ctx, "conntest-"+transcript.NewSessionID())
	start := time.Now()
	// MaxTokens must be generous: reasoning models (e.g. deepseek-v4-pro) emit a large chunk of thinking
	// before giving an answer (in practice even a single "ping" can burn ~2900 tokens). With only 32,
	// the model stays stuck in the "thinking phase" and hits the output cap (finish=length), getting
	// truncated; the connection test still counts as passing (err=nil) but shows up as a mess of
	// "interrupted/length/resume". Give it enough budget to emit OK cleanly (finish=stop).
	// Keep EscalateMaxTokens false: don't raise the cap and retry on truncation, avoiding a wasteful
	// resume loop.
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"You are a connection test. Just output the two characters OK, nothing else — no thinking, no explanation."},
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      8192,
		NonStreaming:   !c.Stream, // run the connection test in this profile's real send/receive mode
	}, "ping")
	lat := time.Since(start)
	if err != nil {
		return lat, "", err
	}
	// err==nil isn't enough: a request can go through while the model emits not a single character
	// (thinking burned the budget, the body was swallowed by a safety policy, the compatibility layer
	// dropped the content). In a conversation such a config simply "doesn't reply", yet the test reports
	// success — exactly the gap this clause eliminates. No visible body always counts as failure.
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return lat, "", fmt.Errorf("model returned no content (request succeeded, but no text was returned)")
	}
	return lat, reply, nil
}
