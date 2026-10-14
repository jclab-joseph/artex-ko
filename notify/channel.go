package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel is the adapter for one notification channel. Implementations must be **stateless**: the
// same instance is reused concurrently by multiple channel configs, and credentials are always passed in via the cfg argument.
type Channel interface {
	// Kind returns the channel type identifier, which must match the registry key.
	Kind() string
	// Validate is called when saving a config, to check required fields and format. The returned error is
	// shown directly to the configurer, so the wording should say "which field is missing" rather than a vague "invalid config".
	Validate(cfg map[string]any) error
	// Send delivers one message, returning the **number of items actually delivered** and an error.
	//
	// Why it returns a count: every platform has a message-length limit, so a digest message is truncated when it cannot hold the whole batch.
	// If the caller unconditionally marks the whole batch as delivered, the truncated items vanish — invisible in the message,
	// shown as success in the delivery history, with nowhere to notice that the findings were never sent. After returning kept,
	// the caller marks only the first kept items and leaves the rest for the next batch.
	//
	// A returned error means delivery failed; a *PermanentError among them means it should not be retried.
	// On failure kept is meaningless and the caller should ignore it.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin returns the channel's officially recommended per-minute delivery cap, used as the default
	// rate limit when creating a new channel instance. Returns 0 when there is no known limit.
	DefaultRatePerMin() int
	// SecretKeys returns the config key names that are credentials for this channel. When the API echoes them back, these keys' values are masked,
	// and on update, receiving a masked value preserves the original value in the database. Only the implementation itself knows which fields count as credentials
	// (for WeCom the entire Webhook address is the credential, whereas for DingTalk it is only the secret within it),
	// so this knowledge must be provided by the channel and cannot be guessed by the upper layer.
	SecretKeys() []string
	// DestinationKeys returns the config key names that decide "where the message is sent" for this channel.
	//
	// Like SecretKeys, this is security-related: the destination address and the credentials are two independent sets of fields,
	// and if "change only the address, keep the credentials as-is" were allowed, anyone able to edit a channel config could send the real credentials from the database
	// to a server they control, rendering the channel-config masking entirely pointless.
	// See PrepareConfigUpdate for details.
	DestinationKeys() []string
}

// registry is the channel registry. It deliberately uses an explicit literal instead of init() self-registration: this way "which channels exist"
// is visible in one place, and adding a channel exposes omissions at compile time rather than via runtime side effects.
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get fetches a channel implementation by type.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports whether kind is a supported channel type.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds returns all supported channel types, sorted lexicographically (for a stable UI dropdown).
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks a delivery failure that should not be retried: credential errors, target rejection, an illegal request body, etc.
// Retrying is only meaningful for transient faults (network jitter, rate limiting, peer 5xx); repeatedly backing off and retrying a permanent failure
// neither succeeds nor helps — it just buries the real error under retry logs.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks err as a permanent failure. It returns nil when err is nil,
// so it can be written as `return Permanent(someCheck())`.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether the err chain carries a permanent-failure mark.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- config-reading helpers ----
//
// A channel config comes from a JSONB column in the database; after encoding/json deserialization it is a map[string]any,
// where numbers are always float64 and arrays are []any. The helpers below unify this conversion and tolerate type
// deviations from users leaving UI fields blank (such as entering a port as a string).

// cfgString reads a string config item, trimming surrounding whitespace — easily picked up when copy-pasting from a web form.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt reads an integer config item, accepting both float64 (the JSON default) and string sources.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool reads a boolean config item, accepting the strings "true"/"1".
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings reads a string-array config item, trimming whitespace and dropping empty strings.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// Also accepts a single string, convenient for a form submission with only one value.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap reads a string-map config item (such as custom HTTP headers), trimming keys and values and dropping empty keys.
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
