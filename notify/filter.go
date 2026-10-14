package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract for the notification_channels.filter JSONB column: the filter conditions of a channel instance.
// All fields are optional, and absence means "no filtering" — which is precisely the fallback semantics for malformed config, see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical); empty = no threshold.
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs as empty arrays mean unrestricted; non-empty requires the event to intersect them.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// VulnClassInclude empty means accept all; non-empty requires vulnclass to match any one of its keywords.
	// VulnClassExclude excludes on matching any keyword (exclude takes precedence over include).
	// Matching is case-insensitive substring — safer than regex: a user's mistyped regex will not silently break the channel.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether this channel receives finding-status-change events (meaningful only in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses the channel's filter config.
//
// **Never returns an error.** This is a deliberate design choice: a malformed filter config always degrades to a zero-value
// Filter (= no filtering = everything matches), because for a vulnerability notification system, **pushing one extra is far better
// than silently dropping a high-severity one**. Letting a parse failure become "do not push" hands the user a channel that looks configured
// but actually pushes nothing — the worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On parse failure f stays at its zero value, i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (an empty string means no threshold).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the **value-restricted** fields in the filter config, for calling when saving a channel.
//
// Why it must be caught at write time: Match's verdict for an unknown threshold is `rank >= 0`, always true —
// that is, a single typo in min_severity ("hgih") makes the filter **silently break** into
// "push everything". This aligns with the package's "better over-push than under-push" trade-off (nothing is dropped),
// but the consequence is that the user thinks they are doing tiered pushing while actually flooding the group with every finding,
// with no sign at all that they misconfigured it. This kind of "silent degradation" is exactly what should be caught at the entry point.
//
// Note that Validate is used only on the **write** path. The read path still uses ParseFilter's lenient semantics,
// so bad values already present in historical data will not make a whole channel unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("올바르지 않은 최소 심각도입니다: %q. low / medium / high / critical 중에서 선택하거나, 비워 두면 제한하지 않습니다", f.MinSeverity)
	}
	return nil
}

// Match determines whether an event should be delivered to a channel carrying these filter conditions.
//
// **Never returns an error**, for the same reason as ParseFilter: any internal anomaly is treated as "matched".
// Verdict order: event type → severity threshold → task/asset scope → vulnerability-type keywords.
func Match(f Filter, s Snapshot) bool {
	// Status-change events are received only by channels that explicitly enable them. Off by default, because the vast majority of users
	// expect "push" to mean "a new finding was discovered", not a running log following every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclude first: matching any exclude keyword knocks it out, even if it also matched the include list.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan suffices for small sets; both sides are on the order of "a few dozen hand-picked by a person",
	// so building a map costs more than it saves.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any of the keywords (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
