package notify

import "testing"

func TestParseFilterMalformedFallsBackToMatchAll(t *testing.T) {
	// Malformed JSON, empty input, wrong-typed fields — all must degrade to a zero-value Filter,
	// i.e. "no filtering". This invariant is where "better over-push than under-push" lands:
	// if this ever changed to error or partial-parse, a single wrong character would silently drop all high-severity notifications.
	cases := []struct {
		name string
		raw  string
	}{
		{"empty input", ""},
		{"invalid JSON", `{not json`},
		{"truncated JSON", `{"min_severity":`},
		{"type mismatch", `{"min_severity": 123, "task_ids": "abc"}`},
		{"top level is an array", `[1,2,3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ParseFilter([]byte(tc.raw))
			if f.MinSeverity != "" || len(f.TaskIDs) != 0 || len(f.AssetIDs) != 0 {
				t.Fatalf("malformed config should degrade to a zero-value Filter, got %+v", f)
			}
			// A zero-value Filter must match any event.
			ev := Snapshot{Kind: EventFindingCreated, Severity: "low", VulnClass: "XSS"}
			if !Match(f, ev) {
				t.Fatal("a zero-value Filter should match all events")
			}
		})
	}
}

func TestMatchSeverityThreshold(t *testing.T) {
	ev := func(sev string) Snapshot {
		return Snapshot{Kind: EventFindingCreated, Severity: sev}
	}
	cases := []struct {
		min    string
		sev    string
		expect bool
	}{
		{"", "low", true},
		{"", "critical", true},
		{"high", "critical", true},
		{"high", "high", true},
		{"high", "medium", false},
		{"high", "low", false},
		{"critical", "high", false},
		{"critical", "critical", true},
		// An unknown severity has ordinal 0 and should be blocked by any non-empty threshold (when in doubt, do not push).
		{"low", "", false},
		{"low", "unknown", false},
		{"", "", true},
	}
	for _, tc := range cases {
		got := Match(Filter{MinSeverity: tc.min}, ev(tc.sev))
		if got != tc.expect {
			t.Errorf("min=%q sev=%q: expected %v got %v", tc.min, tc.sev, tc.expect, got)
		}
	}
}

func TestMatchScopeRestrictions(t *testing.T) {
	ev := Snapshot{
		Kind:      EventFindingCreated,
		Severity:  "high",
		TaskID:    7,
		AssetIDs:  []int64{10, 20},
		VulnClass: "SQL injection",
	}
	cases := []struct {
		name   string
		filter Filter
		expect bool
	}{
		{"empty scope = unrestricted", Filter{}, true},
		{"task matches", Filter{TaskIDs: []int64{7}}, true},
		{"task does not match", Filter{TaskIDs: []int64{8}}, false},
		{"task multi-select includes a match", Filter{TaskIDs: []int64{8, 7}}, true},
		{"assets intersect", Filter{AssetIDs: []int64{20, 99}}, true},
		{"assets do not intersect", Filter{AssetIDs: []int64{99}}, false},
		{"task and assets both match", Filter{TaskIDs: []int64{7}, AssetIDs: []int64{10}}, true},
		{"task matches but assets do not", Filter{TaskIDs: []int64{7}, AssetIDs: []int64{99}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.filter, ev); got != tc.expect {
				t.Errorf("expected %v got %v", tc.expect, got)
			}
		})
	}
}

func TestMatchVulnClassKeywords(t *testing.T) {
	ev := func(class string) Snapshot {
		return Snapshot{Kind: EventFindingCreated, Severity: "high", VulnClass: class}
	}
	cases := []struct {
		name   string
		filter Filter
		class  string
		expect bool
	}{
		{"empty include = accept all", Filter{}, "any type", true},
		{"include matches", Filter{VulnClassInclude: []string{"SQL"}}, "SQL injection", true},
		{"include does not match", Filter{VulnClassInclude: []string{"command execution"}}, "SQL injection", false},
		{"include any of multiple words matches", Filter{VulnClassInclude: []string{"command execution", "SQL"}}, "SQL injection", true},
		{"case-insensitive", Filter{VulnClassInclude: []string{"sql"}}, "SQL injection", true},
		{"exclude match excludes", Filter{VulnClassExclude: []string{"information disclosure"}}, "information disclosure", false},
		{"exclude no match lets through", Filter{VulnClassExclude: []string{"information disclosure"}}, "SQL injection", true},
		// Exclude takes precedence over include: when both match it should be knocked out.
		{"exclude over include", Filter{
			VulnClassInclude: []string{"SQL"},
			VulnClassExclude: []string{"injection"},
		}, "SQL injection", false},
		// Pure-whitespace keywords should be ignored, otherwise it degrades to "match any string containing a space".
		{"blank keywords are ignored", Filter{VulnClassInclude: []string{"", "  "}}, "SQL injection", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.filter, ev(tc.class)); got != tc.expect {
				t.Errorf("expected %v got %v", tc.expect, got)
			}
		})
	}
}

func TestMatchStatusChangeRequiresOptIn(t *testing.T) {
	ev := Snapshot{Kind: EventFindingStatusChanged, Severity: "critical", FromStatus: "pending", ToStatus: "fixed"}
	// Off by default: what most people mean by "push findings" is discovering new findings, not a running log of statuses.
	if Match(Filter{MinSeverity: "low"}, ev) {
		t.Fatal("a status-change event should be skipped when not enabled")
	}
	if !Match(Filter{OnStatusChange: true}, ev) {
		t.Fatal("with on_status_change enabled a status-change event should match")
	}
	// Creation events are not affected by on_status_change.
	created := Snapshot{Kind: EventFindingCreated, Severity: "critical"}
	if !Match(Filter{MinSeverity: "low"}, created) {
		t.Fatal("a creation event should not depend on on_status_change")
	}
}
