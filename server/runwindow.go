package server

import (
	"fmt"
	"time"
)

// Per-task run window ("작업 시간대"): a task may be restricted to run only during a
// daily time window in a given IANA timezone (e.g. 01:00–06:00 Asia/Seoul). Outside
// the window the scheduler auto-pauses the task; inside it auto-resumes. The window
// is stored on the task as (tz, startMin, endMin) where start/end are minutes from
// midnight [0,1440). An empty tz means no window (feature off).
//
// This file holds only the pure, timezone-aware predicate + validation so the logic
// is unit-testable without a DB or engine.

// minutesPerDay is the number of minute slots in a day; valid minute-of-day is [0, minutesPerDay).
const minutesPerDay = 24 * 60

// ValidateRunWindow checks a run-window triple. An empty tz disables the window and
// is always valid (start/end are ignored). Otherwise tz must be a loadable IANA zone,
// start/end must be in [0,1440), and start must differ from end (start==end is a
// degenerate zero/full window — to run with no restriction, leave tz empty instead).
func ValidateRunWindow(tz string, startMin, endMin int) error {
	if tz == "" {
		return nil
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	if startMin < 0 || startMin >= minutesPerDay || endMin < 0 || endMin >= minutesPerDay {
		return fmt.Errorf("run window minutes must be in [0,%d): start=%d end=%d", minutesPerDay, startMin, endMin)
	}
	if startMin == endMin {
		return fmt.Errorf("run window start and end must differ (got %d); leave the timezone empty for no restriction", startMin)
	}
	return nil
}

// RunWindowOpenAt reports whether the window (tz, startMin, endMin) is open at the
// instant now. A caller with an empty tz has no window and must not call this (it
// returns an error). start is inclusive, end is exclusive. When startMin > endMin the
// window wraps past midnight (e.g. 22:00–06:00). DST is handled by comparing the
// local wall-clock minute-of-day in the task's zone.
func RunWindowOpenAt(tz string, startMin, endMin int, now time.Time) (bool, error) {
	if err := ValidateRunWindow(tz, startMin, endMin); err != nil {
		return false, err
	}
	if tz == "" {
		return false, fmt.Errorf("no run window configured")
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return false, fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	local := now.In(loc)
	m := local.Hour()*60 + local.Minute()
	if startMin < endMin {
		return m >= startMin && m < endMin, nil
	}
	// wrap past midnight
	return m >= startMin || m < endMin, nil
}
