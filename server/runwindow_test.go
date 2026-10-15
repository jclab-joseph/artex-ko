package server

import (
	"testing"
	"time"
)

func TestValidateRunWindow(t *testing.T) {
	cases := []struct {
		name       string
		tz         string
		start, end int
		wantErr    bool
	}{
		{"empty tz disables (valid)", "", 0, 0, false},
		{"empty tz ignores bad minutes", "", 9999, -5, false},
		{"valid seoul window", "Asia/Seoul", 60, 360, false},
		{"valid wrap window", "Asia/Seoul", 1320, 360, false},
		{"invalid tz", "Mars/Olympus", 60, 360, true},
		{"start==end rejected", "Asia/Seoul", 120, 120, true},
		{"start out of range", "Asia/Seoul", 1440, 360, true},
		{"end out of range", "Asia/Seoul", 60, -1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRunWindow(c.tz, c.start, c.end)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateRunWindow(%q,%d,%d) err=%v wantErr=%v", c.tz, c.start, c.end, err, c.wantErr)
			}
		})
	}
}

func TestRunWindowOpenAt(t *testing.T) {
	seoul, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Fatalf("LoadLocation Asia/Seoul (is time/tzdata embedded?): %v", err)
	}
	at := func(h, m int) time.Time { return time.Date(2026, 6, 15, h, m, 0, 0, seoul) }

	// no-wrap window 01:00–06:00: start inclusive, end exclusive.
	nowrap := []struct {
		h, m int
		open bool
	}{
		{0, 59, false},
		{1, 0, true}, // start inclusive
		{3, 30, true},
		{5, 59, true},
		{6, 0, false}, // end exclusive
		{23, 0, false},
	}
	for _, c := range nowrap {
		got, err := RunWindowOpenAt("Asia/Seoul", 60, 360, at(c.h, c.m))
		if err != nil {
			t.Fatalf("no-wrap %02d:%02d err %v", c.h, c.m, err)
		}
		if got != c.open {
			t.Errorf("no-wrap 01:00-06:00 at %02d:%02d = %v, want %v", c.h, c.m, got, c.open)
		}
	}

	// wrap window 22:00–06:00 (crosses midnight).
	wrap := []struct {
		h, m int
		open bool
	}{
		{21, 59, false},
		{22, 0, true}, // start inclusive
		{23, 30, true},
		{0, 0, true},
		{5, 59, true},
		{6, 0, false}, // end exclusive
		{12, 0, false},
	}
	for _, c := range wrap {
		got, err := RunWindowOpenAt("Asia/Seoul", 1320, 360, at(c.h, c.m))
		if err != nil {
			t.Fatalf("wrap %02d:%02d err %v", c.h, c.m, err)
		}
		if got != c.open {
			t.Errorf("wrap 22:00-06:00 at %02d:%02d = %v, want %v", c.h, c.m, got, c.open)
		}
	}

	// timezone matters: 03:00 UTC is 12:00 KST → outside a 01:00–06:00 KST window.
	utcNoon := time.Date(2026, 6, 15, 3, 0, 0, 0, time.UTC)
	if open, err := RunWindowOpenAt("Asia/Seoul", 60, 360, utcNoon); err != nil || open {
		t.Errorf("03:00 UTC (=12:00 KST) should be closed for 01:00-06:00 KST: open=%v err=%v", open, err)
	}

	// invalid inputs surface an error.
	if _, err := RunWindowOpenAt("Asia/Seoul", 120, 120, at(3, 0)); err == nil {
		t.Error("start==end should error")
	}
	if _, err := RunWindowOpenAt("", 60, 360, at(3, 0)); err == nil {
		t.Error("empty tz should error (no window configured)")
	}
}
