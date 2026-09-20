package main

import (
	"testing"
	"time"
)

func TestSelectedHistoryRangeDefaultsToOneDay(t *testing.T) {
	if got := selectedHistoryRange("not-a-range"); got != 24*time.Hour {
		t.Errorf("unknown range = %s, want 24h", got)
	}
	if got := selectedHistoryRange("year"); got != 365*24*time.Hour {
		t.Errorf("year range = %s, want 365 days", got)
	}
}

func TestAddWeekHourSecondsUsesActualWindowBounds(t *testing.T) {
	start := time.Date(2026, time.January, 5, 10, 30, 0, 0, time.Local) // Monday
	end := start.Add(105 * time.Minute)
	var buckets [7][24]float64
	addWeekHourSeconds(&buckets, start.Unix(), end.Unix())

	if got := buckets[time.Monday][10]; got != 30*60 {
		t.Errorf("Monday 10:00 = %.0f seconds, want 1800", got)
	}
	if got := buckets[time.Monday][11]; got != 60*60 {
		t.Errorf("Monday 11:00 = %.0f seconds, want 3600", got)
	}
	if got := buckets[time.Monday][12]; got != 15*60 {
		t.Errorf("Monday 12:00 = %.0f seconds, want 900", got)
	}
}
