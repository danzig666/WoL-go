package main

import (
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// The state of every computer is sampled once a minute. Only state *changes*
// are stored - an unchanged state extends the open interval - so two years of
// history for a machine is a few thousand rows, not a million.
const historyInterval = time.Minute

// History is kept for three years, comfortably beyond the promised two.
const historyRetention = 3 * 365 * 24 * time.Hour

// A gap longer than this (the app was not running) closes the open interval
// rather than extending it, so downtime of the tracker is never mistaken for
// continuous coverage of the machine.
const historyGapLimit = 3 * historyInterval

// startHistoryTracker begins the background sampling loop.
func startHistoryTracker() {
	go func() {
		// A first sample right away, so a fresh start has data immediately.
		trackOnce()
		ticker := time.NewTicker(historyInterval)
		defer ticker.Stop()

		lastPrune := time.Now()
		for range ticker.C {
			trackOnce()
			if time.Since(lastPrune) > 24*time.Hour {
				pruneHistory()
				lastPrune = time.Now()
			}
		}
	}()
	log.Printf("Tracking computer states every %s (kept for %d days)",
		historyInterval, int(historyRetention.Hours()/24))
}

// trackOnce samples every device and records the result.
func trackOnce() {
	devices, err := loadDevices()
	if err != nil {
		log.Printf("History: could not load devices: %v", err)
		return
	}
	if len(devices) == 0 {
		return
	}

	statuses := computeStatuses(devices, false)
	now := time.Now().Unix()

	for _, d := range devices {
		state := "unknown" // no IP saved, so nothing can be asked
		if d.IP != "" {
			state = "offline"
			if s, ok := statuses[strconv.FormatInt(d.ID, 10)]; ok {
				switch {
				case s.Online:
					state = "online"
				case s.Asleep:
					state = "asleep"
				}
			}
		}
		recordState(d.ID, state, now)
	}
}

// recordState extends the open interval when nothing changed, and closes it
// and opens a new one when the state moved or the tracker had been away.
func recordState(deviceID int64, state string, now int64) {
	var id int64
	var lastState string
	var endedAt int64
	err := db.QueryRow(
		"SELECT id, state, ended_at FROM device_history WHERE device_id = ? ORDER BY ended_at DESC LIMIT 1",
		deviceID,
	).Scan(&id, &lastState, &endedAt)

	freshGap := err == nil && now-endedAt > int64(historyGapLimit.Seconds())

	if err == nil && lastState == state && !freshGap {
		if _, err := db.Exec("UPDATE device_history SET ended_at = ? WHERE id = ?", now, id); err != nil {
			log.Printf("History: could not extend interval: %v", err)
		}
		return
	}

	if _, err := db.Exec(
		"INSERT INTO device_history (device_id, state, started_at, ended_at) VALUES (?, ?, ?, ?)",
		deviceID, state, now, now,
	); err != nil {
		log.Printf("History: could not record state: %v", err)
	}
}

func pruneHistory() {
	cutoff := time.Now().Add(-historyRetention).Unix()
	if res, err := db.Exec("DELETE FROM device_history WHERE ended_at < ?", cutoff); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("History: pruned %d old interval(s)", n)
		}
	}
	if _, err := db.Exec("DELETE FROM wake_events WHERE at < ?", cutoff); err != nil {
		log.Printf("History: could not prune wake events: %v", err)
	}
}

// recordWake notes who woke which machine, for the activity list.
func recordWake(deviceID int64, actor string) {
	if actor == "" {
		actor = "local network"
	}
	if _, err := db.Exec(
		"INSERT INTO wake_events (device_id, at, actor) VALUES (?, ?, ?)",
		deviceID, time.Now().Unix(), actor,
	); err != nil {
		log.Printf("Could not record wake event: %v", err)
	}
}

// --- Reporting (admin only) ---

type historyInterval2 struct {
	State string `json:"state"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
}

type deviceHistory struct {
	ID         int64              `json:"id"`
	Name       string             `json:"name"`
	Intervals  []historyInterval2 `json:"intervals"`
	OnlinePct  float64            `json:"online_pct"`
	AsleepPct  float64            `json:"asleep_pct"`
	OfflinePct float64            `json:"offline_pct"`
	TrackedPct float64            `json:"tracked_pct"`
	LongestOn  int64              `json:"longest_on"`
	WakeCount  int64              `json:"wake_count"`
}

var historyRanges = map[string]time.Duration{
	"day":   24 * time.Hour,
	"week":  7 * 24 * time.Hour,
	"month": 30 * 24 * time.Hour,
	"year":  365 * 24 * time.Hour,
	"all":   historyRetention,
}

// historyOverview returns, for every computer, its timeline over the chosen
// range plus the numbers the dashboard tiles show.
func historyOverview(c *gin.Context) {
	span, ok := historyRanges[c.DefaultQuery("range", "day")]
	if !ok {
		span = 24 * time.Hour
	}
	now := time.Now().Unix()
	from := now - int64(span.Seconds())

	devices, err := loadDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load your devices"})
		return
	}

	out := make([]deviceHistory, 0, len(devices))
	for _, d := range devices {
		h := deviceHistory{ID: d.ID, Name: d.Name, Intervals: []historyInterval2{}}

		rows, err := db.Query(
			`SELECT state, started_at, ended_at FROM device_history
			 WHERE device_id = ? AND ended_at >= ? ORDER BY started_at`,
			d.ID, from,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the history"})
			return
		}

		var tracked, online, asleep, offline, longestOn int64
		for rows.Next() {
			var iv historyInterval2
			if err := rows.Scan(&iv.State, &iv.From, &iv.To); err != nil {
				continue
			}
			// Clip to the window.
			if iv.From < from {
				iv.From = from
			}
			if iv.To > now {
				iv.To = now
			}
			if iv.To <= iv.From {
				continue
			}
			// A single sample covers one polling step, not an instant, so the
			// last interval is padded to the sampling width for display.
			length := iv.To - iv.From
			if length < int64(historyInterval.Seconds()) {
				length = int64(historyInterval.Seconds())
				if iv.To = iv.From + length; iv.To > now {
					iv.To = now
					length = iv.To - iv.From
				}
			}
			tracked += length
			switch iv.State {
			case "online":
				online += length
				if length > longestOn {
					longestOn = length
				}
			case "asleep":
				asleep += length
			case "offline":
				offline += length
			}
			h.Intervals = append(h.Intervals, iv)
		}
		rows.Close()

		windowLen := now - from
		if tracked > 0 {
			h.OnlinePct = 100 * float64(online) / float64(tracked)
			h.AsleepPct = 100 * float64(asleep) / float64(tracked)
			h.OfflinePct = 100 * float64(offline) / float64(tracked)
		}
		if windowLen > 0 {
			h.TrackedPct = 100 * float64(tracked) / float64(windowLen)
			if h.TrackedPct > 100 {
				h.TrackedPct = 100
			}
		}
		h.LongestOn = longestOn

		if err := db.QueryRow(
			"SELECT COUNT(*) FROM wake_events WHERE device_id = ? AND at >= ?", d.ID, from,
		).Scan(&h.WakeCount); err != nil {
			h.WakeCount = 0
		}

		out = append(out, h)
	}

	c.JSON(http.StatusOK, gin.H{
		"from":    from,
		"to":      now,
		"devices": out,
	})
}

// deviceHeatmap buckets the last 90 days into hour-of-week cells, each holding
// the fraction of that hour the machine was on. It shows the rhythm of a
// machine - workday mornings, evening gaming, always-on - at a glance.
func deviceHeatmap(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}

	now := time.Now()
	from := now.Add(-90 * 24 * time.Hour).Unix()

	rows, err := db.Query(
		`SELECT state, started_at, ended_at FROM device_history
		 WHERE device_id = ? AND ended_at >= ? AND state = 'online' ORDER BY started_at`,
		id, from,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the history"})
		return
	}
	defer rows.Close()

	// onSeconds[weekday][hour], observed[weekday][hour]
	var onSeconds [7][24]float64
	for rows.Next() {
		var state string
		var start, end int64
		if err := rows.Scan(&state, &start, &end); err != nil {
			continue
		}
		if start < from {
			start = from
		}
		// Walk the interval hour by hour, attributing seconds to cells.
		for t := start; t < end; {
			moment := time.Unix(t, 0)
			hourEnd := moment.Truncate(time.Hour).Add(time.Hour).Unix()
			sliceEnd := hourEnd
			if end < sliceEnd {
				sliceEnd = end
			}
			onSeconds[int(moment.Weekday())][moment.Hour()] += float64(sliceEnd - t)
			t = sliceEnd
		}
	}

	// How many times each hour-of-week occurred in the window bounds the
	// fraction; 90 days is ~12-13 of each weekday.
	weeks := 90.0 / 7.0
	grid := make([][]float64, 7)
	for day := 0; day < 7; day++ {
		grid[day] = make([]float64, 24)
		for hour := 0; hour < 24; hour++ {
			fraction := onSeconds[day][hour] / (weeks * 3600)
			if fraction > 1 {
				fraction = 1
			}
			grid[day][hour] = fraction
		}
	}

	c.JSON(http.StatusOK, gin.H{"days": grid})
}

// listWakeEvents returns the recent wake activity, newest first.
func listWakeEvents(c *gin.Context) {
	rows, err := db.Query(
		`SELECT w.at, w.actor, COALESCE(d.name, 'a removed computer')
		 FROM wake_events w LEFT JOIN devices d ON d.id = w.device_id
		 ORDER BY w.at DESC LIMIT 50`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the activity"})
		return
	}
	defer rows.Close()

	type wakeEvent struct {
		At     int64  `json:"at"`
		Actor  string `json:"actor"`
		Device string `json:"device"`
	}
	events := []wakeEvent{}
	for rows.Next() {
		var e wakeEvent
		if err := rows.Scan(&e.At, &e.Actor, &e.Device); err == nil {
			events = append(events, e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].At > events[j].At })
	c.JSON(http.StatusOK, events)
}
