package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReducedDeviceAndStatusIncludeLastSeen(t *testing.T) {
	deviceJSON, err := json.Marshal(PublicDevice{ID: 1, Name: "Office", LastSeen: 1234567890})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(deviceJSON), `"last_seen":1234567890`) {
		t.Errorf("reduced device does not include last_seen: %s", deviceJSON)
	}

	statusJSON, err := json.Marshal(deviceStatus{LastSeen: 1234567890, OnlineSince: 1234567000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(statusJSON), `"last_seen":1234567890`) {
		t.Errorf("status does not include last_seen: %s", statusJSON)
	}
	if !strings.Contains(string(statusJSON), `"online_since":1234567000`) {
		t.Errorf("status does not include online_since: %s", statusJSON)
	}
}
