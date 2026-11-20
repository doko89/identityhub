package http

import (
	"testing"
	"time"

	"github.com/identityhub/identityhub/internal/domain"
)

// The per-app "open in new tab" flag travels the same road as the other
// catalog fields: request overlay on create/update, appJSON on every read.
func TestAdminAppRequest_OpenInNewTab(t *testing.T) {
	on := true
	if got := (adminAppRequest{OpenInNewTab: &on}).applyTo(domain.Application{}); !got.OpenInNewTab {
		t.Fatal("applyTo did not set OpenInNewTab")
	}
	if kept := (adminAppRequest{}).applyTo(domain.Application{OpenInNewTab: true}); !kept.OpenInNewTab {
		t.Fatal("applyTo cleared OpenInNewTab on omitted key")
	}
}

func TestAppJSON_OpenInNewTab(t *testing.T) {
	if out := appJSON(domain.Application{OpenInNewTab: true}); out["open_in_new_tab"] != true {
		t.Fatalf("appJSON = %v, want open_in_new_tab true", out)
	}
	if out := appJSON(domain.Application{}); out["open_in_new_tab"] != false {
		t.Fatalf("appJSON = %v, want open_in_new_tab false", out)
	}
}

func TestMyAppJSON_UsageFields(t *testing.T) {
	out := myAppJSON(domain.Application{}, false, nil)
	if out["is_favorite"] != false {
		t.Fatalf("myAppJSON = %v, want is_favorite false", out)
	}
	if out["last_launched_at"] != nil {
		t.Fatalf("myAppJSON = %v, want last_launched_at nil", out)
	}
	at := time.Date(2026, 11, 20, 12, 30, 0, 0, time.UTC)
	out = myAppJSON(domain.Application{}, true, &at)
	if out["is_favorite"] != true {
		t.Fatalf("myAppJSON = %v, want is_favorite true", out)
	}
	if out["last_launched_at"] != "2026-11-20T12:30:00Z" {
		t.Fatalf("myAppJSON = %v, want RFC3339 timestamp", out)
	}
}
