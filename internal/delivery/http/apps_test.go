package http

import (
	"testing"

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
