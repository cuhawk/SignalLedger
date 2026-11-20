package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func Test429PartialPagesSchemaDriftAndReplay(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("missing bearer")
		}
		if hits == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[{"id":"late","createdDateTime":"2025-01-01T02:00:00Z","unexpected":123},{"id":"drift","createdDateTime":false}]}`)
			return
		}
		if hits > 3 && !strings.Contains(r.URL.Query().Get("$filter"), "2025-01-01T00:00:00Z") {
			t.Error("expected 24-hour overlap")
		}
		fmt.Fprint(w, `{"value":[{"id":"new","createdDateTime":"2025-01-02T00:00:00Z","userId":"u1"}],"@odata.nextLink":"?page=2"}`)
	}))
	defer server.Close()
	var delays []time.Duration
	feed := Feed{Vendor: EntraSignIn, URL: server.URL + "/logs", HTTP: HTTP{Token: "fixture", Sleep: func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		return nil
	}}}
	dir := t.TempDir()
	ctx := context.Background()
	if err := Poll(ctx, dir, feed, time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	if err := Poll(ctx, dir, feed, time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	if err := Poll(ctx, dir, feed, time.Time{}, 2); err != nil {
		t.Fatal(err)
	}
	if len(delays) != 1 || delays[0] < 2*time.Second || delays[0] >= 2250*time.Millisecond {
		t.Fatalf("unexpected delays %v", delays)
	}
	for n, want := range []struct{ events, dup, rejected int }{{1, 0, 0}, {1, 0, 1}, {0, 1, 0}, {0, 1, 1}} {
		data, err := os.ReadFile(filepath.Join(dir, batchName(n+1)))
		if err != nil {
			t.Fatal(err)
		}
		var got Batch
		if err = json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Events) != want.events || got.Duplicates != want.dup || got.Rejected != want.rejected {
			t.Fatalf("batch %d: %+v", n, got)
		}
	}
}

func TestVendorNormalization(t *testing.T) {
	cases := []struct {
		vendor Vendor
		raw    string
		class  int
		kind   string
		scope  string
	}{
		{EntraAudit, `{"id":"audit","activityDateTime":"2025-01-01T00:00:00Z","activityDisplayName":"Update user","result":"success"}`, 3001, "account_change", ""},
		{Workspace, `{"id":{"time":"2025-01-01T00:00:00Z","uniqueQualifier":"1"},"events":[{"name":"login_failure"}]}`, 3002, "login", ""},
		{Calendar, `{"id":{"time":"2025-01-01T00:00:00Z","uniqueQualifier":"1"},"events":[{"name":"change_calendar_acl_rule","parameters":[{"name":"scope_type","value":"default"}]}]}`, 6003, "share", "public_share"},
		{Notion, `{"id":"1","timestamp":"2025-01-01T00:00:00Z","action":"page.shared","details":{"visibility":"public"}}`, 6003, "share", "public_share"},
	}
	for _, tc := range cases {
		t.Run(string(tc.vendor), func(t *testing.T) {
			events, err := normalize(tc.vendor, []byte(tc.raw))
			if err != nil || len(events) != 1 || events[0].Class != tc.class || events[0].Details.Kind != tc.kind || events[0].Details.Scope != tc.scope || len(events[0].PayloadHash) != 64 {
				t.Fatalf("unexpected %v: %v", events, err)
			}
		})
	}
}
