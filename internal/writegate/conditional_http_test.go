package writegate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestConditionalHTTP(t *testing.T) {
	var state sync.Mutex
	revision, active := "\"v1\"", true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		defer state.Unlock()
		if r.URL.Path != "/entra/disable_user/user-1" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer reader" {
				t.Error("missing read credential")
			}
			w.Header().Set("ETag", revision)
			fmt.Fprintf(w, `{"active":%t}`, active)
		case http.MethodPatch:
			if r.Header.Get("Authorization") != "Bearer scoped" || r.Header.Get("Idempotency-Key") != "id1" {
				t.Error("missing scoped credential or idempotency key")
			}
			if r.Header.Get("If-Match") != revision {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			active = false
			revision = "\"v2\""
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()
	request := Request{Connector: "entra", Action: DisableUser, Target: "user-1"}
	client := ConditionalHTTP{BaseURL: server.URL, Client: server.Client(), ReadBearer: "reader", Mint: func(_ context.Context, token Token) (string, error) {
		if token.Request != request {
			t.Error("credential scope mismatch")
		}
		return "scoped", nil
	}}
	ctx := context.Background()
	before, err := client.Read(ctx, request)
	if err != nil || !before.Active {
		t.Fatalf("read before: %+v %v", before, err)
	}
	token := Token{Request: request, Revision: "\"stale\"", Expires: time.Now().Add(30 * time.Second), Key: "id1"}
	if err = client.ApplyIfRevision(ctx, token); err == nil {
		t.Fatal("stale revision committed")
	}
	token.Revision = before.Revision
	if err = client.ApplyIfRevision(ctx, token); err != nil {
		t.Fatal(err)
	}
	after, err := client.Read(ctx, request)
	if err != nil || after.Active || before.Revision == after.Revision {
		t.Fatalf("readback: %+v %v", after, err)
	}
}
