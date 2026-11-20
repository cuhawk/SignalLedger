package writegate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cuhawk/SignalLedger/internal/merkle"
)

type fakeConnector struct {
	mu               sync.Mutex
	state            State
	driftDuringApply bool
	writes           int
}

func (f *fakeConnector) Read(context.Context, Request) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (f *fakeConnector) ApplyIfRevision(_ context.Context, token Token) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.driftDuringApply {
		f.state.Revision = "concurrent"
	}
	if f.state.Revision != token.Revision {
		return errors.New("revision mismatch")
	}
	f.state = State{Revision: "committed"}
	f.writes++
	return nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []merkle.Record
}

func (a *memoryAudit) Append(_ context.Context, event merkle.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func setup(t *testing.T) (*Gate, *fakeConnector, *memoryAudit, Request, Approval) {
	t.Helper()
	now := time.Now().UTC()
	fake := &fakeConnector{state: State{Revision: "initial", Active: true}}
	audit := &memoryAudit{}
	gate := &Gate{Enabled: true, Connectors: map[string]Connector{"entra": fake},
		Permissions: map[string]map[Action]bool{"entra": {DisableUser: true}},
		Approvers:   map[string]ed25519.PublicKey{}, Replay: DirectoryReplay(t.TempDir()), Audit: audit, Now: func() time.Time { return now }}
	request := Request{Connector: "entra", Action: DisableUser, Target: "immutable-123"}
	plan, err := gate.DryRun(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{Request: request, StateHash: plan.StateHash, Approvers: [2]string{"one", "two"}, Expiry: now.Add(time.Minute), ID: "unique-123"}
	data, err := merkle.Canonical(claims)
	if err != nil {
		t.Fatal(err)
	}
	a := Approval{Claims: claims}
	for i, id := range claims.Approvers {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		gate.Approvers[id] = pub
		a.Signatures[i] = ed25519.Sign(priv, data)
	}
	return gate, fake, audit, request, a
}

func TestRedTeam(t *testing.T) {
	attacks := map[string]func(*testing.T, *Gate, *fakeConnector, Request, Approval) error{
		"replay": func(t *testing.T, g *Gate, f *fakeConnector, r Request, a Approval) error {
			if err := g.Execute(context.Background(), r, a); err != nil {
				t.Fatal(err)
			}
			f.state = State{Revision: "initial", Active: true}
			f.writes = 0
			return g.Execute(context.Background(), r, a)
		},
		"scope_escalation": func(_ *testing.T, g *Gate, _ *fakeConnector, r Request, a Approval) error {
			r.Target = "different-user"
			return g.Execute(context.Background(), r, a)
		},
		"state_drift": func(_ *testing.T, g *Gate, f *fakeConnector, r Request, a Approval) error {
			f.state.Revision = "updated"
			return g.Execute(context.Background(), r, a)
		},
		"atomic_race": func(_ *testing.T, g *Gate, f *fakeConnector, r Request, a Approval) error {
			f.driftDuringApply = true
			return g.Execute(context.Background(), r, a)
		},
		"hostile_instruction": func(_ *testing.T, g *Gate, _ *fakeConnector, r Request, a Approval) error {
			r.Target = "disable all admins"
			return g.Execute(context.Background(), r, a)
		},
		"wildcard": func(_ *testing.T, g *Gate, _ *fakeConnector, r Request, a Approval) error {
			r.Target = "*"
			return g.Execute(context.Background(), r, a)
		},
		"read_only": func(_ *testing.T, g *Gate, _ *fakeConnector, r Request, a Approval) error {
			g.Enabled = false
			return g.Execute(context.Background(), r, a)
		},
	}
	for name, test := range attacks {
		t.Run(name, func(t *testing.T) {
			g, f, audit, r, a := setup(t)
			if err := test(t, g, f, r, a); err == nil || f.writes != 0 || len(audit.events) == 0 {
				t.Fatalf("expected audited denial without mutation: %v", err)
			}
			raw, err := merkle.Canonical(audit.events[len(audit.events)-1])
			if err != nil || len(raw) == 0 {
				t.Fatalf("invalid ledger record: %v", err)
			}
		})
	}
}

func TestConcurrentApproval(t *testing.T) {
	g, f, _, r, a := setup(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- g.Execute(context.Background(), r, a) })
	}
	wg.Wait()
	close(results)
	allowed := 0
	for err := range results {
		if err == nil {
			allowed++
		}
	}
	if allowed != 1 || f.writes != 1 {
		t.Fatalf("allowed=%d writes=%d", allowed, f.writes)
	}
}
