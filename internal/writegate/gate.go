// Package writegate authorizes narrowly scoped conditional connector mutations.
package writegate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cuhawk/SignalLedger/internal/merkle"
)

type Action string

const (
	RevokeGrant       Action = "revoke_oauth_grant"
	DisableUser       Action = "disable_user"
	RevokeCalendarACL Action = "revoke_calendar_acl"
	QuarantineShare   Action = "quarantine_notion_share"
)

type Request struct {
	Connector string `json:"connector"`
	Action    Action `json:"action"`
	Target    string `json:"target_id"`
}

type State struct {
	Revision string
	Active   bool
	Details  map[string]string
}

type Plan struct {
	Request     Request
	Before      State
	AfterActive bool
	StateHash   string
}

type Claims struct {
	Request   Request
	StateHash string
	Approvers [2]string
	Expiry    time.Time
	ID        string
}

type Approval struct {
	Claims     Claims
	Signatures [2][]byte
}

type Token struct {
	Request  Request
	Revision string
	Expires  time.Time
	Key      string
}

// Connector must atomically match Revision and apply the single scoped action.
// Read-only APIs and APIs without a conditional mutation must return an error.
type Connector interface {
	Read(context.Context, Request) (State, error)
	ApplyIfRevision(context.Context, Token) error
}

// ReplayStore must atomically and durably reserve a key across all gate instances.
type ReplayStore interface {
	Reserve(context.Context, string) error
}

// Audit must durably append the record before returning success.
type Audit interface {
	Append(context.Context, merkle.Record) error
}

type Gate struct {
	Enabled     bool
	Connectors  map[string]Connector
	Permissions map[string]map[Action]bool
	Approvers   map[string]ed25519.PublicKey
	Replay      ReplayStore
	Audit       Audit
	Now         func() time.Time
}

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,254}$`)

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

func (g *Gate) policy(r Request) (Connector, error) {
	if !opaqueID.MatchString(r.Target) || strings.EqualFold(r.Target, "all") || strings.EqualFold(r.Target, "admins") {
		return nil, errors.New("target must be one immutable resource ID")
	}
	switch r.Action {
	case RevokeGrant, DisableUser, RevokeCalendarACL, QuarantineShare:
	default:
		return nil, errors.New("action denied")
	}
	c := g.Connectors[r.Connector]
	if c == nil || !g.Permissions[r.Connector][r.Action] {
		return nil, errors.New("connector policy denied")
	}
	return c, nil
}

func snapshot(ctx context.Context, c Connector, r Request) (Plan, error) {
	state, err := c.Read(ctx, r)
	if err != nil {
		return Plan{}, err
	}
	if state.Revision == "" {
		return Plan{}, errors.New("connector has no conditional revision")
	}
	raw, err := merkle.Canonical(state)
	if err != nil {
		return Plan{}, err
	}
	sum := sha256.Sum256(raw)
	return Plan{Request: r, Before: state, AfterActive: false, StateHash: hex.EncodeToString(sum[:])}, nil
}

func (g *Gate) DryRun(ctx context.Context, r Request) (Plan, error) {
	c, err := g.policy(r)
	if err != nil {
		return Plan{}, err
	}
	return snapshot(ctx, c, r)
}

func (g *Gate) Execute(ctx context.Context, r Request, a Approval) error {
	if g.Audit == nil {
		return errors.New("audit unavailable")
	}
	err := g.execute(ctx, r, a)
	result := "verified"
	if err != nil {
		result = err.Error()
	}
	auditErr := g.Audit.Append(context.WithoutCancel(ctx), merkle.Record{Time: g.now(), Kind: "connector_write", Data: map[string]any{"request": r, "approval_id": a.Claims.ID, "result": result}})
	return errors.Join(err, auditErr)
}

func (g *Gate) execute(ctx context.Context, r Request, a Approval) error {
	if !g.Enabled {
		return errors.New("read-only")
	}
	c, err := g.policy(r)
	if err != nil {
		return err
	}
	claims := a.Claims
	now := g.now()
	if claims.Request != r || !opaqueID.MatchString(claims.ID) || !claims.Expiry.After(now) || claims.Expiry.After(now.Add(5*time.Minute)) {
		return errors.New("approval scope or expiry invalid")
	}
	if claims.Approvers[0] == claims.Approvers[1] {
		return errors.New("two distinct approvers required")
	}
	first, second := g.Approvers[claims.Approvers[0]], g.Approvers[claims.Approvers[1]]
	if len(first) != ed25519.PublicKeySize || len(second) != ed25519.PublicKeySize || first.Equal(second) {
		return errors.New("two distinct trusted approval keys required")
	}
	raw, err := merkle.Canonical(claims)
	if err != nil {
		return err
	}
	if !ed25519.Verify(first, raw, a.Signatures[0]) || !ed25519.Verify(second, raw, a.Signatures[1]) {
		return errors.New("invalid approval signatures")
	}
	plan, err := snapshot(ctx, c, r)
	if err != nil {
		return err
	}
	if plan.StateHash != claims.StateHash {
		return errors.New("target state drift")
	}
	if g.Replay == nil {
		return errors.New("replay store unavailable")
	}
	key := hex.EncodeToString([]byte(claims.ID))
	if err = g.Replay.Reserve(ctx, key); err != nil {
		return fmt.Errorf("approval reservation: %w", err)
	}
	now = g.now()
	if !claims.Expiry.After(now) {
		return errors.New("approval expired")
	}
	if !plan.Before.Active {
		return errors.New("target already inactive")
	}
	if err = g.Audit.Append(ctx, merkle.Record{Time: now, Kind: "connector_write_authorized", Data: claims}); err != nil {
		return err
	}
	if !claims.Expiry.After(g.now()) {
		return errors.New("approval expired")
	}
	expiry := now.Add(30 * time.Second)
	if claims.Expiry.Before(expiry) {
		expiry = claims.Expiry
	}
	if !expiry.After(g.now()) {
		return errors.New("execution token expired")
	}
	token := Token{Request: r, Revision: plan.Before.Revision, Expires: expiry, Key: key}
	if err = c.ApplyIfRevision(ctx, token); err != nil {
		return fmt.Errorf("conditional mutation: %w", err)
	}
	after, err := c.Read(ctx, r)
	if err != nil {
		return fmt.Errorf("mutation readback: %w", err)
	}
	if after.Active != plan.AfterActive {
		return errors.New("mutation readback mismatch")
	}
	return nil
}
