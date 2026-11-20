package merkle

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func consistencyFixture(t *testing.T) ([]json.RawMessage, func([]json.RawMessage, time.Time, time.Time) SignedRoot, ed25519.PublicKey, time.Time, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	var records []json.RawMessage
	for i := range 21 {
		raw, err := json.Marshal(Record{Time: start.Add(time.Minute * time.Duration(i+1)), Kind: "test", Data: i})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, raw)
	}
	sign := func(records []json.RawMessage, begin, finish time.Time) SignedRoot {
		head, _, err := Collect(records, begin, finish, finish, key)
		if err != nil {
			t.Fatal(err)
		}
		return head
	}
	return records, sign, key.Public().(ed25519.PublicKey), start, end
}

func TestConsistencyPrefixes(t *testing.T) {
	records, sign, key, start, end := consistencyFixture(t)
	for n := 1; n <= len(records); n++ {
		newer := sign(records[:n], start, end)
		for m := 1; m <= n; m++ {
			older := sign(records[:m], start, end)
			proof, err := ProveConsistency(m, newer, records[:n])
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(older, newer, proof, key); err != nil {
				t.Fatalf("%d -> %d: %v", m, n, err)
			}
		}
	}
	// RFC 6962 section 2.1.2 diagram for size 3 -> 7.
	newer := sign(records[:7], start, end)
	proof, err := ProveConsistency(3, newer, records[:7])
	if err != nil {
		t.Fatal(err)
	}
	want := []Hash{
		sign(records[2:3], start, end).Statement.Root,
		sign(records[3:4], start, end).Statement.Root,
		sign(records[:2], start, end).Statement.Root,
		sign(records[4:7], start, end).Statement.Root,
	}
	if !slices.Equal(proof.Path, want) {
		t.Fatal("proof differs from RFC 6962 example")
	}
}

func TestConsistencyTamper(t *testing.T) {
	records, sign, key, start, end := consistencyFixture(t)
	older := sign(records[:3], start, end)
	newer := sign(records[:7], start, end.Add(time.Hour))
	proof, err := ProveConsistency(3, newer, records[:7])
	if err != nil || VerifyConsistency(older, newer, proof, key) != nil {
		t.Fatal("valid growth failed", err)
	}
	cases := map[string]func(*SignedRoot, *SignedRoot, *ConsistencyProof){
		"tampered_hash":        func(_, _ *SignedRoot, p *ConsistencyProof) { p.Path[0][0] ^= 1 },
		"reordered_proof":      func(_, _ *SignedRoot, p *ConsistencyProof) { slices.Reverse(p.Path) },
		"truncated_proof":      func(_, _ *SignedRoot, p *ConsistencyProof) { p.Path = p.Path[:len(p.Path)-1] },
		"extra_hash":           func(_, _ *SignedRoot, p *ConsistencyProof) { p.Path = append(p.Path, Hash{}) },
		"forged_old_signature": func(a, _ *SignedRoot, _ *ConsistencyProof) { a.Signature[0] ^= 1 },
		"forged_new_signature": func(_, b *SignedRoot, _ *ConsistencyProof) { b.Signature[0] ^= 1 },
		"rewritten_prefix": func(_, b *SignedRoot, p *ConsistencyProof) {
			changed := slices.Clone(records[:7])
			changed[0], changed[1] = changed[1], changed[0]
			*b = sign(changed, start, end.Add(time.Hour))
			var err error
			*p, err = ProveConsistency(3, *b, changed)
			if err != nil {
				t.Error(err)
			}
		},
		"truncated_log": func(_, b *SignedRoot, p *ConsistencyProof) {
			*b = sign(records[:2], start, end.Add(time.Hour))
			p.Path = nil
		},
		"rollback": func(a, b *SignedRoot, _ *ConsistencyProof) { *a, *b = *b, *a },
		"same_size_fork": func(a, b *SignedRoot, p *ConsistencyProof) {
			*b = sign(records[1:4], start, end.Add(time.Hour))
			p.Path = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := older, newer
			a.Signature, b.Signature = slices.Clone(a.Signature), slices.Clone(b.Signature)
			p := ConsistencyProof{Path: slices.Clone(proof.Path)}
			mutate(&a, &b, &p)
			if err := VerifyConsistency(a, b, p, key); err == nil {
				t.Fatal("accepted invalid append-only history")
			}
		})
	}
}
