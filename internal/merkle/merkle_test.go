package merkle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTamper(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	record := func(ts time.Time, label string) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(Record{Time: ts, Kind: "heartbeat", Data: label})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	a, b, c := record(start, "alpha"), record(start, "bravo"), record(start, "charlie")
	records := []json.RawMessage{a, b, c}
	s, proofs, err := Collect(records, start, end, end, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyWindow(s, records, pub); err != nil {
		t.Fatal(err)
	}
	for i, p := range proofs {
		if err = Verify(s, p, records[i], pub); err != nil {
			t.Fatal(err)
		}
	}
	changed := append(json.RawMessage(nil), a...)
	changed[len(changed)-3] ^= 1
	forged := s
	forged.Signature = append([]byte(nil), s.Signature...)
	forged.Signature[0] ^= 1
	tests := map[string]func() error{
		"byte_flip":        func() error { return Verify(s, proofs[0], changed, pub) },
		"reorder":          func() error { return VerifyWindow(s, []json.RawMessage{b, a, c}, pub) },
		"delete":           func() error { return VerifyWindow(s, records[:2], pub) },
		"adjacent_window":  func() error { return Verify(s, proofs[0], record(end, "alpha"), pub) },
		"forged_signature": func() error { return Verify(forged, proofs[0], a, pub) },
		"empty_window": func() error {
			_, _, err := Collect(nil, start, end, end, key)
			if !errors.Is(err, ErrEmpty) {
				t.Fatalf("expected FAIL_EMPTY_WINDOW, got %v", err)
			}
			return VerifyWindow(SignedRoot{}, nil, pub)
		},
	}
	for name, attack := range tests {
		t.Run(name, func(t *testing.T) {
			if err := attack(); err == nil {
				t.Fatal("tampered evidence verified")
			}
		})
	}
}

func TestCanonicalAndDomainSeparation(t *testing.T) {
	canonical, err := Canonical(json.RawMessage(`{ "z":-0.0, "a":1e0, "s":"\u0061" }`))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"a":1,"s":"a","z":0}` {
		t.Fatalf("canonical form: %s", canonical)
	}
	left := sha256.Sum256([]byte("\x00a"))
	right := sha256.Sum256([]byte("\x00b"))
	data := append([]byte{1}, left[:]...)
	data = append(data, right[:]...)
	if hashLeaf([]byte("a")) != left || root([]Hash{left, right}) != sha256.Sum256(data) {
		t.Fatal("invalid RFC 6962 hash")
	}
}
