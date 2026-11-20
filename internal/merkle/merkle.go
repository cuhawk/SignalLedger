// Package merkle creates and verifies signed evidence windows.
package merkle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrEmpty = errors.New("FAIL_EMPTY_WINDOW")

type Hash [32]byte

type Record struct {
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	Data any       `json:"data"`
}

type Statement struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	SignedAt time.Time `json:"signed_at"`
	Count    int       `json:"count"`
	Root     Hash      `json:"root"`
	Controls []string  `json:"controls"`
}

type SignedRoot struct {
	Statement Statement `json:"statement"`
	Signature []byte    `json:"signature"`
}

type Proof struct {
	Index int    `json:"index"`
	Path  []Hash `json:"path"`
}

func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func hashLeaf(leaf []byte) Hash { return sha256.Sum256(append([]byte{0}, leaf...)) }
func hashNode(left, right Hash) Hash {
	var data [65]byte
	data[0] = 1
	copy(data[1:33], left[:])
	copy(data[33:], right[:])
	return sha256.Sum256(data[:])
}

func split(n int) int {
	k := 1
	for k <= (n-1)/2 {
		k *= 2
	}
	return k
}

func root(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return hashNode(root(leaves[:k]), root(leaves[k:]))
}

type branch struct {
	hash        Hash
	size        int
	left, right *branch
}

func makeTree(leaves []Hash) *branch {
	if len(leaves) == 1 {
		return &branch{hash: leaves[0], size: 1}
	}
	k := split(len(leaves))
	left, right := makeTree(leaves[:k]), makeTree(leaves[k:])
	return &branch{hash: hashNode(left.hash, right.hash), size: len(leaves), left: left, right: right}
}

func (b *branch) proof(i int) []Hash {
	if b.size == 1 {
		return nil
	}
	if i < b.left.size {
		return append(b.left.proof(i), b.right.hash)
	}
	return append(b.right.proof(i-b.left.size), b.left.hash)
}

func recordHash(raw json.RawMessage, start, end time.Time) (Hash, error) {
	var record struct {
		Time time.Time
		Kind string
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return Hash{}, err
	}
	if err = json.Unmarshal(canonical, &record); err != nil {
		return Hash{}, err
	}
	if record.Kind == "" || record.Time.Before(start) || !record.Time.Before(end) {
		return Hash{}, errors.New("invalid evidence record or timestamp outside window")
	}
	return hashLeaf(canonical), nil
}

func Collect(records []json.RawMessage, start, end, now time.Time, key ed25519.PrivateKey) (SignedRoot, []Proof, error) {
	if len(records) == 0 {
		return SignedRoot{}, nil, ErrEmpty
	}
	if !start.Before(end) || now.Before(end) || len(key) != ed25519.PrivateKeySize {
		return SignedRoot{}, nil, errors.New("invalid window or signing key")
	}
	leaves := make([]Hash, len(records))
	for i, record := range records {
		h, err := recordHash(record, start, end)
		if err != nil {
			return SignedRoot{}, nil, fmt.Errorf("record %d: %w", i, err)
		}
		leaves[i] = h
	}
	tree := makeTree(leaves)
	s := Statement{Start: start.UTC(), End: end.UTC(), SignedAt: now.UTC(), Count: len(leaves), Root: tree.hash,
		Controls: []string{"SOC 2 CC6.1", "SOC 2 CC7.2", "SOC 2 CC8.1", "ISO 27001:2022 A.5.15", "ISO 27001:2022 A.8.15", "ISO 27001:2022 A.8.16"}}
	data, err := Canonical(s)
	if err != nil {
		return SignedRoot{}, nil, err
	}
	proofs := make([]Proof, len(leaves))
	for i := range proofs {
		proofs[i] = Proof{Index: i, Path: tree.proof(i)}
	}
	return SignedRoot{Statement: s, Signature: ed25519.Sign(key, data)}, proofs, nil
}

func verifyRoot(s SignedRoot, key ed25519.PublicKey) error {
	if s.Statement.Count == 0 {
		return ErrEmpty
	}
	if s.Statement.Count < 0 || !s.Statement.Start.Before(s.Statement.End) || s.Statement.SignedAt.Before(s.Statement.End) {
		return errors.New("invalid signed window")
	}
	data, err := Canonical(s.Statement)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid signature")
	}
	return nil
}

func Verify(s SignedRoot, p Proof, record json.RawMessage, key ed25519.PublicKey) error {
	if err := verifyRoot(s, key); err != nil {
		return err
	}
	if p.Index < 0 || p.Index >= s.Statement.Count {
		return errors.New("invalid proof index")
	}
	h, err := recordHash(record, s.Statement.Start, s.Statement.End)
	if err != nil {
		return err
	}
	index, n := p.Index, s.Statement.Count
	var left []bool
	for n > 1 {
		k := split(n)
		left = append(left, index < k)
		if index < k {
			n = k
		} else {
			index -= k
			n -= k
		}
	}
	if len(left) != len(p.Path) {
		return errors.New("invalid proof size")
	}
	slices.Reverse(left)
	for i, sibling := range p.Path {
		if left[i] {
			h = hashNode(h, sibling)
		} else {
			h = hashNode(sibling, h)
		}
	}
	if h != s.Statement.Root {
		return errors.New("inclusion proof mismatch")
	}
	return nil
}

func VerifyWindow(s SignedRoot, records []json.RawMessage, key ed25519.PublicKey) error {
	if err := verifyRoot(s, key); err != nil {
		return err
	}
	if len(records) != s.Statement.Count {
		return errors.New("window count mismatch")
	}
	leaves := make([]Hash, len(records))
	for i, record := range records {
		h, err := recordHash(record, s.Statement.Start, s.Statement.End)
		if err != nil {
			return err
		}
		leaves[i] = h
	}
	if computed := root(leaves); !bytes.Equal(computed[:], s.Statement.Root[:]) {
		return errors.New("window root mismatch")
	}
	return nil
}
