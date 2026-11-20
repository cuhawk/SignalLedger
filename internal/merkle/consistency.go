package merkle

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

// ConsistencyProof contains the RFC 6962 section 2.1.2 SUBPROOF hashes.
// The two signed heads supply the sizes and roots.
type ConsistencyProof struct {
	Path []Hash `json:"path"`
}

// ProveConsistency constructs a prefix proof from the newer head's ordered
// records. The new head's root is checked against the supplied records.
func ProveConsistency(oldCount int, newer SignedRoot, records []json.RawMessage) (ConsistencyProof, error) {
	if oldCount <= 0 || oldCount > len(records) || newer.Statement.Count != len(records) {
		return ConsistencyProof{}, errors.New("invalid consistency proof sizes")
	}
	leaves := make([]Hash, len(records))
	for i, raw := range records {
		h, err := recordHash(raw, newer.Statement.Start, newer.Statement.End)
		if err != nil {
			return ConsistencyProof{}, err
		}
		leaves[i] = h
	}
	if root(leaves) != newer.Statement.Root {
		return ConsistencyProof{}, errors.New("new tree root mismatch")
	}
	return ConsistencyProof{Path: subproof(oldCount, leaves, true)}, nil
}

func subproof(m int, leaves []Hash, complete bool) []Hash {
	if m == len(leaves) {
		if complete {
			return nil
		}
		return []Hash{root(leaves)}
	}
	k := split(len(leaves))
	if m <= k {
		return append(subproof(m, leaves[:k], complete), root(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), root(leaves[:k]))
}

// VerifyConsistency verifies the signatures and the prefix relation from a
// previously trusted head to a candidate head for the same cumulative window.
func VerifyConsistency(older, newer SignedRoot, proof ConsistencyProof, key ed25519.PublicKey) error {
	if err := verifyRoot(older, key); err != nil {
		return err
	}
	if err := verifyRoot(newer, key); err != nil {
		return err
	}
	old, next := older.Statement, newer.Statement
	if !old.Start.Equal(next.Start) || next.End.Before(old.End) ||
		next.SignedAt.Before(old.SignedAt) || next.Count < old.Count {
		return errors.New("signed tree heads are out of order or from different windows")
	}
	path := proof.Path
	first, second, ok := consistencyRoots(old.Count, next.Count, true, old.Root, &path)
	if !ok || len(path) != 0 || first != old.Root || second != next.Root {
		return errors.New("consistency proof mismatch")
	}
	return nil
}

func consistencyRoots(m, n int, complete bool, old Hash, path *[]Hash) (Hash, Hash, bool) {
	if m == n && complete {
		return old, old, true
	}
	if m == n {
		h, ok := takeHash(path)
		return h, h, ok
	}
	k := split(n)
	if m <= k {
		first, second, ok := consistencyRoots(m, k, complete, old, path)
		sibling, present := takeHash(path)
		return first, hashNode(second, sibling), ok && present
	}
	first, second, ok := consistencyRoots(m-k, n-k, false, old, path)
	sibling, present := takeHash(path)
	return hashNode(sibling, first), hashNode(sibling, second), ok && present
}

func takeHash(path *[]Hash) (Hash, bool) {
	if len(*path) == 0 {
		return Hash{}, false
	}
	h := (*path)[0]
	*path = (*path)[1:]
	return h, true
}
