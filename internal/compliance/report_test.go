package compliance

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/cuhawk/SignalLedger/internal/detect"
	"github.com/cuhawk/SignalLedger/internal/merkle"
	"github.com/cuhawk/SignalLedger/internal/writegate"
)

func TestPosture(t *testing.T) {
	stamp := time.Unix(1700000000, 0).UTC()
	log := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := make(map[string]ed25519.PublicKey)
	signers := make([]ed25519.PrivateKey, 2)
	for i, id := range []string{"alice", "bob"} {
		var seed [32]byte
		seed[0] = byte(i + 1)
		signers[i] = ed25519.NewKeyFromSeed(seed[:])
		keys[id] = signers[i].Public().(ed25519.PublicKey)
	}
	finding := detect.Finding{Rule: "token_replay", EventID: "one", TimeMS: stamp.UnixMilli()}
	request := writegate.Request{Connector: "test", Action: writegate.DisableUser, Target: "one"}
	claims := writegate.Claims{Request: request, StateHash: "example", Approvers: [2]string{"alice", "bob"}, Expiry: stamp.Add(time.Minute), ID: "approval"}
	canonical, err := merkle.Canonical(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, oversight, window string
		coverage, records       int
	}{
		{"verified", pass, pass, 8, 3},
		{"missing", fail, pass, 3, 1},
		{"unapproved", fail, pass, 3, 3},
		{"invalid_approval_signature", fail, pass, 3, 3},
		{"invalid_window", fail, fail, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evidence := []merkle.Record{FindingRecord(finding)}
			if tc.name != "missing" {
				result := "verified"
				receipt := writegate.ApprovalReceipt{Claims: claims,
					Signatures: [2][]byte{ed25519.Sign(signers[0], canonical), ed25519.Sign(signers[1], canonical)}}
				switch tc.name {
				case "unapproved":
					result = "read-only"
				case "invalid_approval_signature":
					receipt.Signatures[1][0] ^= 1
				}
				evidence = append(evidence,
					merkle.Record{Time: stamp, Kind: "connector_write_authorized", Data: receipt},
					merkle.Record{Time: stamp, Kind: "connector_write", Data: map[string]any{
						"request": request, "approval_id": claims.ID, "result": result,
					}})
			}
			var raw []json.RawMessage
			for _, record := range evidence {
				data, err := merkle.Canonical(record)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, data)
			}
			root, _, err := merkle.Collect(raw, stamp, stamp.Add(time.Second), stamp.Add(time.Second), log)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "invalid_window" {
				root.Signature[0] ^= 1
			}
			report := Evaluate(root, raw, log.Public().(ed25519.PublicKey), keys, []detect.Finding{finding})
			if report.WindowVerification != tc.window || report.VerifiedRecords != tc.records || len(report.Controls) != 27 {
				t.Fatalf("window verification = %s, verified records = %d, controls = %d", report.WindowVerification, report.VerifiedRecords, len(report.Controls))
			}
			count := 0
			for _, c := range report.Controls {
				if c.Posture == pass {
					count++
				}
				if c.ID == "Article 14" && (c.Posture != tc.oversight || c.MerkleVerification != tc.oversight) {
					t.Fatalf("oversight = %+v", c)
				}
			}
			if count != tc.coverage {
				t.Fatalf("passing controls = %d, want %d", count, tc.coverage)
			}
		})
	}
}
