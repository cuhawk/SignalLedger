// Package compliance evaluates narrowly scoped auditor evidence against a fixed control catalog.
package compliance

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/cuhawk/SignalLedger/internal/detect"
	"github.com/cuhawk/SignalLedger/internal/merkle"
	"github.com/cuhawk/SignalLedger/internal/writegate"
)

const (
	pass = "PASS"
	fail = "FAIL"
)

type Result struct {
	Framework          string   `json:"framework"`
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Posture            string   `json:"posture"`
	MerkleVerification string   `json:"merkle_verification"`
	VerifiedDetections int      `json:"verified_detections"`
	VerifiedApprovals  int      `json:"verified_approvals"`
	Reasons            []string `json:"reasons"`
}

type Report struct {
	SchemaVersion      int              `json:"schema_version"`
	Window             merkle.Statement `json:"window"`
	WindowSignature    []byte           `json:"window_signature"`
	WindowVerification string           `json:"window_verification"`
	VerifiedRecords    int              `json:"verified_records"`
	Controls           []Result         `json:"controls"`
}

func FindingRecord(f detect.Finding) merkle.Record {
	return merkle.Record{Time: time.UnixMilli(f.TimeMS).UTC(), Kind: "ocsf_detection", Data: f}
}

type auditRecord struct {
	Time time.Time
	Kind string
	Data json.RawMessage
}

type outcome struct {
	Request writegate.Request
	ID      string `json:"approval_id"`
	Result  string
}

type outcomeRecord struct {
	time time.Time
	data outcome
}

type receipt struct {
	time time.Time
	data writegate.ApprovalReceipt
}

func approvals(records []auditRecord, keys map[string]ed25519.PublicKey) (verified, invalid int) {
	receipts := make(map[string][]receipt)
	outcomes := make(map[string][]outcomeRecord)
	ids := make(map[string]bool)
	for _, record := range records {
		switch record.Kind {
		case "connector_write_authorized":
			var data writegate.ApprovalReceipt
			if json.Unmarshal(record.Data, &data) != nil || data.ID == "" {
				invalid++
				continue
			}
			ids[data.ID] = true
			receipts[data.ID] = append(receipts[data.ID], receipt{record.Time, data})
		case "connector_write":
			var data outcome
			if json.Unmarshal(record.Data, &data) != nil || data.ID == "" {
				invalid++
				continue
			}
			ids[data.ID] = true
			outcomes[data.ID] = append(outcomes[data.ID], outcomeRecord{record.Time, data})
		}
	}
	for id := range ids {
		if len(receipts[id]) != 1 || len(outcomes[id]) != 1 {
			invalid++
			continue
		}
		r, end := receipts[id][0], outcomes[id][0]
		data := end.data
		approval := writegate.Approval{Claims: r.data.Claims, Signatures: r.data.Signatures}
		if data.Result != "verified" || end.time.Before(r.time) ||
			writegate.VerifyApproval(data.Request, approval, keys, r.time) != nil {
			invalid++
			continue
		}
		verified++
	}
	return verified, invalid
}

// Evaluate verifies the whole window against a separately trusted log key. Findings
// must come from the trusted Parquet query run for the supplied window.
func Evaluate(root merkle.SignedRoot, records []json.RawMessage, logKey ed25519.PublicKey, approverKeys map[string]ed25519.PublicKey, findings []detect.Finding) Report {
	report := Report{SchemaVersion: 1, Window: root.Statement, WindowSignature: root.Signature, WindowVerification: fail}
	signedFindings := make(map[detect.Finding]bool)
	var audit []auditRecord
	var logged int
	if merkle.VerifyWindow(root, records, logKey) == nil {
		report.WindowVerification = pass
		report.VerifiedRecords = len(records)
		for _, raw := range records {
			var record auditRecord
			_ = json.Unmarshal(raw, &record) // VerifyWindow checked record shape and timestamps.
			if record.Kind == "ocsf_detection" || record.Kind == "connector_write_authorized" || record.Kind == "connector_write" {
				logged++
			}
			if record.Kind == "ocsf_detection" {
				var finding detect.Finding
				if json.Unmarshal(record.Data, &finding) == nil && finding.Rule != "" && finding.EventID != "" && record.Time.Equal(FindingRecord(finding).Time) {
					signedFindings[finding] = true
				}
			}
			audit = append(audit, record)
		}
	}
	verified, invalid := approvals(audit, approverKeys)
	findingsByRule := make(map[detect.Finding]bool)
	for _, f := range findings {
		t := FindingRecord(f).Time
		if !t.Before(root.Statement.Start) && t.Before(root.Statement.End) {
			findingsByRule[f] = signedFindings[f]
		}
	}
	for _, c := range controls {
		result := Result{Framework: c.framework, ID: c.id, Title: c.title, Posture: fail, MerkleVerification: fail, Reasons: []string{}}
		switch {
		case !c.logging && !c.approval && len(c.rules) == 0:
			result.Reasons = append(result.Reasons, "no_mapped_evidence")
		case report.WindowVerification != pass:
			result.Reasons = append(result.Reasons, "signed_window_verification_failed")
		default:
			result.MerkleVerification = pass
			if c.missingEvidence != "" {
				result.Reasons = append(result.Reasons, c.missingEvidence)
			}
			if c.logging && logged == 0 {
				result.MerkleVerification = fail
				result.Reasons = append(result.Reasons, "mapped_log_record_required")
			}
			if len(c.rules) > 0 {
				missing := false
				for f, signed := range findingsByRule {
					if slices.Contains(c.rules, f.Rule) {
						if signed {
							result.VerifiedDetections++
						} else {
							missing = true
						}
					}
				}
				if missing {
					result.MerkleVerification = fail
					result.Reasons = append(result.Reasons, "detection_missing_from_signed_window")
				}
				if result.VerifiedDetections == 0 {
					result.MerkleVerification = fail
					result.Reasons = append(result.Reasons, "verified_detection_required")
				}
			}
			if c.approval {
				result.VerifiedApprovals = verified
				if invalid > 0 {
					result.Reasons = append(result.Reasons, "unverified_or_unapproved_write")
				}
				if verified == 0 {
					result.MerkleVerification = fail
					result.Reasons = append(result.Reasons, "verified_approval_required")
				}
			}
			if len(result.Reasons) == 0 {
				result.Posture = pass
			}
		}
		report.Controls = append(report.Controls, result)
	}
	return report
}

func (r Report) WriteMarkdown(w io.Writer) error {
	var lines = "# Auditor posture\n\nPASS applies to the mapped evidence checks for this window.\n\n"
	lines += fmt.Sprintf("Window: %s to %s (exclusive)\n\nSigned root: `%x`\n\nWindow verification: **%s** (%d verified records)\n\n",
		r.Window.Start.Format(time.RFC3339Nano), r.Window.End.Format(time.RFC3339Nano), r.Window.Root, r.WindowVerification, r.VerifiedRecords)
	lines += "| Framework | Control | Posture | Merkle verification | Verified detections | Verified approvals | Reasons |\n| --- | --- | --- | --- | ---: | ---: | --- |\n"
	for _, c := range r.Controls {
		lines += fmt.Sprintf("| %s | %s %s | %s | %s | %d | %d | %v |\n",
			c.Framework, c.ID, c.Title, c.Posture, c.MerkleVerification, c.VerifiedDetections, c.VerifiedApprovals, c.Reasons)
	}
	_, err := io.WriteString(w, lines)
	return err
}
