package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/cuhawk/SignalLedger/internal/compliance"
	"github.com/cuhawk/SignalLedger/internal/merkle"
)

func complianceCommand(args []string) error {
	if len(args) == 0 || args[0] != "report" {
		return errors.New("usage: signalledger compliance report")
	}
	f := flag.NewFlagSet("compliance report", flag.ContinueOnError)
	bundle := f.String("bundle", "", "signed evidence bundle from collect")
	queries := f.String("queries", "", "trusted compiled Parquet detection queries")
	pubkey := f.String("pubkey", "", "trusted Ed25519 log public key as a JSON base64 string")
	approvers := f.String("approver-keys", "", "JSON mapping of trusted approver IDs to base64 Ed25519 public keys")
	format := f.String("format", "json", "json or markdown")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *bundle == "" || *queries == "" || *pubkey == "" ||
		(*format != "json" && *format != "markdown") {
		return errors.New("provide bundle, queries and pubkey, with format json or markdown")
	}
	var evidence struct {
		Root    merkle.SignedRoot
		Records []json.RawMessage
	}
	if err := read(*bundle, &evidence); err != nil {
		return err
	}
	var key []byte
	if err := read(*pubkey, &key); err != nil {
		return err
	}
	var people map[string]ed25519.PublicKey
	if *approvers != "" {
		if err := read(*approvers, &people); err != nil {
			return err
		}
	}
	findings, err := runDetections(context.Background(), *queries)
	if err != nil {
		return err
	}
	report := compliance.Evaluate(evidence.Root, evidence.Records, key, people, findings)
	if *format == "markdown" {
		return report.WriteMarkdown(os.Stdout)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
