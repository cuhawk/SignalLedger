package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cuhawk/SignalLedger/internal/merkle"
)

func read(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	canonical, err := merkle.Canonical(json.RawMessage(data))
	if err != nil {
		return err
	}
	return json.Unmarshal(canonical, v)
}

func verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := flags.String("root", "", "signed root JSON")
	proof := flags.String("proof", "", "inclusion proof JSON")
	leaf := flags.String("leaf", "", "evidence record JSON")
	key := flags.String("pubkey", "", "trusted Ed25519 public key as a JSON base64 string")
	window := flags.String("window", "", "complete window as a JSON array")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *root == "" || *key == "" || (*window != "" && (*proof != "" || *leaf != "")) || (*window == "" && (*proof == "" || *leaf == "")) {
		return errors.New("provide root and pubkey plus either window or both proof and leaf")
	}
	var s merkle.SignedRoot
	var pub []byte
	if err := read(*root, &s); err != nil {
		return err
	}
	if err := read(*key, &pub); err != nil {
		return err
	}
	if *window != "" {
		var records []json.RawMessage
		if err := read(*window, &records); err != nil {
			return err
		}
		return merkle.VerifyWindow(s, records, ed25519.PublicKey(pub))
	}
	var p merkle.Proof
	if err := read(*proof, &p); err != nil {
		return err
	}
	raw, err := os.ReadFile(*leaf)
	if err != nil {
		return err
	}
	return merkle.Verify(s, p, raw, ed25519.PublicKey(pub))
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: signalledger {ingest|detect|collect|verify|prove-consistency|verify-consistency}")
	}
	switch args[0] {
	case "prove-consistency", "verify-consistency":
		return consistencyCommand(args[0], args[1:])
	case "verify":
		if err := verify(args[1:]); err != nil {
			return err
		}
		fmt.Println("PASS")
		return nil
	case "ingest":
		return ingestCommand(args[1:])
	case "detect":
		return detectCommand(args[1:])
	case "collect":
		return collectCommand(args[1:])
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
