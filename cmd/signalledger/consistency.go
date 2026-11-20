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

func consistencyCommand(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	oldPath := flags.String("old-root", "", "prior trusted signed root JSON")
	newPath := flags.String("new-root", "", "candidate signed root JSON")
	keyPath := flags.String("pubkey", "", "trusted Ed25519 public key as a JSON base64 string")
	var input *string
	if command == "prove-consistency" {
		input = flags.String("window", "", "candidate head's ordered records as a JSON array")
	} else {
		input = flags.String("proof", "", "consistency proof JSON")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *oldPath == "" || *newPath == "" || *keyPath == "" || *input == "" {
		return errors.New("provide old-root, new-root, pubkey and the proof or window input")
	}
	var older, newer merkle.SignedRoot
	var key []byte
	if err := read(*oldPath, &older); err != nil {
		return err
	}
	if err := read(*newPath, &newer); err != nil {
		return err
	}
	if err := read(*keyPath, &key); err != nil {
		return err
	}
	var proof merkle.ConsistencyProof
	if command == "prove-consistency" {
		var records []json.RawMessage
		if err := read(*input, &records); err != nil {
			return err
		}
		var err error
		proof, err = merkle.ProveConsistency(older.Statement.Count, newer, records)
		if err != nil {
			return err
		}
	} else if err := read(*input, &proof); err != nil {
		return err
	}
	if err := merkle.VerifyConsistency(older, newer, proof, ed25519.PublicKey(key)); err != nil {
		return err
	}
	if command == "prove-consistency" {
		return json.NewEncoder(os.Stdout).Encode(proof)
	}
	fmt.Println("PASS")
	return nil
}
