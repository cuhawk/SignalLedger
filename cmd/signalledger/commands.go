package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"github.com/cuhawk/SignalLedger/internal/detect"
	"github.com/cuhawk/SignalLedger/internal/ingest"
	"github.com/cuhawk/SignalLedger/internal/merkle"
)

func ingestCommand(args []string) error {
	f := flag.NewFlagSet("ingest", flag.ContinueOnError)
	vendor := f.String("vendor", "", "entra-signin, entra-audit, workspace, calendar or notion")
	endpoint := f.String("url", "", "trusted vendor audit endpoint")
	dir := f.String("journal", "", "tenant/feed journal directory")
	since := f.String("since", "", "initial RFC3339 timestamp")
	pages := f.Int("pages", 50, "maximum pages per poll")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *vendor == "" || *endpoint == "" || *dir == "" || *since == "" || f.NArg() != 0 {
		return errors.New("provide vendor, url, journal and since")
	}
	initial, err := time.Parse(time.RFC3339Nano, *since)
	if err != nil {
		return err
	}
	feed := ingest.Feed{Vendor: ingest.Vendor(*vendor), URL: *endpoint, HTTP: ingest.HTTP{Token: os.Getenv("SIGNALLEDGER_AUDIT_TOKEN")}}
	return ingest.Poll(context.Background(), *dir, feed, initial, *pages)
}

func detectCommand(args []string) error {
	f := flag.NewFlagSet("detect", flag.ContinueOnError)
	bundle := f.String("queries", "", "trusted compiled SQL bundle")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *bundle == "" || f.NArg() != 0 {
		return errors.New("provide queries")
	}
	input, err := os.Open(*bundle)
	if err != nil {
		return err
	}
	defer input.Close()
	queries, err := detect.ReadQueries(input)
	if err != nil {
		return err
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return err
	}
	defer db.Close()
	findings, err := detect.Run(context.Background(), db, queries)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(findings)
}

func collectCommand(args []string) error {
	f := flag.NewFlagSet("collect", flag.ContinueOnError)
	window := f.String("window", "", "evidence records as a JSON array")
	journal := f.String("journal", "", "evidence journal directory")
	private := f.String("private-key", "", "Ed25519 private key as a JSON base64 string")
	begin := f.String("start", "", "inclusive RFC3339 window start")
	finish := f.String("end", "", "exclusive RFC3339 window end")
	if err := f.Parse(args); err != nil {
		return err
	}
	if (*window == "") == (*journal == "") || *private == "" || f.NArg() != 0 {
		return errors.New("provide exactly one of window or journal, and private-key, start and end")
	}
	start, err := time.Parse(time.RFC3339Nano, *begin)
	if err != nil {
		return err
	}
	end, err := time.Parse(time.RFC3339Nano, *finish)
	if err != nil {
		return err
	}
	var records []json.RawMessage
	if *window != "" {
		if err = read(*window, &records); err != nil {
			return err
		}
	} else {
		records, err = merkle.Journal(*journal).Window(start, end)
		if err != nil {
			return err
		}
	}
	var key []byte
	if err = read(*private, &key); err != nil {
		return err
	}
	root, proofs, err := merkle.Collect(records, start, end, time.Now(), key)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Root    merkle.SignedRoot `json:"root"`
		Proofs  []merkle.Proof    `json:"proofs"`
		Records []json.RawMessage `json:"records"`
	}{root, proofs, records})
}
