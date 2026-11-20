package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const allowedLateness = 24 * time.Hour

type Checkpoint struct {
	HighWater time.Time `json:"high_water"`
	ScanSince time.Time `json:"scan_since"`
	Cursor    string    `json:"cursor"`
}

type Batch struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Events     []Event    `json:"events"`
	Rejected   int        `json:"rejected"`
	TooLate    int        `json:"too_late"`
	Duplicates int        `json:"duplicates"`
}

// Poll commits each page as a JSONL batch. Use one directory per tenant/feed.
// An fsynced batch includes both the accepted events and their next cursor.
func Poll(ctx context.Context, dir string, connector Connector, initial time.Time, maxPages int) error {
	if maxPages <= 0 {
		return errors.New("maxPages must be positive")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another collector owns the journal: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	seen := map[[2]string]bool{}
	checkpoint := Checkpoint{}
	var sequence int
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		sequence++
		if entry.Name() != batchName(sequence) {
			return errors.New("journal sequence gap")
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		var batch Batch
		if err = json.Unmarshal(data, &batch); err != nil {
			return err
		}
		checkpoint = batch.Checkpoint
		for _, e := range batch.Events {
			seen[[2]string{e.Metadata.UID, e.PayloadHash}] = true
		}
	}
	if checkpoint.Cursor == "" {
		checkpoint.ScanSince = initial.UTC()
		if !checkpoint.HighWater.IsZero() {
			checkpoint.ScanSince = maxTime(checkpoint.ScanSince, checkpoint.HighWater.Add(-allowedLateness))
		}
	}
	cursors := map[string]bool{checkpoint.Cursor: true}
	for range maxPages {
		page, err := connector.Fetch(ctx, checkpoint.ScanSince, checkpoint.Cursor)
		if err != nil {
			return err
		}
		if page.Next != "" && cursors[page.Next] {
			return errors.New("repeated pagination cursor")
		}
		cursors[page.Next] = true
		batch := Batch{Checkpoint: checkpoint, Rejected: page.Rejected}
		batch.Checkpoint.Cursor = page.Next
		for _, e := range page.Events {
			t := time.UnixMilli(e.Time).UTC()
			if t.Before(checkpoint.ScanSince) {
				batch.TooLate++
				continue
			}
			key := [2]string{e.Metadata.UID, e.PayloadHash}
			if seen[key] {
				batch.Duplicates++
				continue
			}
			seen[key] = true
			batch.Events = append(batch.Events, e)
			batch.Checkpoint.HighWater = maxTime(batch.Checkpoint.HighWater, t)
		}
		sequence++
		if err = commit(dir, sequence, batch); err != nil {
			return err
		}
		checkpoint = batch.Checkpoint
		if page.Next == "" {
			return nil
		}
	}
	return nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func batchName(n int) string { return fmt.Sprintf("%020d.jsonl", n) }

func commit(dir string, n int, batch Batch) error {
	f, err := os.CreateTemp(dir, ".batch-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	writeErr := json.NewEncoder(f).Encode(batch)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err = errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, batchName(n))); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
