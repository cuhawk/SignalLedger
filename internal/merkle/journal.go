package merkle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Journal stores immutable evidence records, one atomically published file per record.
type Journal string

func (j Journal) Append(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Time.IsZero() || record.Kind == "" {
		return errors.New("missing evidence time or kind")
	}
	data, err := Canonical(record)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(string(j), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(string(j), ".record-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	name := record.Time.UTC().Format("20060102T150405.000000000Z") + "-" + filepath.Base(f.Name())[len(".record-"):]
	if err = os.Link(f.Name(), filepath.Join(string(j), name+".json")); err != nil {
		return err
	}
	dir, err := os.Open(string(j))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (j Journal) Window(start, end time.Time) ([]json.RawMessage, error) {
	entries, err := os.ReadDir(string(j))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []json.RawMessage
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(string(j), entry.Name()))
		if err != nil {
			return nil, err
		}
		var record struct{ Time time.Time }
		if err = json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		if record.Time.IsZero() {
			return nil, errors.New("journal record missing time")
		}
		if !record.Time.Before(start) && record.Time.Before(end) {
			records = append(records, raw)
		}
	}
	return records, nil
}
