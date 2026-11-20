package writegate

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// DirectoryReplay uses atomic file creation on a shared local filesystem.
type DirectoryReplay string

func (d DirectoryReplay) Reserve(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := hex.DecodeString(key); err != nil || key == "" {
		return errors.New("invalid replay key")
	}
	dir, err := os.Open(string(d))
	if err != nil {
		return err
	}
	defer dir.Close()
	file, err := os.OpenFile(filepath.Join(string(d), key), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return errors.Join(file.Close(), dir.Sync())
}
