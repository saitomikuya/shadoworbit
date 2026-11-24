package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const currentWALVersion = 1

type walState struct {
	Version         int                     `json:"version"`
	NICRxDelta      uint64                  `json:"nic_rx_delta"`
	NICTxDelta      uint64                  `json:"nic_tx_delta"`
	AdminSnellBytes uint64                  `json:"admin_snell_bytes,omitempty"`
	UserDeltas      map[string]walUserDelta `json:"user_deltas"`
}

type walUserDelta struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	UpBytes   uint64 `json:"up_bytes"`
	DownBytes uint64 `json:"down_bytes"`
}

func newEmptyWAL() walState {
	return walState{
		Version:    currentWALVersion,
		UserDeltas: make(map[string]walUserDelta),
	}
}

func (w walState) clone() walState {
	out := walState{
		Version:         w.Version,
		NICRxDelta:      w.NICRxDelta,
		NICTxDelta:      w.NICTxDelta,
		AdminSnellBytes: w.AdminSnellBytes,
		UserDeltas:      make(map[string]walUserDelta, len(w.UserDeltas)),
	}
	if out.Version == 0 {
		out.Version = currentWALVersion
	}
	for k, v := range w.UserDeltas {
		out.UserDeltas[k] = v
	}
	return out
}

func (w *walState) normalize() {
	if w.Version == 0 {
		w.Version = currentWALVersion
	}
	if w.UserDeltas == nil {
		w.UserDeltas = make(map[string]walUserDelta)
		return
	}
	for k, v := range w.UserDeltas {
		uname := v.Username
		if uname == "" {
			uname = k
		}
		if uname == "" || (v.UpBytes == 0 && v.DownBytes == 0) {
			delete(w.UserDeltas, k)
			continue
		}
		if v.Username == "" {
			v.Username = uname
			w.UserDeltas[k] = v
		}
	}
}

func (c *Collector) loadWAL() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.walPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.wal = newEmptyWAL()
			return nil
		}
		return fmt.Errorf("read WAL %q: %w", c.walPath, err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		if qErr := c.quarantineCorruptWALLocked(errors.New("empty or null WAL payload")); qErr != nil {
			return qErr
		}
		c.wal = newEmptyWAL()
		return nil
	}

	var loaded walState
	if err := json.Unmarshal(trimmed, &loaded); err != nil {
		if qErr := c.quarantineCorruptWALLocked(err); qErr != nil {
			return qErr
		}
		c.wal = newEmptyWAL()
		return nil
	}

	loaded.normalize()
	c.wal = loaded
	return nil
}

func (c *Collector) quarantineCorruptWALLocked(cause error) error {
	corruptPath := fmt.Sprintf("%s.corrupt.%d", c.walPath, time.Now().UnixNano())
	if err := os.Rename(c.walPath, corruptPath); err != nil {
		return fmt.Errorf("quarantine corrupt WAL %q (%v): %w", c.walPath, cause, err)
	}
	c.logger.Error("quarantined corrupt traffic WAL", "wal_path", c.walPath, "corrupt_path", corruptPath, "error", cause)
	return nil
}

func (c *Collector) addNICDelta(rxDelta, txDelta uint64) error {
	if rxDelta == 0 && txDelta == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.wal.clone()
	next.NICRxDelta += rxDelta
	next.NICTxDelta += txDelta
	if err := writeWALAtomic(c.walPath, next); err != nil {
		return err
	}
	c.wal = next
	return nil
}

func (c *Collector) addAdminSnellDelta(delta uint64) error {
	if delta == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.wal.clone()
	next.AdminSnellBytes += delta
	if err := writeWALAtomic(c.walPath, next); err != nil {
		return err
	}
	c.wal = next
	return nil
}

func (c *Collector) addUserDeltas(deltas map[string]walUserDelta, activeUsers map[string]int64) error {
	if len(deltas) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.wal.clone()
	changed := false
	for uname, d := range deltas {
		if uname == "" || (d.UpBytes == 0 && d.DownBytes == 0) {
			continue
		}
		existing := next.UserDeltas[uname]
		existing.Username = uname
		if existing.UserID == 0 {
			if d.UserID != 0 {
				existing.UserID = d.UserID
			} else if id, ok := activeUsers[uname]; ok && id != 0 {
				existing.UserID = id
			}
		}
		existing.UpBytes += d.UpBytes
		existing.DownBytes += d.DownBytes
		next.UserDeltas[uname] = existing
		changed = true
	}
	if !changed {
		return nil
	}
	if err := writeWALAtomic(c.walPath, next); err != nil {
		return err
	}
	c.wal = next
	return nil
}

func writeWALAtomic(path string, st walState) error {
	st.normalize()
	payload, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal WAL: %w", err)
	}
	return writeFileAtomic(path, payload)
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create WAL dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp WAL file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp WAL file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp WAL file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp WAL file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp WAL file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp WAL file: %w", err)
	}
	cleanup = false

	// Best-effort directory fsync for crash durability.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func subClamped(cur, sub uint64) uint64 {
	if cur >= sub {
		return cur - sub
	}
	return 0
}
