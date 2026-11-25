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

func (c *Collector) commitWALWriteLocked(next walState, forceSync bool) error {
	syncDisk := forceSync || c.walSyncInterval < 0 || c.lastWALSync.IsZero() || time.Since(c.lastWALSync) >= c.walSyncInterval
	fsyncs, err := writeWALAtomicSync(c.walPath, next, syncDisk)
	if err != nil {
		return err
	}
	c.walWrites.Add(1)
	if fsyncs > 0 {
		c.walFsyncs.Add(int64(fsyncs))
	}
	c.wal = next
	if syncDisk {
		c.lastWALSync = time.Now()
		c.walUnsynced = false
	} else {
		c.walUnsynced = true
	}
	return nil
}

// FlushWAL forces an fsync of the WAL file and its parent directory if there are unsynced writes.
func (c *Collector) FlushWAL() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.walUnsynced {
		return nil
	}
	return c.commitWALWriteLocked(c.wal.clone(), true)
}

// WALStats returns cumulative atomic WAL file write and fsync syscall counts.
func (c *Collector) WALStats() (writes, fsyncs int64) {
	return c.walWrites.Load(), c.walFsyncs.Load()
}

func (c *Collector) addCombinedDeltas(
	rxDelta, txDelta, adminSnellDelta uint64,
	userDeltas map[string]walUserDelta,
	activeUsers map[string]int64,
) error {
	hasUsers := false
	for uname, d := range userDeltas {
		if uname != "" && (d.UpBytes > 0 || d.DownBytes > 0) {
			hasUsers = true
			break
		}
	}
	if rxDelta == 0 && txDelta == 0 && adminSnellDelta == 0 && !hasUsers {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.wal.clone()
	changed := false
	if rxDelta > 0 || txDelta > 0 {
		next.NICRxDelta += rxDelta
		next.NICTxDelta += txDelta
		changed = true
	}
	if adminSnellDelta > 0 {
		next.AdminSnellBytes += adminSnellDelta
		changed = true
	}
	for uname, d := range userDeltas {
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
	return c.commitWALWriteLocked(next, false)
}

func (c *Collector) addNICDelta(rxDelta, txDelta uint64) error {
	return c.addCombinedDeltas(rxDelta, txDelta, 0, nil, nil)
}

func (c *Collector) addAdminSnellDelta(delta uint64) error {
	return c.addCombinedDeltas(0, 0, delta, nil, nil)
}

func (c *Collector) addUserDeltas(deltas map[string]walUserDelta, activeUsers map[string]int64) error {
	return c.addCombinedDeltas(0, 0, 0, deltas, activeUsers)
}

func writeWALAtomic(path string, st walState) error {
	_, err := writeWALAtomicSync(path, st, true)
	return err
}

func writeWALAtomicSync(path string, st walState, syncDisk bool) (int, error) {
	st.normalize()
	payload, err := json.Marshal(st)
	if err != nil {
		return 0, fmt.Errorf("marshal WAL: %w", err)
	}
	return writeFileAtomicSync(path, payload, syncDisk)
}

func writeFileAtomic(path string, data []byte) error {
	_, err := writeFileAtomicSync(path, data, true)
	return err
}

func writeFileAtomicSync(path string, data []byte, syncDisk bool) (int, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("create WAL dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("create temp WAL file: %w", err)
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
		return 0, fmt.Errorf("chmod temp WAL file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("write temp WAL file: %w", err)
	}
	fsyncs := 0
	if syncDisk {
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return 0, fmt.Errorf("sync temp WAL file: %w", err)
		}
		fsyncs++
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp WAL file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return 0, fmt.Errorf("rename temp WAL file: %w", err)
	}
	cleanup = false

	if syncDisk {
		// Best-effort directory fsync for crash durability.
		if d, err := os.Open(dir); err == nil {
			if err := d.Sync(); err == nil {
				fsyncs++
			}
			_ = d.Close()
		}
	}
	return fsyncs, nil
}

func subClamped(cur, sub uint64) uint64 {
	if cur >= sub {
		return cur - sub
	}
	return 0
}
