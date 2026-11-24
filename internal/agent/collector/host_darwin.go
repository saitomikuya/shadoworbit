//go:build darwin

package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func platformCPUPercent(ctx context.Context) float64 {
	cmdCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(cmdCtx, "ps", "-A", "-o", "%cpu").Output()
	if err != nil {
		return 0
	}
	var sum float64
	scanner := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.Contains(strings.ToUpper(line), "CPU") {
				continue
			}
		}
		v, err := strconv.ParseFloat(line, 64)
		if err != nil || v < 0 {
			continue
		}
		sum += v
	}
	cores := runtime.NumCPU()
	if cores <= 0 {
		cores = 1
	}
	pct := sum / float64(cores)
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	return pct
}

func platformMemory(ctx context.Context) (used, total uint64) {
	total = darwinTotalRAM()
	if total == 0 {
		return 0, 0
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(cmdCtx, "vm_stat").Output()
	if err != nil {
		return 0, total
	}

	pageSize := uint64(os.Getpagesize())
	if pageSize == 0 {
		pageSize = 4096
	}

	var active, wired, compressor uint64
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "page size of ") {
			if idx := strings.Index(line, "page size of "); idx >= 0 {
				rest := line[idx+len("page size of "):]
				if fields := strings.Fields(rest); len(fields) > 0 {
					if ps, err := strconv.ParseUint(fields[0], 10, 64); err == nil && ps > 0 {
						pageSize = ps
					}
				}
			}
			continue
		}
		key, valStr, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		valStr = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(valStr), "."))
		pages, err := strconv.ParseUint(valStr, 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Pages active":
			active = pages
		case "Pages wired down":
			wired = pages
		case "Pages occupied by compressor":
			compressor = pages
		}
	}

	used = (active + wired + compressor) * pageSize
	if used > total {
		used = total
	}
	return used, total
}

func darwinTotalRAM() uint64 {
	raw, err := syscall.Sysctl("hw.memsize")
	if err != nil || len(raw) == 0 {
		return 0
	}
	// syscall.Sysctl strips a trailing NUL byte, so copy into a zero-padded 8-byte buffer.
	var buf [8]byte
	copy(buf[:], raw)
	return binary.LittleEndian.Uint64(buf[:])
}

func platformUptime() uint64 {
	raw, err := syscall.Sysctl("kern.boottime")
	if err != nil || len(raw) < 8 {
		return 0
	}
	bootSec := int64(binary.LittleEndian.Uint64([]byte(raw[:8])))
	now := time.Now().Unix()
	if bootSec <= 0 || now <= bootSec {
		return 0
	}
	return uint64(now - bootSec)
}
