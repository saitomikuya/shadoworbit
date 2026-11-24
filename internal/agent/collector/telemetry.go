package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func (c *Collector) readCPUPercent(ctx context.Context) float64 {
	raw, err := os.ReadFile(c.opts.ProcStatPath)
	if err == nil {
		total, idle, ok := parseProcStatCPU(raw)
		if !ok {
			return 0
		}
		c.cpuMu.Lock()
		defer c.cpuMu.Unlock()

		if !c.hasLastCPU {
			c.hasLastCPU = true
			c.lastCPUTotal = total
			c.lastCPUIdle = idle
			c.lastCPUPercent = 0
			return 0
		}
		if total < c.lastCPUTotal || idle < c.lastCPUIdle {
			c.lastCPUTotal = total
			c.lastCPUIdle = idle
			c.lastCPUPercent = 0
			return 0
		}
		deltaTotal := total - c.lastCPUTotal
		deltaIdle := idle - c.lastCPUIdle
		if deltaTotal == 0 {
			return c.lastCPUPercent
		}
		var pct float64
		if deltaTotal > deltaIdle {
			pct = float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0
		}
		if pct < 0 {
			pct = 0
		} else if pct > 100 {
			pct = 100
		}
		c.lastCPUTotal = total
		c.lastCPUIdle = idle
		c.lastCPUPercent = pct
		return pct
	}

	if errors.Is(err, os.ErrNotExist) && runtime.GOOS == "darwin" && c.opts.ProcStatPath == defaultProcStatPath {
		return platformCPUPercent(ctx)
	}
	return 0
}

func parseProcStatCPU(data []byte) (total, idle uint64, ok bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// Fields: cpu user nice system idle [iowait irq softirq steal ...]
		if len(fields) < 5 {
			return 0, 0, false
		}
		limit := len(fields)
		if limit > 9 {
			// Exclude guest and guest_nice (fields[9], fields[10]), already accounted in user/nice.
			limit = 9
		}
		var sum uint64
		for i := 1; i < limit; i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			sum += v
			if i == 4 || i == 5 { // idle + iowait
				idle += v
			}
		}
		return sum, idle, true
	}
	return 0, 0, false
}

func (c *Collector) readMemory(ctx context.Context) (used, total uint64) {
	raw, err := os.ReadFile(c.opts.ProcMeminfoPath)
	if err == nil {
		if u, t, ok := parseProcMeminfo(raw); ok {
			return u, t
		}
		return 0, 0
	}

	if errors.Is(err, os.ErrNotExist) && runtime.GOOS == "darwin" && c.opts.ProcMeminfoPath == defaultProcMeminfoPath {
		return platformMemory(ctx)
	}
	return 0, 0
}

func parseProcMeminfo(data []byte) (used, total uint64, ok bool) {
	var (
		memTotal     uint64
		memAvailable uint64
		hasAvailable bool
		memFree      uint64
		buffers      uint64
		cached       uint64
		sReclaimable uint64
	)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		val, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		valBytes := val * 1024
		switch key {
		case "MemTotal":
			memTotal = valBytes
		case "MemAvailable":
			memAvailable = valBytes
			hasAvailable = true
		case "MemFree":
			memFree = valBytes
		case "Buffers":
			buffers = valBytes
		case "Cached":
			cached = valBytes
		case "SReclaimable":
			sReclaimable = valBytes
		}
	}

	if memTotal == 0 {
		return 0, 0, false
	}
	avail := memAvailable
	if !hasAvailable {
		avail = memFree + buffers + cached + sReclaimable
	}
	if avail > memTotal {
		avail = memTotal
	}
	return memTotal - avail, memTotal, true
}

func (c *Collector) readUptime() uint64 {
	raw, err := os.ReadFile(c.opts.ProcUptimePath)
	if err == nil {
		if u, ok := parseProcUptime(raw); ok {
			return u
		}
		return 0
	}

	if errors.Is(err, os.ErrNotExist) && runtime.GOOS == "darwin" && c.opts.ProcUptimePath == defaultProcUptimePath {
		return platformUptime()
	}
	return 0
}

func parseProcUptime(data []byte) (uint64, bool) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, false
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(secs) || math.IsInf(secs, 0) || secs < 0 {
		return 0, false
	}
	return uint64(secs), true
}

func (c *Collector) readDiskUsedPercent() float64 {
	pct, err := diskUsedPercent(c.opts.DiskPath)
	if err != nil {
		return 0
	}
	return pct
}
