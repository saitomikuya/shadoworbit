package collector

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type procNetDevEntry struct {
	iface   string
	rxBytes uint64
	txBytes uint64
}

func (c *Collector) pollNIC() error {
	raw, err := os.ReadFile(c.opts.ProcNetDevPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && runtime.GOOS == "darwin" && c.opts.ProcNetDevPath == defaultProcNetDevPath {
			return nil
		}
		return fmt.Errorf("read %q: %w", c.opts.ProcNetDevPath, err)
	}

	entries, byName, err := parseProcNetDev(raw)
	if err != nil {
		return fmt.Errorf("parse %q: %w", c.opts.ProcNetDevPath, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no interfaces found in %q", c.opts.ProcNetDevPath)
	}

	iface, err := c.resolveInterface(entries, byName)
	if err != nil {
		return err
	}
	entry, ok := byName[iface]
	if !ok {
		return fmt.Errorf("interface %q not found in %q", iface, c.opts.ProcNetDevPath)
	}

	now := time.Now()
	var rxDelta, txDelta uint64

	c.nicMu.Lock()
	defer c.nicMu.Unlock()

	if !c.hasLastNIC || c.lastIface != iface {
		c.hasLastNIC = true
		c.lastIface = iface
		c.lastNICRx = entry.rxBytes
		c.lastNICTx = entry.txBytes
		c.lastNICTime = now
		c.lastRxBPS = 0
		c.lastTxBPS = 0
		return nil
	}

	if entry.rxBytes >= c.lastNICRx {
		rxDelta = entry.rxBytes - c.lastNICRx
	} else {
		// Counter reset (e.g., host reboot or interface reset): reset baseline cleanly.
		rxDelta = 0
	}

	if entry.txBytes >= c.lastNICTx {
		txDelta = entry.txBytes - c.lastNICTx
	} else {
		txDelta = 0
	}

	if rxDelta > 0 || txDelta > 0 {
		if err := c.addNICDelta(rxDelta, txDelta); err != nil {
			return fmt.Errorf("persist NIC delta: %w", err)
		}
	}

	elapsed := now.Sub(c.lastNICTime).Seconds()
	if elapsed > 0 {
		c.lastRxBPS = uint64(float64(rxDelta) / elapsed)
		c.lastTxBPS = uint64(float64(txDelta) / elapsed)
	} else {
		c.lastRxBPS = 0
		c.lastTxBPS = 0
	}

	c.lastNICRx = entry.rxBytes
	c.lastNICTx = entry.txBytes
	c.lastNICTime = now
	return nil
}

func (c *Collector) resolveInterface(entries []procNetDevEntry, byName map[string]procNetDevEntry) (string, error) {
	if c.opts.Interface != "" {
		if _, ok := byName[c.opts.Interface]; !ok {
			return "", fmt.Errorf("configured interface %q not found in %q", c.opts.Interface, c.opts.ProcNetDevPath)
		}
		return c.opts.Interface, nil
	}

	if routeRaw, err := os.ReadFile(c.opts.ProcNetRoutePath); err == nil {
		if iface, ok := parseDefaultRouteIface(routeRaw, byName); ok {
			return iface, nil
		}
	}

	if ifaces, err := net.Interfaces(); err == nil {
		if iface, ok := pickOSInterface(ifaces, byName); ok {
			return iface, nil
		}
	}

	// Fallback to first non-loopback interface in /proc/net/dev (e.g., synthetic tests on macOS).
	for _, e := range entries {
		if e.iface != "lo" && !isVirtualNoiseIface(e.iface) {
			return e.iface, nil
		}
	}
	for _, e := range entries {
		if e.iface != "lo" {
			return e.iface, nil
		}
	}
	return entries[0].iface, nil
}

func pickOSInterface(ifaces []net.Interface, byName map[string]procNetDevEntry) (string, bool) {
	var fallback string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if _, ok := byName[ifc.Name]; !ok {
			continue
		}
		if hasGlobalUnicastIP(ifc) && ifc.Flags&net.FlagPointToPoint == 0 {
			return ifc.Name, true
		}
		if fallback == "" {
			fallback = ifc.Name
		}
	}
	if fallback != "" {
		return fallback, true
	}
	return "", false
}

func hasGlobalUnicastIP(ifc net.Interface) bool {
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func isVirtualNoiseIface(name string) bool {
	return strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(name, "docker") ||
		strings.HasPrefix(name, "br-") ||
		strings.HasPrefix(name, "virbr")
}

func parseDefaultRouteIface(data []byte, byName map[string]procNetDevEntry) (string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	first := true
	bestIface := ""
	bestMetric := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "Iface") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		if iface == "" || iface == "lo" {
			continue
		}
		if byName != nil {
			if _, ok := byName[iface]; !ok {
				continue
			}
		}
		dest := fields[1]
		mask := fields[7]
		if !strings.EqualFold(dest, "00000000") || !strings.EqualFold(mask, "00000000") {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			metric = 0
		}
		if bestIface == "" || metric < bestMetric {
			bestIface = iface
			bestMetric = metric
		}
	}
	return bestIface, bestIface != ""
}

func parseProcNetDev(data []byte) ([]procNetDevEntry, map[string]procNetDevEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]procNetDevEntry, 0, 4)
	byName := make(map[string]procNetDevEntry, 4)

	for scanner.Scan() {
		line := scanner.Text()
		ifacePart, statsPart, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(ifacePart)
		if iface == "" {
			continue
		}
		fields := strings.Fields(statsPart)
		if len(fields) < 9 {
			continue
		}
		rxBytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parse rx_bytes for %q: %w", iface, err)
		}
		txBytes, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parse tx_bytes for %q: %w", iface, err)
		}
		entry := procNetDevEntry{
			iface:   iface,
			rxBytes: rxBytes,
			txBytes: txBytes,
		}
		entries = append(entries, entry)
		byName[iface] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return entries, byName, nil
}
