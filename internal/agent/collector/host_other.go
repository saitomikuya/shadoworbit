//go:build !darwin

package collector

import "context"

func platformCPUPercent(context.Context) float64 {
	return 0
}

func platformMemory(context.Context) (uint64, uint64) {
	return 0, 0
}

func platformUptime() uint64 {
	return 0
}
