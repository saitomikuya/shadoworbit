//go:build !linux && !darwin

package collector

func diskUsedPercent(path string) (float64, error) {
	return 0, nil
}
