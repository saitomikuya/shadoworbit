//go:build linux || darwin

package collector

import "syscall"

func diskUsedPercent(path string) (float64, error) {
	if path == "" {
		path = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Blocks == 0 {
		return 0, nil
	}
	var used uint64
	if st.Blocks > st.Bfree {
		used = st.Blocks - st.Bfree
	}
	pct := float64(used) / float64(st.Blocks) * 100.0
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	return pct, nil
}
