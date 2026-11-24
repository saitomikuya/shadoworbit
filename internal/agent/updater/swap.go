package updater

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type swapState struct {
	hadOriginal bool
	backupPath  string
	backupMode  os.FileMode
}

func stageBinary(extractedPath string, targetBinary string) (string, error) {
	targetDir := filepath.Dir(targetBinary)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("updater: create target directory %q: %w", targetDir, err)
	}

	stageFile, err := os.CreateTemp(targetDir, "."+filepath.Base(targetBinary)+".stage-*")
	if err != nil {
		return "", fmt.Errorf("updater: create staging file in %q: %w", targetDir, err)
	}
	stagePath := stageFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(stagePath)
		}
	}()

	src, err := os.Open(extractedPath)
	if err != nil {
		_ = stageFile.Close()
		return "", fmt.Errorf("updater: open extracted binary: %w", err)
	}
	_, copyErr := io.Copy(stageFile, src)
	srcCloseErr := src.Close()
	syncErr := stageFile.Sync()
	chmodErr := stageFile.Chmod(0o755)
	closeErr := stageFile.Close()

	if copyErr != nil {
		return "", fmt.Errorf("updater: copy to staging file: %w", copyErr)
	}
	if srcCloseErr != nil {
		return "", fmt.Errorf("updater: close extracted binary: %w", srcCloseErr)
	}
	if syncErr != nil {
		return "", fmt.Errorf("updater: sync staging file: %w", syncErr)
	}
	if chmodErr != nil {
		return "", fmt.Errorf("updater: chmod staging file: %w", chmodErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("updater: close staging file: %w", closeErr)
	}

	cleanup = false
	return stagePath, nil
}

func atomicSwap(stagePath string, targetBinary string) (swapState, error) {
	var state swapState
	targetDir := filepath.Dir(targetBinary)

	origInfo, statErr := os.Lstat(targetBinary)
	switch {
	case statErr == nil:
		state.hadOriginal = true
		state.backupMode = origInfo.Mode().Perm() | 0o755
		state.backupPath = targetBinary + ".bak"
		if err := copyFileAtomic(targetBinary, state.backupPath, targetDir, "."+filepath.Base(targetBinary)+".bak.tmp-*", state.backupMode); err != nil {
			return swapState{}, fmt.Errorf("updater: create backup %q: %w", state.backupPath, err)
		}
	case os.IsNotExist(statErr):
		state.hadOriginal = false
		state.backupMode = 0o755
	default:
		return swapState{}, fmt.Errorf("updater: stat target binary %q: %w", targetBinary, statErr)
	}

	if err := os.Rename(stagePath, targetBinary); err != nil {
		return swapState{}, fmt.Errorf("updater: atomic rename %q -> %q: %w", stagePath, targetBinary, err)
	}
	return state, nil
}

func restoreBackup(targetBinary string, state swapState) error {
	if !state.hadOriginal {
		if err := os.Remove(targetBinary); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove newly installed binary %q: %w", targetBinary, err)
		}
		return nil
	}

	mode := state.backupMode | 0o755
	targetDir := filepath.Dir(targetBinary)
	if err := copyFileAtomic(state.backupPath, targetBinary, targetDir, "."+filepath.Base(targetBinary)+".rb.tmp-*", mode); err != nil {
		return fmt.Errorf("restore %q from %q: %w", targetBinary, state.backupPath, err)
	}
	return nil
}

func copyFileAtomic(srcPath string, dstPath string, tmpDir string, tmpPattern string, mode os.FileMode) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	tmpFile, err := os.CreateTemp(tmpDir, tmpPattern)
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	_, copyErr := io.Copy(tmpFile, src)
	syncErr := tmpFile.Sync()
	chmodErr := tmpFile.Chmod(mode)
	closeErr := tmpFile.Close()

	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if chmodErr != nil {
		return chmodErr
	}
	if closeErr != nil {
		return closeErr
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}
