package updater

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type downloadResult struct {
	artifactPath       string
	size               int64
	reqURL             *url.URL
	finalURL           *url.URL
	contentDisposition string
	contentType        string
}

func (u *Updater) downloadArtifact(
	ctx context.Context,
	workDir string,
	kernel string,
	version string,
	reqURL *url.URL,
	expectedSHA256 []byte,
	hasExpectedSHA256 bool,
) (downloadResult, error) {
	dlCtx, cancel := context.WithTimeout(ctx, u.opts.DownloadTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(dlCtx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return downloadResult{}, fmt.Errorf("updater: build download request: %w", err)
	}
	httpReq.Header.Set("User-Agent", "snell-panel-agent/1.0")

	resp, err := u.opts.HTTPClient.Do(httpReq)
	if err != nil {
		return downloadResult{}, fmt.Errorf("updater: download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippetBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		snippet := strings.TrimSpace(string(snippetBytes))
		if snippet == "" {
			return downloadResult{}, fmt.Errorf("updater: download returned HTTP %d", resp.StatusCode)
		}
		return downloadResult{}, fmt.Errorf("updater: download returned HTTP %d: %s", resp.StatusCode, snippet)
	}

	if resp.ContentLength > u.opts.MaxDownloadBytes {
		return downloadResult{}, fmt.Errorf("updater: download content-length %d exceeds max limit %d", resp.ContentLength, u.opts.MaxDownloadBytes)
	}

	artifactPath := filepath.Join(workDir, "artifact.dl")
	outFile, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return downloadResult{}, fmt.Errorf("updater: create download file: %w", err)
	}

	hasher := sha256.New()
	limitedBody := io.LimitReader(resp.Body, u.opts.MaxDownloadBytes+1)
	written, copyErr := io.Copy(io.MultiWriter(outFile, hasher), limitedBody)
	closeErr := outFile.Close()
	if copyErr != nil {
		return downloadResult{}, fmt.Errorf("updater: stream download failed: %w", copyErr)
	}
	if closeErr != nil {
		return downloadResult{}, fmt.Errorf("updater: close download file: %w", closeErr)
	}

	if written == 0 {
		return downloadResult{}, fmt.Errorf("updater: downloaded artifact is empty (0 bytes)")
	}
	if written > u.opts.MaxDownloadBytes {
		return downloadResult{}, fmt.Errorf("updater: downloaded artifact exceeds max size limit (%d bytes)", u.opts.MaxDownloadBytes)
	}

	if hasExpectedSHA256 {
		u.emitProgress(kernel, version, "verifying", "")
		if err := verifySHA256(hasher.Sum(nil), expectedSHA256); err != nil {
			return downloadResult{}, err
		}
	}

	var finalURL *url.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL
	}

	return downloadResult{
		artifactPath:       artifactPath,
		size:               written,
		reqURL:             reqURL,
		finalURL:           finalURL,
		contentDisposition: resp.Header.Get("Content-Disposition"),
		contentType:        resp.Header.Get("Content-Type"),
	}, nil
}

func verifySHA256(actual []byte, expected []byte) error {
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return fmt.Errorf(
			"updater: sha256 mismatch: expected %s, got %s",
			hex.EncodeToString(expected),
			hex.EncodeToString(actual),
		)
	}
	return nil
}
