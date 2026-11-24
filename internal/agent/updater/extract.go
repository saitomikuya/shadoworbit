package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxArchiveEntries = 10000

type archiveFormat int

const (
	formatUnknown archiveFormat = iota
	formatTarGz
	formatZip
	formatRaw
	formatUnsupported
)

func (u *Updater) extractBinary(workDir string, kernel string, dl downloadResult) (string, error) {
	format, hintDetail, err := detectArtifactFormat(dl)
	if err != nil {
		return "", err
	}

	switch format {
	case formatUnsupported:
		return "", fmt.Errorf("updater: unsupported archive format (%s)", hintDetail)
	case formatRaw:
		if dl.size <= 0 || dl.size > u.opts.MaxExtractBytes {
			return "", fmt.Errorf("updater: raw binary size %d out of bounds (max %d)", dl.size, u.opts.MaxExtractBytes)
		}
		extractedPath := filepath.Join(workDir, kernel+".extracted")
		if err := os.Rename(dl.artifactPath, extractedPath); err != nil {
			return "", fmt.Errorf("updater: prepare raw binary: %w", err)
		}
		if err := os.Chmod(extractedPath, 0o755); err != nil {
			return "", fmt.Errorf("updater: chmod raw binary: %w", err)
		}
		return extractedPath, nil
	case formatTarGz:
		return u.extractTarGz(workDir, kernel, dl.artifactPath)
	case formatZip:
		return u.extractZip(workDir, kernel, dl.artifactPath)
	default:
		return "", errors.New("updater: unable to determine artifact format")
	}
}

func detectArtifactFormat(dl downloadResult) (archiveFormat, string, error) {
	hintFormat, hintSource := detectFormatHints(dl)

	f, err := os.Open(dl.artifactPath)
	if err != nil {
		return formatUnknown, "", fmt.Errorf("updater: open downloaded artifact: %w", err)
	}
	defer f.Close()

	magic := make([]byte, 512)
	n, err := io.ReadFull(f, magic)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return formatUnknown, "", fmt.Errorf("updater: read artifact magic bytes: %w", err)
	}
	magic = magic[:n]

	isGzip := len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b
	isZip := len(magic) >= 4 && magic[0] == 'P' && magic[1] == 'K' &&
		((magic[2] == 0x03 && magic[3] == 0x04) ||
			(magic[2] == 0x05 && magic[3] == 0x06) ||
			(magic[2] == 0x07 && magic[3] == 0x08))

	switch hintFormat {
	case formatUnsupported:
		return formatUnsupported, hintSource, nil
	case formatTarGz:
		if !isGzip {
			return formatUnknown, "", fmt.Errorf("updater: artifact hinted as .tar.gz/.tgz (%s) does not have valid gzip magic bytes", hintSource)
		}
		return formatTarGz, hintSource, nil
	case formatZip:
		if !isZip {
			return formatUnknown, "", fmt.Errorf("updater: artifact hinted as .zip (%s) does not have valid zip magic bytes", hintSource)
		}
		return formatZip, hintSource, nil
	default:
		if isGzip {
			return formatTarGz, "magic:gzip", nil
		}
		if isZip {
			return formatZip, "magic:zip", nil
		}
		return formatRaw, "magic:raw", nil
	}
}

func detectFormatHints(dl downloadResult) (archiveFormat, string) {
	if dl.contentDisposition != "" {
		if _, params, err := mime.ParseMediaType(dl.contentDisposition); err == nil {
			if fname := strings.TrimSpace(params["filename"]); fname != "" {
				fname = strings.ReplaceAll(fname, "\\", "/")
				if fmtHint, desc := classifyFilenameHint(path.Base(fname)); fmtHint != formatUnknown {
					return fmtHint, "content-disposition:" + desc
				}
			}
		}
	}

	if dl.finalURL != nil && dl.finalURL.Path != "" {
		if fmtHint, desc := classifyFilenameHint(path.Base(dl.finalURL.Path)); fmtHint != formatUnknown {
			return fmtHint, "final-url:" + desc
		}
	}

	if dl.reqURL != nil && dl.reqURL.Path != "" {
		if fmtHint, desc := classifyFilenameHint(path.Base(dl.reqURL.Path)); fmtHint != formatUnknown {
			return fmtHint, "request-url:" + desc
		}
	}

	if dl.contentType != "" {
		if mediaType, _, err := mime.ParseMediaType(dl.contentType); err == nil {
			switch strings.ToLower(mediaType) {
			case "application/zip", "application/x-zip-compressed":
				return formatZip, "content-type:" + mediaType
			case "application/gzip", "application/x-gzip", "application/x-gtar", "application/x-compressed-tar":
				return formatTarGz, "content-type:" + mediaType
			}
		}
	}

	return formatUnknown, ""
}

func classifyFilenameHint(name string) (archiveFormat, string) {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "." || lower == "/" {
		return formatUnknown, ""
	}
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return formatTarGz, lower
	case strings.HasSuffix(lower, ".zip"):
		return formatZip, lower
	case strings.HasSuffix(lower, ".tar.xz"),
		strings.HasSuffix(lower, ".txz"),
		strings.HasSuffix(lower, ".tar.bz2"),
		strings.HasSuffix(lower, ".tbz2"),
		strings.HasSuffix(lower, ".7z"),
		strings.HasSuffix(lower, ".rar"),
		strings.HasSuffix(lower, ".tar"),
		strings.HasSuffix(lower, ".gz"):
		return formatUnsupported, lower
	default:
		return formatUnknown, ""
	}
}

func (u *Updater) extractTarGz(workDir string, kernel string, archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("updater: open tar.gz archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("updater: invalid gzip stream: %w", err)
	}
	defer gz.Close()

	maxStream := int64(math.MaxInt64)
	if u.opts.MaxExtractBytes <= (math.MaxInt64-65536)/2 {
		maxStream = u.opts.MaxExtractBytes*2 + 65536
	}
	tr := tar.NewReader(io.LimitReader(gz, maxStream))

	var (
		entries      int
		totalPayload int64
		exactCand    candidateFile
		fallbackCand candidateFile
		candSeq      int
	)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("updater: corrupt tar stream: %w", err)
		}

		entries++
		if entries > maxArchiveEntries {
			return "", fmt.Errorf("updater: archive exceeds max entry count (%d)", maxArchiveEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		case tar.TypeSymlink, tar.TypeLink:
			return "", fmt.Errorf("updater: archive contains forbidden link entry %q", hdr.Name)
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return "", fmt.Errorf("updater: archive contains forbidden special entry %q", hdr.Name)
		case tar.TypeDir, tar.TypeReg, tar.TypeRegA:
		default:
			return "", fmt.Errorf("updater: archive contains unsupported entry type %q for %q", hdr.Typeflag, hdr.Name)
		}

		clean, isDir, err := validateArchiveEntryPath(hdr.Name)
		if err != nil {
			return "", err
		}

		if hdr.Typeflag == tar.TypeDir || isDir {
			if hdr.Size > 0 {
				return "", fmt.Errorf("updater: directory entry %q has non-zero size", hdr.Name)
			}
			continue
		}

		if hdr.Size < 0 || hdr.Size > u.opts.MaxExtractBytes {
			return "", fmt.Errorf("updater: archive entry %q size %d exceeds max extract limit %d", hdr.Name, hdr.Size, u.opts.MaxExtractBytes)
		}
		if totalPayload > u.opts.MaxExtractBytes-hdr.Size {
			return "", fmt.Errorf("updater: archive total uncompressed size exceeds max limit %d", u.opts.MaxExtractBytes)
		}
		totalPayload += hdr.Size

		base := path.Base(clean)
		depth := pathDepth(clean)

		isExact := base == kernel
		isFallback := !isExact && isFallbackBinaryName(kernel, base)
		if !isExact && !isFallback {
			continue
		}

		if isExact && exactCand.valid && !candidateBetter(depth, clean, exactCand) {
			continue
		}
		if isFallback && (exactCand.valid || (fallbackCand.valid && !candidateBetter(depth, clean, fallbackCand))) {
			continue
		}

		candSeq++
		candPath := filepath.Join(workDir, fmt.Sprintf("%s.cand-%d", kernel, candSeq))
		written, err := copyBoundedToFile(candPath, tr, u.opts.MaxExtractBytes)
		if err != nil {
			_ = os.Remove(candPath)
			return "", fmt.Errorf("updater: extract %q: %w", hdr.Name, err)
		}
		if written == 0 {
			_ = os.Remove(candPath)
			continue
		}

		cand := candidateFile{
			valid: true,
			path:  candPath,
			clean: clean,
			depth: depth,
		}
		if isExact {
			if exactCand.valid {
				_ = os.Remove(exactCand.path)
			}
			exactCand = cand
		} else {
			if fallbackCand.valid {
				_ = os.Remove(fallbackCand.path)
			}
			fallbackCand = cand
		}
	}

	chosen := exactCand
	if chosen.valid {
		if fallbackCand.valid {
			_ = os.Remove(fallbackCand.path)
		}
	} else if fallbackCand.valid {
		chosen = fallbackCand
	} else {
		return "", fmt.Errorf("updater: target binary %q not found in tar.gz archive", kernel)
	}

	extractedPath := filepath.Join(workDir, kernel+".extracted")
	if err := os.Rename(chosen.path, extractedPath); err != nil {
		return "", fmt.Errorf("updater: finalize extracted binary: %w", err)
	}
	if err := os.Chmod(extractedPath, 0o755); err != nil {
		return "", fmt.Errorf("updater: chmod extracted binary: %w", err)
	}
	return extractedPath, nil
}

func (u *Updater) extractZip(workDir string, kernel string, archivePath string) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("updater: open zip archive: %w", err)
	}
	defer zr.Close()

	if len(zr.File) > maxArchiveEntries {
		return "", fmt.Errorf("updater: zip archive exceeds max entry count (%d)", maxArchiveEntries)
	}

	var (
		totalPayload int64
		exactFile    *zip.File
		exactCand    candidateFile
		fallbackFile *zip.File
		fallbackCand candidateFile
	)

	for _, zf := range zr.File {
		clean, isDir, err := validateArchiveEntryPath(zf.Name)
		if err != nil {
			return "", err
		}

		mode := zf.Mode()
		if mode&os.ModeSymlink != 0 {
			return "", fmt.Errorf("updater: zip archive contains forbidden symlink %q", zf.Name)
		}
		if mode&(os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeIrregular) != 0 {
			return "", fmt.Errorf("updater: zip archive contains forbidden special file %q", zf.Name)
		}
		if zf.FileInfo().IsDir() || isDir {
			continue
		}
		if !mode.IsRegular() {
			return "", fmt.Errorf("updater: zip archive contains non-regular entry %q", zf.Name)
		}

		if zf.UncompressedSize64 > uint64(u.opts.MaxExtractBytes) {
			return "", fmt.Errorf("updater: zip entry %q exceeds max extract limit %d", zf.Name, u.opts.MaxExtractBytes)
		}
		entrySize := int64(zf.UncompressedSize64)
		if totalPayload > u.opts.MaxExtractBytes-entrySize {
			return "", fmt.Errorf("updater: zip archive total uncompressed size exceeds max limit %d", u.opts.MaxExtractBytes)
		}
		totalPayload += entrySize

		if zf.UncompressedSize64 == 0 {
			continue
		}

		base := path.Base(clean)
		depth := pathDepth(clean)

		if base == kernel {
			if !exactCand.valid || candidateBetter(depth, clean, exactCand) {
				exactCand = candidateFile{valid: true, clean: clean, depth: depth}
				exactFile = zf
			}
		} else if !exactCand.valid && isFallbackBinaryName(kernel, base) {
			if !fallbackCand.valid || candidateBetter(depth, clean, fallbackCand) {
				fallbackCand = candidateFile{valid: true, clean: clean, depth: depth}
				fallbackFile = zf
			}
		}
	}

	chosenFile := exactFile
	if chosenFile == nil {
		chosenFile = fallbackFile
	}
	if chosenFile == nil {
		return "", fmt.Errorf("updater: target binary %q not found in zip archive", kernel)
	}

	rc, err := chosenFile.Open()
	if err != nil {
		return "", fmt.Errorf("updater: open zip entry %q: %w", chosenFile.Name, err)
	}
	defer rc.Close()

	extractedPath := filepath.Join(workDir, kernel+".extracted")
	written, err := copyBoundedToFile(extractedPath, rc, u.opts.MaxExtractBytes)
	if err != nil {
		_ = os.Remove(extractedPath)
		return "", fmt.Errorf("updater: extract zip entry %q: %w", chosenFile.Name, err)
	}
	if written == 0 {
		_ = os.Remove(extractedPath)
		return "", fmt.Errorf("updater: extracted binary %q from zip is empty", chosenFile.Name)
	}
	if err := os.Chmod(extractedPath, 0o755); err != nil {
		return "", fmt.Errorf("updater: chmod extracted binary: %w", err)
	}
	return extractedPath, nil
}

type candidateFile struct {
	valid bool
	path  string
	clean string
	depth int
}

func candidateBetter(depth int, clean string, existing candidateFile) bool {
	if !existing.valid {
		return true
	}
	if depth != existing.depth {
		return depth < existing.depth
	}
	return clean < existing.clean
}

func pathDepth(clean string) int {
	if clean == "." || clean == "" {
		return 0
	}
	return strings.Count(clean, "/")
}

func validateArchiveEntryPath(rawName string) (string, bool, error) {
	if rawName == "" {
		return "", false, errors.New("updater: archive contains empty entry name")
	}
	if strings.ContainsRune(rawName, '\x00') {
		return "", false, fmt.Errorf("updater: archive entry %q contains NUL byte", rawName)
	}
	if strings.ContainsRune(rawName, '\\') {
		return "", false, fmt.Errorf("updater: archive entry %q contains forbidden backslash", rawName)
	}
	if strings.HasPrefix(rawName, "/") {
		return "", false, fmt.Errorf("updater: archive entry %q has forbidden absolute path", rawName)
	}
	if len(rawName) >= 2 && rawName[1] == ':' {
		return "", false, fmt.Errorf("updater: archive entry %q has forbidden drive prefix", rawName)
	}

	for _, seg := range strings.Split(rawName, "/") {
		if seg == ".." {
			return "", false, fmt.Errorf("updater: archive entry %q contains path traversal segment '..'", rawName)
		}
	}

	isDir := strings.HasSuffix(rawName, "/")
	trimmed := strings.TrimRight(rawName, "/")
	if trimmed == "" {
		return ".", true, nil
	}
	clean := path.Clean(trimmed)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false, fmt.Errorf("updater: archive entry %q resolves outside archive root (%q)", rawName, clean)
	}
	return clean, isDir, nil
}

func isFallbackBinaryName(kernel string, base string) bool {
	if !strings.HasPrefix(base, kernel+"-") {
		return false
	}
	lower := strings.ToLower(base)
	nonBinarySuffixes := []string{
		".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
		".service", ".1", ".bash", ".fish", ".zsh", ".ps1",
		".sha256", ".sha512", ".sig", ".asc", ".tar", ".gz", ".zip", ".xz",
	}
	for _, sfx := range nonBinarySuffixes {
		if strings.HasSuffix(lower, sfx) {
			return false
		}
	}
	return true
}

func copyBoundedToFile(dstPath string, src io.Reader, maxBytes int64) (int64, error) {
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(out, io.LimitReader(src, maxBytes+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return 0, copyErr
	}
	if syncErr != nil {
		return 0, syncErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if written > maxBytes {
		return 0, fmt.Errorf("extracted entry exceeds max extract size limit (%d bytes)", maxBytes)
	}
	return written, nil
}
