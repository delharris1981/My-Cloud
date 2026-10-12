// Package upload handles file writes: a single-request multipart path that
// works with JavaScript disabled, and resumable chunk sessions for large files.
//
// Every destination is produced by vfs.Resolve. This package is one of only two
// allowed to open a path under the data directory, and it does so exclusively
// after that call.
package upload

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/vfs"
)

// ErrTooLarge means the write would exceed the caller's byte cap.
var ErrTooLarge = errors.New("upload exceeds the permitted size")

// defaultChunkTimeout is how long an unfinished chunk session may sit idle
// before the sweeper removes it and its .part file.
const defaultChunkTimeout = 24 * time.Hour

// Sink writes a finished upload into the destination FS.
type Sink struct {
	// FS is the user's files root. Every path goes through Resolve.
	FS *vfs.FS
	// QuotaBytes caps total usage; 0 means unlimited.
	QuotaBytes int64
	// MaxBytes caps a single upload independently of quota, so an
	// unlimited-quota user still cannot fill the disk.
	MaxBytes int64
	// AllowSubdirs permits client-supplied relative subpaths under the
	// destination. False for anonymous drop-box writes.
	AllowSubdirs bool
	// OutOfSpaceMsg is returned when the quota is hit.
	OutOfSpaceMsg string
}

// Stream copies a multipart request into destDir, enforcing both caps.
//
// The quota is checked before the body is read and re-checked as bytes land,
// because a client that lies about Content-Length would otherwise be able to
// blow past the cap mid-stream.
func (s *Sink) Stream(r *http.Request, destDir string) (written []string, err error) {
	if err := s.checkQuota(destDir, 0); err != nil {
		return nil, err
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, fmt.Errorf("upload: expected multipart: %w", err)
	}

	var total int64
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, fmt.Errorf("upload: read part: %w", err)
		}
		name := part.FileName()
		if name == "" {
			part.Close()
			continue
		}
		n, err := s.writePart(part, destDir, name, &total)
		part.Close()
		if err != nil {
			return written, err
		}
		written = append(written, n)
	}
	return written, nil
}

// writePart streams one file part to disk.
func (s *Sink) writePart(src io.Reader, destDir, name string, total *int64) (string, error) {
	dest, err := s.destFor(destDir, name)
	if err != nil {
		return "", err
	}
	abs, err := s.FS.Resolve(dest)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}

	// O_EXCL: a name that survived UniqueName must not already exist.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("upload: create %s: %w", filepath.Base(abs), err)
	}
	defer f.Close()

	// limitedWriter enforces the caps as bytes arrive, not just at the end.
	lw := &limitedWriter{
		w:         f,
		quotaLeft: s.QuotaBytes - *total - s.currentUsage(destDir),
		maxLeft:   s.MaxBytes - *total,
	}
	if _, err := io.Copy(lw, src); err != nil {
		os.Remove(abs) // do not leave a truncated file behind
		if errors.Is(err, ErrTooLarge) {
			// Surface the operator's message (e.g. "The owner is out of
			// storage space.") rather than the internal sentinel, which means
			// nothing to a user watching an upload fail.
			return "", s.tooLargeError()
		}
		return "", fmt.Errorf("upload: write: %w", err)
	}
	*total += lw.written
	return filepath.Base(abs), nil
}

// destFor computes the destination relative path for an incoming filename.
//
// A unique name is always applied, so a second upload of the same filename
// becomes "name (1).ext" instead of overwriting the first. AllowSubdirs only
// controls whether a client-supplied directory prefix is honoured; the
// filename itself is always reduced to its base component.
func (s *Sink) destFor(destDir, name string) (string, error) {
	safe := sanitiseFilename(name)
	if safe == "" {
		return "", fmt.Errorf("upload: invalid filename %q", name)
	}
	unique, err := s.FS.UniqueName(destDir, safe)
	if err != nil {
		return "", err
	}
	return joinRel(destDir, unique), nil
}

func (s *Sink) currentUsage(destDir string) int64 {
	// Only used as a cap guard; the authoritative check is checkQuota.
	return s.FS.Usage(destDir)
}

// checkQuota returns an error if current usage would exceed the quota.
func (s *Sink) checkQuota(destDir string, incoming int64) error {
	if s.QuotaBytes <= 0 {
		return nil // unlimited
	}
	used := s.FS.Usage(destDir)
	if used+incoming > s.QuotaBytes {
		return s.tooLargeError()
	}
	return nil
}

// tooLargeError returns the user-facing message for a size or quota refusal.
func (s *Sink) tooLargeError() error {
	if s.OutOfSpaceMsg != "" {
		return errors.New(s.OutOfSpaceMsg)
	}
	return ErrTooLarge
}

// limitedWriter enforces quota and per-file caps while streaming.
type limitedWriter struct {
	w         io.Writer
	quotaLeft int64
	maxLeft   int64
	written   int64
	fs        *vfs.FS
	destDir   string
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.maxLeft > 0 && l.written+int64(len(p)) > l.maxLeft {
		return 0, ErrTooLarge
	}
	if l.quotaLeft > 0 && l.written+int64(len(p)) > l.quotaLeft {
		return 0, ErrTooLarge
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return n, err
}

// --- Resumable chunk sessions ---

// ChunkSession is an in-progress resumable upload. State lives on disk as
// <dest>/<id>.part so a restart does not orphan an upload in memory.
type ChunkSession struct {
	ID        string
	DestDir   string // relative to the FS root
	Filename  string
	Total     int64
	Written   int64
	CreatedAt int64
	UpdatedAt int64
}

// partPath returns the on-disk .part location for a session within destDir.
// The id is server-generated hex, so it cannot traverse, but it is still
// validated as a single safe component.
func (s *Sink) partPath(destDir, id string) (string, error) {
	if !vfs.ValidName(id + ".part") {
		return "", fmt.Errorf("upload: bad session id")
	}
	return s.FS.Resolve(joinRel(destDir, id+".part"))
}

// CreateSession starts a resumable upload and returns the session.
//
// The id goes to the client, which echoes it in later Content-Range requests.
// It doubles as the .part filename, so it must be a safe single component.
func (s *Sink) CreateSession(destDir, filename string, total int64) (*ChunkSession, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	name := sanitiseFilename(filename)
	if name == "" {
		return nil, fmt.Errorf("upload: invalid filename %q", filename)
	}
	// Reject an obviously oversized declared total before allocating anything.
	if s.MaxBytes > 0 && total > s.MaxBytes {
		return nil, ErrTooLarge
	}
	partAbs, err := s.partPath(destDir, id)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(partAbs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("upload: create part: %w", err)
	}
	f.Close()

	now := time.Now().UnixMilli()
	return &ChunkSession{
		ID: id, DestDir: destDir, Filename: name, Total: total,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// SessionStatus returns how many bytes of a session have been stored, so a
// client that lost its connection can resume from the right offset.
func (s *Sink) SessionStatus(destDir, id string) (int64, error) {
	partAbs, err := s.partPath(destDir, id)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(partAbs)
	if err != nil {
		return 0, fmt.Errorf("upload: unknown session")
	}
	return st.Size(), nil
}

// sanitiseFilename reduces an incoming name to a single safe component,
// discarding any directory part a client may have included.
func sanitiseFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if !vfs.ValidName(name) {
		return ""
	}
	return name
}

// WriteChunk appends a byte range to a session's .part file.
//
// offset comes from Content-Range and must match what has already been
// written: accepting an arbitrary offset would let a client interleave chunks
// and produce a corrupt file that only fails after the final rename.
func (s *Sink) WriteChunk(destDir, id string, offset int64, r io.Reader) (written int64, err error) {
	partAbs, err := s.partPath(destDir, id)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(partAbs)
	if err != nil {
		return 0, fmt.Errorf("upload: unknown session")
	}
	if offset != st.Size() {
		return 0, fmt.Errorf("upload: expected offset %d, got %d", st.Size(), offset)
	}
	f, err := os.OpenFile(partAbs, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// The per-file cap applies across the whole assembled file.
	var remaining int64 = -1
	if s.MaxBytes > 0 {
		remaining = s.MaxBytes - st.Size()
	}
	lw := &limitedWriter{w: f, maxLeft: remaining}
	n, err := io.Copy(lw, r)
	if err != nil {
		return n, err
	}
	return n, nil
}

// CompleteSession moves a finished .part into its final name and returns the
// stored filename.
func (s *Sink) CompleteSession(destDir, id, filename string) (string, error) {
	partAbs, err := s.partPath(destDir, id)
	if err != nil {
		return "", err
	}
	name := sanitiseFilename(filename)
	if name == "" {
		return "", fmt.Errorf("upload: invalid filename %q", filename)
	}
	if err := s.checkQuota(destDir, 0); err != nil {
		return "", err
	}

	destRel, err := s.destFor(destDir, name)
	if err != nil {
		return "", err
	}
	destAbs, err := s.FS.Resolve(destRel)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(destAbs), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(partAbs, destAbs); err != nil {
		// Cross-device (trash or shares on another mount): copy then unlink.
		if cerr := copyPath(partAbs, destAbs); cerr != nil {
			return "", cerr
		}
		os.Remove(partAbs)
	}
	return filepath.Base(destAbs), nil
}

// CancelSession removes a .part file.
func (s *Sink) CancelSession(destDir, id string) error {
	partAbs, err := s.partPath(destDir, id)
	if err != nil {
		return err
	}
	os.Remove(partAbs)
	return nil
}

// SweepStaleSessions removes .part files under destDir older than ttl,
// returning how many were reclaimed.
func (s *Sink) SweepStaleSessions(destDir string, ttl time.Duration) (int, error) {
	if ttl <= 0 {
		ttl = defaultChunkTimeout
	}
	dirAbs, err := s.FS.Resolve(destDir)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-ttl)
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(dirAbs, e.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}

// ParseContentRange extracts the start offset from a Content-Range header of
// the form "bytes 0-1023/2048". Returns ok=false when the header is absent or
// malformed.
func ParseContentRange(header string) (offset int64, total int64, ok bool) {
	if !strings.HasPrefix(header, "bytes ") {
		return 0, 0, false
	}
	rest := strings.TrimPrefix(header, "bytes ")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return 0, 0, false
	}
	rangePart := rest[:slash]
	totalPart := rest[slash+1:]
	dash := strings.Index(rangePart, "-")
	if dash < 0 {
		return 0, 0, false
	}
	offset, err := strconv.ParseInt(rangePart[:dash], 10, 64)
	if err != nil || offset < 0 {
		return 0, 0, false
	}
	if totalPart != "*" {
		if total, err = strconv.ParseInt(totalPart, 10, 64); err != nil {
			return 0, 0, false
		}
	}
	return offset, total, true
}

// SaveMultipart streams a multipart form's file parts to destDir. Used by the
// no-JS fallback path.
func (s *Sink) SaveMultipart(r *http.Request, destDir string) ([]string, error) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return nil, fmt.Errorf("upload: parse multipart: %w", err)
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	var out []string
	var total int64
	for _, headers := range r.MultipartForm.File {
		for _, fh := range headers {
			n, err := s.saveFile(fh, destDir, &total)
			if err != nil {
				return out, err
			}
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *Sink) saveFile(fh *multipart.FileHeader, destDir string, total *int64) (string, error) {
	src, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("upload: open part: %w", err)
	}
	defer src.Close()
	return s.writePart(src, destDir, fh.Filename, total)
}
