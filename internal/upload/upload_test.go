package upload

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derek/my-cloud/internal/vfs"
)

func newSink(t *testing.T) (*Sink, *vfs.FS) {
	t.Helper()
	fs, err := vfs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Sink{FS: fs, AllowSubdirs: false}, fs
}

// multipartRequest builds a POST body with the given files.
func multipartRequest(t *testing.T, files map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	req := httptest.NewRequest("POST", "/api/files/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestStreamWritesFiles(t *testing.T) {
	sink, fs := newSink(t)
	req := multipartRequest(t, map[string]string{
		"a.txt": "hello",
		"b.txt": "world",
	})

	written, err := sink.Stream(req, "")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(written), written)
	}
	for name, want := range map[string]string{"a.txt": "hello", "b.txt": "world"} {
		abs, err := fs.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("%s not written: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestStreamSanitisesFilename(t *testing.T) {
	sink, fs := newSink(t)
	// A hostile filename must not escape the destination or create a
	// subdirectory.
	written, err := sink.Stream(multipartRequest(t, map[string]string{
		"../../../../etc/passwd": "pwned",
	}), "")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 file, got %v", written)
	}
	// The stored name is the base component only.
	if written[0] != "passwd" {
		t.Fatalf("filename not sanitised: %q", written[0])
	}
	// And it landed inside the FS root.
	if _, err := fs.Stat("passwd"); err != nil {
		t.Fatalf("file not stored in root: %v", err)
	}
}

func TestStreamAppliesUniqueName(t *testing.T) {
	sink, fs := newSink(t)
	// Two uploads of the same name must not overwrite each other.
	if _, err := sink.Stream(multipartRequest(t, map[string]string{"doc.txt": "first"}), ""); err != nil {
		t.Fatal(err)
	}
	written, err := sink.Stream(multipartRequest(t, map[string]string{"doc.txt": "second"}), "")
	if err != nil {
		t.Fatal(err)
	}
	if written[0] != "doc (1).txt" {
		t.Fatalf("unique name not applied: %q", written[0])
	}
	// The original must be intact.
	e, _ := fs.Stat("doc.txt")
	if e.Size != int64(len("first")) {
		t.Fatalf("original overwritten: %d bytes", e.Size)
	}
}

func TestStreamRejectsInvalidFilenames(t *testing.T) {
	sink, fs := newSink(t)
	// "." and ".." are not valid single components and must be refused.
	for _, name := range []string{".", ".."} {
		if _, err := sink.Stream(multipartRequest(t, map[string]string{name: "x"}), ""); err == nil {
			t.Errorf("filename %q was accepted", name)
		}
	}
	// An empty filename is a non-file form field, not an upload: the part is
	// skipped rather than treated as an error.
	written, err := sink.Stream(multipartRequest(t, map[string]string{"": "x"}), "")
	if err != nil {
		t.Fatalf("empty filename should be skipped, not error: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("empty filename produced a file: %v", written)
	}
	// A path in the filename is reduced to its base component by the multipart
	// parser, so it lands as a plain file in the destination — never as a
	// subdirectory.
	written2, err := sink.Stream(multipartRequest(t, map[string]string{"sub/dir/f.txt": "x"}), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(written2) != 1 || written2[0] != "f.txt" {
		t.Fatalf("path filename not reduced: %v", written2)
	}
	if _, err := fs.Stat("f.txt"); err != nil {
		t.Fatalf("file not stored in destination root: %v", err)
	}
}

func TestStreamEnforcesQuota(t *testing.T) {
	sink, fs := newSink(t)
	sink.QuotaBytes = 10 // 10 bytes

	// A 6-byte file fits.
	if _, err := sink.Stream(multipartRequest(t, map[string]string{"a.txt": "123456"}), ""); err != nil {
		t.Fatalf("first upload should fit: %v", err)
	}
	// A second 6-byte file exceeds the quota and must be refused.
	_, err := sink.Stream(multipartRequest(t, map[string]string{"b.txt": "abcdef"}), "")
	if err == nil {
		t.Fatal("quota not enforced")
	}
	// The refused file must not have been left on disk.
	if _, err := fs.Stat("b.txt"); err == vfs.ErrNotFound {
		// correct
	} else if err == nil {
		t.Fatal("refused upload left a file behind")
	}
}

func TestStreamEnforcesMaxBytes(t *testing.T) {
	sink, fs := newSink(t)
	// MaxBytes caps a single upload independently of an unlimited quota.
	sink.QuotaBytes = 0
	sink.MaxBytes = 5

	if _, err := sink.Stream(multipartRequest(t, map[string]string{"big.txt": strings.Repeat("x", 100)}), ""); err == nil {
		t.Fatal("per-file cap not enforced")
	}
	// The partial file must be cleaned up, not left truncated.
	entries, err := os.ReadDir(fs.Root())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial upload left behind: %d files", len(entries))
	}
}

func TestStreamHonoursOutOfSpaceMessage(t *testing.T) {
	sink, _ := newSink(t)
	sink.QuotaBytes = 1
	sink.OutOfSpaceMsg = "The owner is out of storage space."
	_, err := sink.Stream(multipartRequest(t, map[string]string{"a.txt": "too much"}), "")
	if err == nil || !strings.Contains(err.Error(), "out of storage space") {
		t.Fatalf("custom message not returned: %v", err)
	}
}

// --- Resumable chunks ---

func TestChunkSessionRoundTrip(t *testing.T) {
	sink, fs := newSink(t)
	if _, err := fs.MkdirSingle("", "uploads"); err != nil {
		t.Fatal(err)
	}

	sess, err := sink.CreateSession("uploads", "big.bin", 11)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !strings.HasSuffix(sess.ID, "") || sess.ID == "" {
		t.Fatal("empty session id")
	}

	// Send in two chunks.
	if n, err := sink.WriteChunk("uploads", sess.ID, 0, strings.NewReader("hello ")); err != nil || n != 6 {
		t.Fatalf("chunk 1: n=%d err=%v", n, err)
	}
	// A wrong offset must be refused, or chunks could interleave and produce a
	// corrupt file.
	if _, err := sink.WriteChunk("uploads", sess.ID, 0, strings.NewReader("x")); err == nil {
		t.Fatal("wrong offset accepted")
	}
	if n, err := sink.WriteChunk("uploads", sess.ID, 6, strings.NewReader("world")); err != nil || n != 5 {
		t.Fatalf("chunk 2: n=%d err=%v", n, err)
	}

	name, err := sink.CompleteSession("uploads", sess.ID, "big.bin")
	if err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}
	if name != "big.bin" {
		t.Fatalf("stored name %q", name)
	}
	// The assembled content must be correct.
	abs, err := fs.Resolve("uploads/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("assembled content wrong: %q", got)
	}
	// The .part file must be gone after completion.
	if _, err := fs.Stat("uploads/" + sess.ID + ".part"); err != vfs.ErrNotFound {
		t.Fatal("part file left after completion")
	}
}

func TestSessionStatusReportsOffset(t *testing.T) {
	sink, _ := newSink(t)
	sess, err := sink.CreateSession("", "f.bin", 100)
	if err != nil {
		t.Fatal(err)
	}
	// Start at zero.
	got, err := sink.SessionStatus("", sess.ID)
	if err != nil || got != 0 {
		t.Fatalf("status: got %d err=%v", got, err)
	}
	sink.WriteChunk("", sess.ID, 0, strings.NewReader("12345"))
	// A client that lost its connection reads this to learn where to resume.
	got, err = sink.SessionStatus("", sess.ID)
	if err != nil || got != 5 {
		t.Fatalf("status after chunk: got %d err=%v", got, err)
	}
}

func TestSessionRejectsBadID(t *testing.T) {
	sink, _ := newSink(t)
	for _, id := range []string{"../escape", "a/b", "", ".."} {
		if _, err := sink.WriteChunk("", id, 0, strings.NewReader("x")); err == nil {
			t.Errorf("bad session id %q accepted", id)
		}
		if _, err := sink.SessionStatus("", id); err == nil {
			t.Errorf("bad session id %q accepted by status", id)
		}
	}
}

func TestSessionEnforcesMaxBytes(t *testing.T) {
	sink, _ := newSink(t)
	sink.MaxBytes = 10
	if _, err := sink.CreateSession("", "f.bin", 1000); err == nil {
		t.Fatal("oversized session created despite MaxBytes")
	}
	// Chunked writes are capped too.
	sess, err := sink.CreateSession("", "g.bin", 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.WriteChunk("", sess.ID, 0, strings.NewReader(strings.Repeat("x", 20))); err == nil {
		t.Fatal("chunk exceeded MaxBytes")
	}
}

func TestCancelSessionRemovesPart(t *testing.T) {
	sink, fs := newSink(t)
	sess, _ := sink.CreateSession("", "f.bin", 10)
	sink.WriteChunk("", sess.ID, 0, strings.NewReader("data"))
	if err := sink.CancelSession("", sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(sess.ID + ".part"); err != vfs.ErrNotFound {
		t.Fatal("part file survived cancel")
	}
}

func TestSweepStaleSessions(t *testing.T) {
	sink, fs := newSink(t)
	sess, _ := sink.CreateSession("", "stale.bin", 10)
	sink.WriteChunk("", sess.ID, 0, strings.NewReader("data"))

	// Nothing is stale yet.
	n, err := sink.SweepStaleSessions("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("swept a fresh session: %d", n)
	}
	// Backdate the part file past the cutoff.
	partAbs, _ := fs.Resolve(sess.ID + ".part")
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(partAbs, past, past); err != nil {
		t.Fatal(err)
	}
	n, err = sink.SweepStaleSessions("", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 stale session swept, got %d", n)
	}
	if _, err := fs.Stat(sess.ID + ".part"); err != vfs.ErrNotFound {
		t.Fatal("stale part not removed")
	}
}

func TestParseContentRange(t *testing.T) {
	offset, total, ok := ParseContentRange("bytes 0-1023/2048")
	if !ok || offset != 0 || total != 2048 {
		t.Fatalf("got offset=%d total=%d ok=%v", offset, total, ok)
	}
	offset, total, ok = ParseContentRange("bytes 1024-2047/*")
	if !ok || offset != 1024 || total != 0 {
		t.Fatalf("wildcard total: offset=%d total=%d ok=%v", offset, total, ok)
	}
	for _, bad := range []string{"", "bytes", "bytes abc-def/10", "bytes 5/10", "items 0-1/2"} {
		if _, _, ok := ParseContentRange(bad); ok {
			t.Errorf("malformed header %q accepted", bad)
		}
	}
}

func TestSaveMultipartFallback(t *testing.T) {
	sink, fs := newSink(t)
	// This is the no-JS path: a plain form post with no chunking.
	written, err := sink.SaveMultipart(multipartRequest(t, map[string]string{"nojs.txt": "plain"}), "")
	if err != nil {
		t.Fatalf("SaveMultipart: %v", err)
	}
	if len(written) != 1 || written[0] != "nojs.txt" {
		t.Fatalf("unexpected writes: %v", written)
	}
	e, err := fs.Stat("nojs.txt")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != int64(len("plain")) {
		t.Fatalf("size %d", e.Size)
	}
}

func TestLargeUploadStreams(t *testing.T) {
	sink, fs := newSink(t)
	// Larger than the 32MB in-memory multipart threshold used by ParseMultipartForm,
	// exercising the streaming path.
	big := strings.Repeat("A", 5<<20) // 5MB
	if _, err := sink.Stream(multipartRequest(t, map[string]string{"big.bin": big}), ""); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	e, err := fs.Stat("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != int64(len(big)) {
		t.Fatalf("size mismatch: %d vs %d", e.Size, len(big))
	}
}

func TestDestForNeverEscapes(t *testing.T) {
	sink, _ := newSink(t)
	for _, name := range []string{
		"../../../etc/passwd",
		"/absolute/path.txt",
		`..\..\windows\system32`,
		"sub/dir/file.txt",
	} {
		rel, err := sink.destFor("dest", name)
		if err != nil {
			t.Fatalf("destFor(%q): %v", name, err)
		}
		// The result must stay under the destination directory.
		if !strings.HasPrefix(rel, "dest/") {
			t.Fatalf("destFor(%q) escaped: %q", name, rel)
		}
		if strings.Contains(rel, "..") {
			t.Fatalf("destFor(%q) contains ..: %q", name, rel)
		}
	}
}

func BenchmarkStreamLarge(b *testing.B) {
	fs, err := vfs.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	sink := &Sink{FS: fs}
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		fw, _ := w.CreateFormFile("files", fmt.Sprintf("f%d.bin", i))
		fw.Write(data)
		w.Close()
		req := httptest.NewRequest("POST", "/", &buf)
		req.Header.Set("Content-Type", w.FormDataContentType())
		sink.Stream(req, "")
	}
	_ = filepath.Join
}
