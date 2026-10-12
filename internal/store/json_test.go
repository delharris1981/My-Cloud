package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	j := NewJSON(filepath.Join(t.TempDir(), "settings.json"))
	type doc struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	if err := j.Write(doc{Name: "a", Count: 2}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var got doc
	if err := j.Read(&got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Name != "a" || got.Count != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestReadMissingReturnsNotExist(t *testing.T) {
	j := NewJSON(filepath.Join(t.TempDir(), "absent.json"))
	var v map[string]any
	err := j.Read(&v)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestReadCorruptIsDistinguishable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	err := NewJSON(p).Read(&v)
	// The caller (users.json handling) needs to tell "absent" from "corrupt":
	// the first is a fresh install, the second must abort startup.
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestWriteIsAtomicNoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	j := NewJSON(filepath.Join(dir, "doc.json"))
	for i := 0; i < 5; i++ {
		if err := j.Write(map[string]int{"n": i}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	// A crashed write must not leave partial files behind; the rename is the
	// only thing that should persist.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestUpdateAppliesMutation(t *testing.T) {
	j := NewJSON(filepath.Join(t.TempDir(), "counter.json"))
	if err := j.Write(map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.Update(func(cur []byte) ([]byte, error) {
		return []byte(`{"n":2}`), nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	var got map[string]int
	if err := j.Read(&got); err != nil {
		t.Fatal(err)
	}
	if got["n"] != 2 {
		t.Fatalf("update not applied: %v", got)
	}
}

func TestUpdateSeesCurrentContent(t *testing.T) {
	j := NewJSON(filepath.Join(t.TempDir(), "doc.json"))
	if err := j.Write(map[string]string{"who": "before"}); err != nil {
		t.Fatal(err)
	}
	// fn must receive the on-disk bytes, or a read-modify-write would be a
	// blind overwrite.
	if err := j.Update(func(cur []byte) ([]byte, error) {
		if !strings.Contains(string(cur), "before") {
			t.Fatalf("Update did not see current content: %q", cur)
		}
		return []byte(`{"who":"after"}`), nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestUpdatePropagatesError(t *testing.T) {
	j := NewJSON(filepath.Join(t.TempDir(), "doc.json"))
	if err := j.Write(map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("nope")
	if err := j.Update(func([]byte) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("expected the mutation error to propagate, got %v", err)
	}
	// A failed mutation must leave the document untouched.
	var got map[string]string
	if err := j.Read(&got); err != nil {
		t.Fatal(err)
	}
	if got["a"] != "b" {
		t.Fatal("failed update mutated the document")
	}
}

func TestConcurrentWritesDoNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	j := NewJSON(filepath.Join(dir, "doc.json"))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if err := j.Write(map[string]int{"n": n}); err != nil {
				t.Errorf("concurrent Write: %v", err)
			}
		}(i)
	}
	wg.Wait()
	// Whatever the final value, the file must still be valid JSON.
	var got map[string]int
	if err := j.Read(&got); err != nil {
		t.Fatalf("document corrupted by concurrent writes: %v", err)
	}
}

func TestQuarantineCopiesAndKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json")
	if err := os.WriteFile(p, []byte(`{"bad`), 0o644); err != nil {
		t.Fatal(err)
	}
	dst, err := Quarantine(p)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !strings.Contains(filepath.Base(dst), "corrupt-") {
		t.Fatalf("unexpected quarantine name: %s", dst)
	}
	// The original must remain: whoever quarantines decides separately
	// whether replacing it is safe.
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("original was removed: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if string(b) != `{"bad` {
		t.Fatalf("quarantined content differs: %q", b)
	}
}

func TestLockIsExclusiveAcrossGoroutines(t *testing.T) {
	dir := t.TempDir()
	a := NewJSON(filepath.Join(dir, "doc.json"))
	b := NewJSON(filepath.Join(dir, "doc.json"))
	// Two independent JSON handles (standing in for two processes during the
	// strangler rollout) must not interleave inside Update.
	unlock, err := a.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer unlock()

	done := make(chan struct{})
	go func() {
		unlock2, err := b.Lock()
		if err == nil {
			unlock2()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("second lock acquired while the first was held")
	default:
	}
}
