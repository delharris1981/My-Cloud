package server

import (
	"io/fs"
	"os"
	"path/filepath"
)

// maxZipDepth bounds directory recursion when building an archive. A symlink
// loop or an accidental deep tree should not walk forever.
const maxZipDepth = 40

// filepathWalk is a bounded depth-first walk used by the zip builder.
//
// It is a thin wrapper over filepath.WalkDir so the depth limit and the
// skip-unreadable policy live in one place.
func filepathWalk(root string, fn func(path string, info os.FileInfo, err error) error) error {
	return walkDepth(root, 0, fn)
}

func walkDepth(p string, depth int, fn func(string, os.FileInfo, error) error) error {
	if depth > maxZipDepth {
		return filepath.SkipDir
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil // unreadable directory: skip rather than abort the archive
	}
	for _, e := range entries {
		child := filepath.Join(p, e.Name())
		if e.IsDir() {
			if err := walkDepth(child, depth+1, fn); err != nil {
				return err
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if err := fn(child, info, nil); err != nil {
			return err
		}
	}
	return nil
}

var _ fs.FileInfo
