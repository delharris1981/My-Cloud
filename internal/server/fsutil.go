package server

import "os"

// mkdirAll creates a directory tree, ignoring an existing directory.
func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }
