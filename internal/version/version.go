// Package version exposes the build version to the running server.
//
// Values come from the linker, which reads the VERSION file at the repository
// root. A build made without the flags reports "dev", which is deliberately
// obvious rather than a plausible-looking lie.
package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
)

// These are overridden at link time:
//
//	-ldflags "-X github.com/derek/my-cloud/internal/version.Version=2.0.0 ..."
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the full build description.
type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Current returns the build description.
func Current() Info {
	return Info{
		Version:  Version,
		Commit:   Commit,
		Date:     Date,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String is the one-line form.
func (i Info) String() string {
	return fmt.Sprintf("my-cloud %s (commit %s, %s, %s)", i.Version, i.Commit, i.Date, i.Go)
}

// Handler serves the version as JSON. It is deliberately unauthenticated: a
// deployed instance should be identifiable, and nothing here is secret beyond
// the commit hash.
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(Current())
}
