// Command version reports the build version.
//
// The single source of truth is the VERSION file at the repository root, read
// at link time by -X. Keeping it in one place means the container image, the
// /api/status response, and the git tag cannot drift apart.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// These are set at link time. See the version flags in Dockerfile.go-build and
// scripts/build.sh.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println(version)
		return
	}
	switch args[0] {
	case "-json":
		out := map[string]string{
			"version":  version,
			"commit":   commit,
			"date":     date,
			"go":       runtime.Version(),
			"platform": runtime.GOOS + "/" + runtime.GOARCH,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	case "-version":
		fmt.Printf("my-cloud %s (commit %s, built %s, %s)\n",
			version, commit, date, runtime.Version())
	default:
		fmt.Fprintf(os.Stderr, "usage: version [-json|-version]\n")
		os.Exit(2)
	}
}
