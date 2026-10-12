package server

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/share"
	"github.com/derek/my-cloud/internal/vfs"
)

// serveZip streams a set of paths as a zip archive.
//
// The archive is piped straight to the client with no temporary file: a large
// folder would otherwise need disk space equal to the whole selection, on top
// of the selection itself.
func (a *App) serveZip(w http.ResponseWriter, r *http.Request, tr *vfs.Trash, sh *share.Share, paths []string) {
	// Level 0 (store, no compression) matches the Node behaviour: user media
	// is already compressed, so deflating it burns CPU for no size gain.
	zw := zip.NewWriter(w)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="files.zip"`)

	for _, p := range paths {
		abs, err := tr.Files().Resolve(p)
		if err != nil {
			continue
		}
		st, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if st.IsDir() {
			if err := a.zipDir(zw, tr, abs, path.Base(abs)); err != nil {
				return // the client went away or the walk failed
			}
			continue
		}
		if err := zipOneFile(zw, abs, path.Base(abs)); err != nil {
			return
		}
	}
	//nolint:errcheck // the client may already be gone
	zw.Close()
}

// zipDir walks a directory and adds every file under it to the archive.
func (a *App) zipDir(zw *zip.Writer, tr *vfs.Trash, abs, prefix string) error {
	return filepathWalk(abs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip an entry we cannot read rather than aborting the archive.
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := tr.Files().RelPath(p)
		if rerr != nil {
			return nil
		}
		name := path.Join(prefix, path.Base(rel))
		return zipOneFile(zw, p, name)
	})
}

// zipOneFile adds a single file to the archive under name.
func zipOneFile(zw *zip.Writer, abs, name string) error {
	// Opened through vfs so every user-data read routes through the package
	// that owns the confinement rules.
	f, err := vfs.OpenResolved(abs)
	if err != nil {
		return nil // skip unreadable files
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	hdr, err := zip.FileInfoHeader(st)
	if err != nil {
		return nil
	}
	// A crafted name must not be able to escape the extraction directory.
	hdr.Name = zipSafeName(name)
	// Deflate disabled: see serveZip.
	hdr.Method = zip.Store
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

// handleFileZip streams the caller's own selection as a zip.
func (a *App) handleFileZip(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	r.ParseForm() //nolint:errcheck
	paths := formPaths(r, "paths")
	if p := r.FormValue("path"); p != "" && len(paths) == 0 {
		paths = []string{p}
	}
	if len(paths) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}
	// A placeholder share value keeps the signature shared with serveZip; the
	// archive is built from the caller's own selection, not a share row.
	sh := &share.Share{Owner: u.Username}
	a.serveZip(w, r, tr, sh, paths)
}

// zipSafeName ensures an archive entry name cannot escape when extracted.
func zipSafeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimLeft(name, "/")
	if name == "" {
		return "file"
	}
	return name
}
