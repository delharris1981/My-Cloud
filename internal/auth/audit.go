package auth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// AuditEvent records a security-relevant action. The Node version had no audit
// log at all; this adds the record the plan requires.
type AuditEvent struct {
	Username string
	Action   string // login.ok, login.fail, logout, dav.auth, share.view, …
	Detail   string // short, never secrets or file contents
	IP       string
	OK       bool
}

// AuditLogger appends to the audit_log table. Write failures are logged, not
// returned: an audit write must never break the request it describes.
type AuditLogger struct {
	db  *sql.DB
	log *log.Logger
}

// NewAuditLogger wires the logger.
func NewAuditLogger(db *sql.DB, logger *log.Logger) *AuditLogger {
	return &AuditLogger{db: db, log: logger}
}

// Log appends an event.
func (a *AuditLogger) Log(ctx context.Context, ev AuditEvent) {
	if a == nil || a.db == nil {
		return
	}
	// Bound the detail so a caller cannot write an unbounded blob.
	detail := ev.Detail
	if len(detail) > 200 {
		detail = detail[:200]
	}
	var username any
	if ev.Username != "" {
		username = NormaliseUsername(ev.Username)
	}
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO audit_log(at, username, action, detail, ip, ok) VALUES(?,?,?,?,?,?)`,
		time.Now().UnixMilli(), username, ev.Action, nullIfEmpty(detail), nullIfEmpty(ev.IP),
		boolInt(ev.OK))
	if err != nil {
		a.log.Printf("audit: write %s for %q failed: %v", ev.Action, ev.Username, err)
	}
}

// Logf is a formatting convenience for Log.
func (a *AuditLogger) Logf(ctx context.Context, ev AuditEvent, format string, args ...any) {
	ev.Detail = strings.TrimSpace(fmt.Sprintf(format, args...))
	a.Log(ctx, ev)
}
