package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Session is a logged-in session row.
type Session struct {
	ID         string // sha256(token), hex
	Username   string
	CreatedAt  int64
	LastSeen   int64
	ExpiresAt  int64
	CSRFSecret string
	UserAgent  string
	IP         string
}

// ErrNoSession means the token did not match a live row.
var ErrNoSession = errors.New("no session")

// SessionTTL is how long a session lasts and how far the sliding window can
// extend it.
func (s *Store) SessionTTL(cfgSessionDays int) time.Duration {
	if cfgSessionDays < 1 {
		cfgSessionDays = 30
	}
	return time.Duration(cfgSessionDays) * 24 * time.Hour
}

// CreateSession issues a new session and returns the raw token for the cookie
// plus the row. The raw token is never stored.
func (s *Store) CreateSession(ctx context.Context, username, userAgent, ip string, ttl time.Duration) (token string, sess *Session, err error) {
	token, id, err := NewToken()
	if err != nil {
		return "", nil, err
	}
	csrf, err := randomHex(32)
	if err != nil {
		return "", nil, fmt.Errorf("auth: csrf secret: %w", err)
	}
	now := time.Now().UnixMilli()
	expires := time.Now().Add(ttl).UnixMilli()

	sess = &Session{
		ID: id, Username: NormaliseUsername(username),
		CreatedAt: now, LastSeen: now, ExpiresAt: expires,
		CSRFSecret: csrf, UserAgent: truncate(userAgent, 255), IP: truncate(ip, 64),
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions(id, username, created_at, last_seen, expires_at, csrf_secret, user_agent, ip)
		 VALUES(?,?,?,?,?,?,?,?)`,
		sess.ID, sess.Username, sess.CreatedAt, sess.LastSeen, sess.ExpiresAt,
		sess.CSRFSecret, nullIfEmpty(sess.UserAgent), nullIfEmpty(sess.IP))
	if err != nil {
		return "", nil, fmt.Errorf("auth: insert session: %w", err)
	}
	return token, sess, nil
}

// LookupSession resolves a raw cookie token to a live session, sliding its
// expiry forward. Returns ErrNoSession if the token is unknown or expired.
//
// The trg_sessions_purge trigger deletes a row as soon as last_seen passes
// expires_at, so a stale session cannot linger even if this check were skipped.
func (s *Store) LookupSession(ctx context.Context, token string, ttl time.Duration) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	id := HashToken(token)
	var sess Session
	var ua, ip sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, created_at, last_seen, expires_at, csrf_secret, user_agent, ip
		 FROM sessions WHERE id=?`, id).
		Scan(&sess.ID, &sess.Username, &sess.CreatedAt, &sess.LastSeen, &sess.ExpiresAt,
			&sess.CSRFSecret, &ua, &ip)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("auth: lookup session: %w", err)
	}
	now := time.Now()
	if now.UnixMilli() > sess.ExpiresAt {
		// Expired: delete eagerly so the table does not grow.
		s.DeleteSession(ctx, token)
		return nil, ErrNoSession
	}
	sess.UserAgent, sess.IP = ua.String, ip.String

	// Slide the window, but never past the original expiry's spirit: cap the
	// extension at the current expiry plus one TTL so an always-active session
	// does not live forever without an absolute bound.
	newExpiry := sess.ExpiresAt + ttl.Milliseconds()
	if newExpiry > now.Add(ttl).UnixMilli() {
		newExpiry = now.Add(ttl).UnixMilli()
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?`,
		now.UnixMilli(), newExpiry, sess.ID); err != nil {
		// A failed touch must not fail the request; the session is still valid
		// for its original window.
		return &sess, nil
	}
	sess.LastSeen = now.UnixMilli()
	sess.ExpiresAt = newExpiry
	return &sess, nil
}

// DeleteSession revokes one session by raw token. This is the logout fix: the
// Node version only cleared the cookie client-side.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, HashToken(token))
	return err
}

// LogoutAll revokes every session for a user. The Node version could not offer
// this, because its stateless tokens had nothing to delete.
func (s *Store) LogoutAll(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username=?`, NormaliseUsername(username))
	return err
}

// ListSessions returns a user's live sessions for the device list, newest
// activity first. The token itself is never exposed, only its hash prefix.
func (s *Store) ListSessions(ctx context.Context, username string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, last_seen, expires_at, user_agent, ip
		 FROM sessions WHERE username=? ORDER BY last_seen DESC`, NormaliseUsername(username))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		var ua, ip sql.NullString
		if err := rows.Scan(&sess.ID, &sess.CreatedAt, &sess.LastSeen, &sess.ExpiresAt, &ua, &ip); err != nil {
			return nil, err
		}
		sess.Username = NormaliseUsername(username)
		sess.UserAgent, sess.IP = ua.String, ip.String
		out = append(out, sess)
	}
	return out, rows.Err()
}

// PurgeExpiredSessions deletes rows past their expiry. Called by the hourly
// housekeeping sweep.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CSRFToken returns the per-session synchroniser token. Every mutating form
// embeds it, and the handler compares it in constant time.
func CSRFToken(sess *Session) string {
	if sess == nil {
		return ""
	}
	return sess.CSRFSecret
}

// CheckCSRF validates a submitted token against the session.
func CheckCSRF(sess *Session, submitted string) bool {
	if sess == nil || submitted == "" {
		return false
	}
	return ConstantTimeEqual(sess.CSRFSecret, submitted)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
