package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User is an account row.
type User struct {
	Username          string
	IsAdmin           bool
	QuotaMB           int // 0 = unlimited
	CreatedAt         int64
	PasswordChangedAt int64
	HasTOTP           bool
}

// ErrNoUsers is returned when setup is attempted on an already-provisioned
// installation.
var ErrNoUsers = errors.New("setup already completed")

// usernamePattern mirrors the Node USERNAME_RE: 2-32 chars, lowercase
// alphanumerics plus dot, dash, underscore, starting with alphanum.
func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 32 {
		return false
	}
	for i, r := range u {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			continue
		case r == '.' || r == '-' || r == '_':
			if i == 0 {
				return false
			}
			continue
		default:
			return false
		}
	}
	return true
}

// NormaliseUsername lowercases and trims, matching the Node version so the
// same account name resolves after cutover.
func NormaliseUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidatePassword enforces the Node minimum of 6 characters.
func ValidatePassword(pw string) error {
	if len(pw) < 6 {
		return errors.New("password must be at least 6 characters")
	}
	return nil
}

// Store is the authentication data access layer.
type Store struct {
	db *sql.DB
}

// NewStore wraps a database handle.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// CountUsers returns the number of accounts, used to decide whether the setup
// wizard is open.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a new account. The password is hashed with argon2id.
//
// defaultQuotaMB is applied when quota is 0, matching the Node behaviour where
// 0 means "use the server default".
func (s *Store) CreateUser(ctx context.Context, username, password string, isAdmin bool, quotaMB int) (*User, error) {
	username = NormaliseUsername(username)
	if !validUsername(username) {
		return nil, errors.New("username must be 2-32 chars: lowercase letters, numbers, dot, dash, underscore")
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	// Duplicate check first for a clear message; the PK constraint is still
	// the authority, and the UNIQUE error below is translated in case of a race.
	if _, err := s.FindUser(ctx, username); err == nil {
		return nil, errors.New("user already exists")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()

	var quota any
	if quotaMB > 0 {
		quota = quotaMB
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users(username, pw_hash, is_admin, quota_mb, created_at, password_changed_at)
		 VALUES(?,?,?,?,?,?)`,
		username, hash, boolInt(isAdmin), quota, now, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, errors.New("user already exists")
		}
		return nil, fmt.Errorf("auth: insert user: %w", err)
	}
	return &User{
		Username: username, IsAdmin: isAdmin, QuotaMB: quotaMB,
		CreatedAt: now, PasswordChangedAt: now,
	}, nil
}

// FindUser loads one account, including whether a second factor is active.
//
// HasTOTP is resolved here rather than left zero-valued: handlers such as /me
// render the user's 2FA state, and a silently-false field would tell a
// user their second factor is off when it is on.
func (s *Store) FindUser(ctx context.Context, username string) (*User, error) {
	username = NormaliseUsername(username)
	var u User
	var quota sql.NullInt64
	var hasTOTP int
	err := s.db.QueryRowContext(ctx,
		`SELECT u.username, u.is_admin, u.quota_mb, u.created_at, u.password_changed_at,
		        EXISTS(SELECT 1 FROM totp t WHERE t.username=u.username AND t.enabled=1)
		 FROM users u WHERE u.username=?`,
		username).Scan(&u.Username, &u.IsAdmin, &quota, &u.CreatedAt, &u.PasswordChangedAt, &hasTOTP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("auth: find user: %w", err)
	}
	u.QuotaMB = int(quota.Int64)
	u.HasTOTP = hasTOTP == 1
	return &u, nil
}

// FindUserWithHash returns the account and its stored hash, for verification.
func (s *Store) FindUserWithHash(ctx context.Context, username string) (*User, string, error) {
	username = NormaliseUsername(username)
	var u User
	var quota sql.NullInt64
	var hash string
	var hasTOTP int
	err := s.db.QueryRowContext(ctx,
		`SELECT u.username, u.pw_hash, u.is_admin, u.quota_mb, u.created_at, u.password_changed_at,
		        EXISTS(SELECT 1 FROM totp t WHERE t.username=u.username AND t.enabled=1)
		 FROM users u WHERE u.username=?`, username).
		Scan(&u.Username, &hash, &u.IsAdmin, &quota, &u.CreatedAt, &u.PasswordChangedAt, &hasTOTP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", sql.ErrNoRows
		}
		return nil, "", fmt.Errorf("auth: find user with hash: %w", err)
	}
	u.QuotaMB = int(quota.Int64)
	u.HasTOTP = hasTOTP == 1
	return &u, hash, nil
}

// ListUsers returns all accounts, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT username, is_admin, quota_mb, created_at, password_changed_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var quota sql.NullInt64
		if err := rows.Scan(&u.Username, &u.IsAdmin, &quota, &u.CreatedAt, &u.PasswordChangedAt); err != nil {
			return nil, err
		}
		u.QuotaMB = int(quota.Int64)
		out = append(out, u)
	}
	return out, rows.Err()
}

// VerifyPassword checks a password for a username and returns the user on
// success.
//
// A missing account burns a dummy bcrypt comparison so timing does not
// enumerate usernames, and both cases return the same error.
//
// On a successful bcrypt verification the hash is upgraded to argon2id in
// place. That is the whole lazy-upgrade mechanism: no forced reset, and the
// cost can be raised later without touching existing accounts.
func (s *Store) VerifyPassword(ctx context.Context, username, password string) (*User, error) {
	username = NormaliseUsername(username)
	u, hash, err := s.FindUserWithHash(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			DummyCompare()
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	needsUpgrade, verr := VerifyPassword(password, hash)
	if verr != nil {
		return nil, ErrInvalidCredentials
	}
	if needsUpgrade {
		newHash, herr := HashPassword(password)
		if herr != nil {
			// A failed upgrade must not block a valid login; the user can
			// still sign in and it will retry next time.
			return u, nil
		}
		if _, uerr := s.db.ExecContext(ctx,
			`UPDATE users SET pw_hash=? WHERE username=?`, newHash, username); uerr != nil {
			return u, nil
		}
	}
	return u, nil
}

// SetPassword replaces a user's password and bumps password_changed_at, which
// invalidates sessions issued before the change.
func (s *Store) SetPassword(ctx context.Context, username, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET pw_hash=?, password_changed_at=? WHERE username=?`,
		hash, time.Now().UnixMilli(), NormaliseUsername(username))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	// Drop every session for this user: a password change should end access
	// everywhere, not just on other devices the user has to remember.
	_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username=?`, NormaliseUsername(username))
	return err
}

// UpdateUser applies an admin patch.
func (s *Store) UpdateUser(ctx context.Context, username string, isAdmin *bool, quotaMB *int) error {
	sets := []string{}
	args := []any{}
	if isAdmin != nil {
		sets = append(sets, "is_admin=?")
		args = append(args, boolInt(*isAdmin))
	}
	if quotaMB != nil {
		sets = append(sets, "quota_mb=?")
		if *quotaMB > 0 {
			args = append(args, *quotaMB)
		} else {
			args = append(args, nil)
		}
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, NormaliseUsername(username))
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET `+strings.Join(sets, ", ")+` WHERE username=?`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteUser removes an account. Cascades clear sessions, app passwords, TOTP,
// recovery codes, and shares. User files stay on disk, matching the Node
// behaviour so an accidental deletion never destroys data.
func (s *Store) DeleteUser(ctx context.Context, username string) error {
	username = NormaliseUsername(username)
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username=?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// HashAppPassword is exported so the app-password generator can produce a
// verifier in the same argon2id format as pw_hash.
func HashAppPassword(pw string) (string, error) { return HashPassword(pw) }

// CompareAppPassword verifies an app password against a stored hash, accepting
// legacy bcrypt rows carried over by the migration.
func CompareAppPassword(hash, candidate string) (needsUpgrade bool, ok bool) {
	upgrade, err := VerifyPassword(candidate, hash)
	return upgrade, err == nil
}

// UpgradeAppPassword rewrites an app-password hash after a successful legacy
// verification.
func (s *Store) UpgradeAppPassword(ctx context.Context, id, newHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE app_passwords SET pw_hash=? WHERE id=?`, newHash, id)
	return err
}

// HashRecoveryCode hashes a recovery code for storage. Recovery codes stay
// bcrypt: they are low-entropy, verified in a loop, and argon2 at interactive
// cost would be the wrong trade on that path.
func HashRecoveryCode(code string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
	return string(b), err
}

// CompareRecoveryCode verifies a code against a bcrypt hash.
func CompareRecoveryCode(hash, code string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
