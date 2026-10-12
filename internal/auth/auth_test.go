package auth

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derek/my-cloud/internal/crypt"
)

// testDB opens a fresh schema in a temp dir and returns a handle plus its path.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	// The schema lives in the sqlite package, which imports auth-adjacent code;
	// replicate via the exported Open to avoid an import cycle.
	db, err := openSchema(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func testSealer(t *testing.T) *crypt.Sealer {
	t.Helper()
	s, err := crypt.New(strings.Repeat("ab", 48))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected an argon2id PHC string, got %q", hash)
	}
	upgrade, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if upgrade {
		t.Fatal("an argon2id hash should not be flagged for upgrade")
	}
	if _, err := VerifyPassword("wrong password", hash); err != ErrInvalidCredentials {
		t.Fatalf("wrong password should fail, got %v", err)
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	// Identical passwords must not produce identical hashes.
	if a == b {
		t.Fatal("hashes are not salted")
	}
}

func TestVerifyAcceptsLegacyBcrypt(t *testing.T) {
	// A real bcrypt hash of "legacyuser", the format the migration carries.
	const legacy = "$2a$10$ooNkyIDRsEOPW84ztUESUuxQlyRmx37ww8JA8RJYT/eAZ/5Hvo9Vu"
	upgrade, err := VerifyPassword("password", legacy)
	if err != nil {
		t.Fatalf("legacy bcrypt rejected: %v", err)
	}
	// The whole point of lazy upgrade: this must be reported so the caller
	// can re-hash with argon2id.
	if !upgrade {
		t.Fatal("legacy bcrypt hash not flagged for upgrade")
	}
}

func TestVerifyUnknownFormatFails(t *testing.T) {
	if _, err := VerifyPassword("x", "not-a-hash"); err != ErrInvalidCredentials {
		t.Fatalf("unknown format should fail closed, got %v", err)
	}
}

func TestStoreVerifyPasswordUpgradesBcrypt(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()

	if _, err := s.CreateUser(ctx, "Alice", "secret123", true, 0); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Overwrite the hash with a legacy bcrypt row, as the migration would leave
	// a never-logged-in account.
	const legacy = "$2a$10$ooNkyIDRsEOPW84ztUESUuxQlyRmx37ww8JA8RJYT/eAZ/5Hvo9Vu"
	if _, err := db.Exec(`UPDATE users SET pw_hash=? WHERE username='alice'`, legacy); err != nil {
		t.Fatal(err)
	}

	u, err := s.VerifyPassword(ctx, "alice", "password")
	if err != nil {
		t.Fatalf("login with legacy hash failed: %v", err)
	}
	if !u.IsAdmin {
		t.Fatal("admin flag lost")
	}
	// The stored hash must now be argon2id — upgraded on first login, with
	// no forced password reset.
	var hash string
	if err := db.QueryRow(`SELECT pw_hash FROM users WHERE username='alice'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash not upgraded on login: %q", hash)
	}
}

func TestVerifyPasswordUnknownUserGivesSameError(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	// A wrong password and a nonexistent user must be indistinguishable.
	_, errWrong := s.VerifyPassword(ctx, "alice", "wrongpassword")
	_, errNoUser := s.VerifyPassword(ctx, "nobody", "wrongpassword")
	if errWrong != ErrInvalidCredentials || errNoUser != ErrInvalidCredentials {
		t.Fatalf("error mismatch: wrong=%v nouser=%v", errWrong, errNoUser)
	}
}

func TestUsernameValidation(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	good := []string{"ab", "alice", "user.name", "user-name", "user_name", "a1", strings.Repeat("a", 32)}
	for _, u := range good {
		if !validUsername(u) {
			t.Errorf("validUsername(%q) = false", u)
		}
	}
	bad := []string{"", "a", ".leading", "-leading", "_leading", "UPPER", "has space", "sym!bol", strings.Repeat("a", 33)}
	for _, u := range bad {
		if validUsername(u) {
			t.Errorf("validUsername(%q) = true", u)
		}
	}
	// Usernames are normalised, so "Alice" and "alice" are the same account.
	if _, err := s.CreateUser(ctx, "Bob", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "bob", "secret123", false, 0); err == nil {
		t.Fatal("duplicate account created after normalisation")
	}
}

func TestCreateUserValidatesPassword(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "short", false, 0); err == nil {
		t.Fatal("accepted a 5-character password")
	}
}

// --- Sessions ---

func TestSessionTokenNotStoredInPlaintext(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, sess, err := s.CreateSession(ctx, "alice", "Mozilla/5.0", "10.0.0.5", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// The raw token must not appear anywhere in the sessions table.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=?`, token).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("raw token stored as the session id")
	}
	// The row id is the SHA-256 of the token.
	if sess.ID != HashToken(token) {
		t.Fatal("session id is not the token hash")
	}
}

func TestLookupSessionValidatesToken(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupSession(ctx, token, time.Hour)
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if got.Username != "alice" {
		t.Fatalf("wrong user: %q", got.Username)
	}
	// A forged or unknown token must not resolve.
	if _, err := s.LookupSession(ctx, "forged-token", time.Hour); err != ErrNoSession {
		t.Fatalf("forged token accepted: %v", err)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	// The Node version could not do this: its tokens were stateless and only
	// the cookie was cleared client-side.
	if _, err := s.LookupSession(ctx, token, time.Hour); err != ErrNoSession {
		t.Fatal("session survived logout")
	}
}

func TestLogoutAllRevokesEveryDevice(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	var tokens []string
	for i := 0; i < 3; i++ {
		tok, _, err := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
	}
	if err := s.LogoutAll(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	for i, tok := range tokens {
		if _, err := s.LookupSession(ctx, tok, time.Hour); err != ErrNoSession {
			t.Fatalf("session %d survived logout-all", i)
		}
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry in the past.
	if _, err := db.Exec(`UPDATE sessions SET expires_at=? WHERE id=?`,
		time.Now().Add(-time.Hour).UnixMilli(), HashToken(token)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, token, time.Hour); err != ErrNoSession {
		t.Fatal("expired session accepted")
	}
}

func TestPasswordChangeInvalidatesSessions(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, "alice", "newsecret456"); err != nil {
		t.Fatal(err)
	}
	// A password change should end access everywhere.
	if _, err := s.LookupSession(ctx, token, 24*time.Hour); err != ErrNoSession {
		t.Fatal("session survived a password change")
	}
	// And the new password works while the old does not.
	if _, err := s.VerifyPassword(ctx, "alice", "newsecret456"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if _, err := s.VerifyPassword(ctx, "alice", "secret123"); err == nil {
		t.Fatal("old password still accepted")
	}
}

func TestCSRFTokensArePerSession(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	_, s1, _ := s.CreateSession(ctx, "alice", "UA", "1.1.1.1", time.Hour)
	_, s2, _ := s.CreateSession(ctx, "alice", "UA", "2.2.2.2", time.Hour)
	if s1.CSRFSecret == s2.CSRFSecret {
		t.Fatal("two sessions share a CSRF secret")
	}
	if !CheckCSRF(s1, s1.CSRFSecret) {
		t.Fatal("valid CSRF token rejected")
	}
	// A token from another session must not work.
	if CheckCSRF(s1, s2.CSRFSecret) {
		t.Fatal("CSRF token from another session accepted")
	}
	if CheckCSRF(s1, "") || CheckCSRF(nil, "x") {
		t.Fatal("empty or nil CSRF accepted")
	}
}

// --- TOTP ---

func TestVerifyTOTPCompatibility(t *testing.T) {
	// RFC 6238 test vector: secret "12345678901234567890" (base32
	// GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ) at T=59 gives 94287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(59, 0)
	got := hotp(secret, uint64(at.Unix()/30))
	if got != "287082" {
		t.Fatalf("HOTP = %q, want 287082 (RFC 4226 vector)", got)
	}
	// The same code must verify at that instant, and one step either side.
	if !VerifyTOTP(secret, "287082", at) {
		t.Fatal("valid TOTP rejected")
	}
	if !VerifyTOTP(secret, "287082", at.Add(30*time.Second)) {
		t.Fatal("code rejected one step ahead (skew)")
	}
	if VerifyTOTP(secret, "287082", at.Add(5*time.Minute)) {
		t.Fatal("code accepted far outside the skew window")
	}
}

func TestVerifyTOTPRejectsMalformedInput(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()
	for _, c := range []string{"", "12345", "1234567", "abcdef", "  ", "000000x"} {
		if VerifyTOTP(secret, c, now) {
			t.Errorf("malformed code %q accepted", c)
		}
	}
}

func TestTOTPStoreEnrolmentFlow(t *testing.T) {
	db := testDB(t)
	ts := NewTOTPStore(db, testSealer(t))
	ctx := context.Background()
	if _, err := NewStore(db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}

	secret, uri, err := ts.BeginSetup(ctx, "alice", "My Cloud")
	if err != nil {
		t.Fatalf("BeginSetup: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("unexpected otpauth URI: %q", uri)
	}
	// Nothing is active until confirmed.
	if ts.Enabled(ctx, "alice") {
		t.Fatal("TOTP active before confirmation")
	}
	// The pending secret must be sealed at rest, not stored in plaintext.
	var pending []byte
	if err := db.QueryRow(`SELECT pending FROM totp WHERE username='alice'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pending), secret) {
		t.Fatal("pending TOTP secret stored in plaintext")
	}

	// Confirming with a wrong code must fail.
	if _, err := ts.Confirm(ctx, "alice", "000000"); err == nil {
		t.Fatal("wrong code accepted")
	}

	// Confirm with a real code generated from the same secret.
	code := hotp(secret, uint64(time.Now().Unix()/30))
	codes, err := ts.Confirm(ctx, "alice", code)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(codes))
	}
	if !ts.Enabled(ctx, "alice") {
		t.Fatal("TOTP not enabled after confirmation")
	}
	// A fresh code from the now-active secret must verify.
	if !ts.Verify(ctx, "alice", hotp(secret, uint64(time.Now().Unix()/30))) {
		t.Fatal("active TOTP does not verify")
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	db := testDB(t)
	ts := NewTOTPStore(db, testSealer(t))
	ctx := context.Background()
	if _, err := NewStore(db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.BeginSetup(ctx, "alice", "My Cloud")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := ts.Confirm(ctx, "alice", hotp(secret, uint64(time.Now().Unix()/30)))
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Verify(ctx, "alice", codes[0]) {
		t.Fatal("recovery code rejected")
	}
	// Consumed: a replay must fail.
	if ts.Verify(ctx, "alice", codes[0]) {
		t.Fatal("recovery code was reusable")
	}
	// A different unused code still works.
	if !ts.Verify(ctx, "alice", codes[1]) {
		t.Fatal("second recovery code rejected")
	}
}

func TestDisableTOTPRemovesEverything(t *testing.T) {
	db := testDB(t)
	ts := NewTOTPStore(db, testSealer(t))
	ctx := context.Background()
	if _, err := NewStore(db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	secret, _, _ := ts.BeginSetup(ctx, "alice", "My Cloud")
	if _, err := ts.Confirm(ctx, "alice", hotp(secret, uint64(time.Now().Unix()/30))); err != nil {
		t.Fatal(err)
	}
	if err := ts.Disable(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if ts.Enabled(ctx, "alice") {
		t.Fatal("TOTP still enabled after disable")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE username='alice'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("recovery codes survived disable: %d", n)
	}
}

// --- App passwords ---

func TestAppPasswordCreateAndVerify(t *testing.T) {
	db := testDB(t)
	aps := NewAppPasswordStore(db)
	ctx := context.Background()
	if _, err := NewStore(db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	id, token, err := aps.Create(ctx, "alice", "Finder")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if id == "" || token == "" {
		t.Fatal("empty id or token")
	}
	u, ok := aps.VerifyAppPassword(ctx, "alice", token)
	if !ok || u.Username != "alice" {
		t.Fatal("app password did not authenticate")
	}
	if _, ok := aps.VerifyAppPassword(ctx, "alice", "wrong"); ok {
		t.Fatal("wrong app password accepted")
	}
	if _, ok := aps.VerifyAppPassword(ctx, "nobody", token); ok {
		t.Fatal("app password accepted for unknown user")
	}
	// The token must not be recoverable from the table.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_passwords WHERE pw_hash=?`, token).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("app password stored in plaintext")
	}
}

func TestAccountPasswordRejectedForDAVWhenTOTPOn(t *testing.T) {
	db := testDB(t)
	aps := NewAppPasswordStore(db)
	ts := NewTOTPStore(db, testSealer(t))
	ctx := context.Background()
	if _, err := NewStore(db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	secret, _, _ := ts.BeginSetup(ctx, "alice", "My Cloud")
	if _, err := ts.Confirm(ctx, "alice", hotp(secret, uint64(time.Now().Unix()/30))); err != nil {
		t.Fatal(err)
	}
	// With 2FA on, the account password must not work over Basic auth, or it
	// would be a second-factor bypass.
	if _, ok := aps.VerifyAppPassword(ctx, "alice", "secret123"); ok {
		t.Fatal("account password accepted for DAV while 2FA is enabled")
	}
	// An app password still does.
	_, token, _ := aps.Create(ctx, "alice", "rclone")
	if _, ok := aps.VerifyAppPassword(ctx, "alice", token); !ok {
		t.Fatal("app password rejected while 2FA enabled")
	}
}

// --- Rate limiting ---

func TestRateLimiterPerUsername(t *testing.T) {
	r := NewRateLimiter()
	// The username bucket allows 10 attempts before blocking.
	for i := 0; i < 10; i++ {
		if !r.Allow("1.2.3.4", "alice") {
			t.Fatalf("blocked at attempt %d, limit is 10", i)
		}
	}
	// The 11th, even from a different IP, must be blocked: per-username
	// limiting is what stops a distributed spray.
	if r.Allow("9.9.9.9", "alice") {
		t.Fatal("username spray from a new IP was allowed")
	}
	// A different username from the same IP is still fine while the IP bucket
	// has room.
	if !r.Allow("1.2.3.4", "bob") {
		t.Fatal("unrelated username blocked")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	r := NewRateLimiter()
	// 20 per IP across distinct usernames.
	for i := 0; i < 20; i++ {
		if !r.Allow("5.5.5.5", string(rune('a'+i))) {
			t.Fatalf("blocked at %d, IP limit is 20", i)
		}
	}
	if r.Allow("5.5.5.5", "zzz") {
		t.Fatal("per-IP limit not enforced")
	}
}

func TestRateLimiterClearsOnSuccess(t *testing.T) {
	r := NewRateLimiter()
	for i := 0; i < 10; i++ {
		r.Allow("1.1.1.1", "alice")
	}
	// A legitimate user who mistyped must not stay locked out.
	r.ClearLoginAttempts("alice")
	if !r.Allow("1.1.1.1", "alice") {
		t.Fatal("username bucket not cleared after login")
	}
}

func TestPublicLimiterIPv6Prefix(t *testing.T) {
	p := NewPublicLimiter(3, time.Minute)
	if !p.Allow("2001:db8:1:2::1") || !p.Allow("2001:db8:1:2::2") {
		t.Fatal("first two requests from the same /64 rejected")
	}
	if !p.Allow("2001:db8:1:2::3") {
		t.Fatal("third request rejected, limit is 3")
	}
	// A different address in the same /64 must not get a fresh budget: one
	// allocation should not be able to rotate addresses freely.
	if p.Allow("2001:db8:1:2::4") {
		t.Fatal("IPv6 /64 rotation bypassed the limiter")
	}
}

// --- Audit ---

func TestFindUserReportsTOTPState(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := NewStore(db)
	ts := NewTOTPStore(db, testSealer(t))
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	// Before enrolment.
	u, err := s.FindUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.HasTOTP {
		t.Fatal("HasTOTP true before enrolment")
	}

	// Enrol.
	secret, _, err := ts.BeginSetup(ctx, "alice", "My Cloud")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Confirm(ctx, "alice", hotp(secret, uint64(time.Now().Unix()/30))); err != nil {
		t.Fatal(err)
	}
	// After enrolment. /me renders this field, so a silently-false value
	// would tell a user their second factor is off when it is on.
	u2, err := s.FindUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !u2.HasTOTP {
		t.Fatal("HasTOTP false after enrolment; the 2FA status is misreported")
	}
	// And the same must hold through password verification, which is the path
	// login uses.
	vu, _, err := s.FindUserWithHash(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !vu.HasTOTP {
		t.Fatal("FindUserWithHash does not report TOTP state")
	}
}

func TestStagedTotpNotReportedAsEnrolled(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := NewStore(db)
	ts := NewTOTPStore(db, testSealer(t))
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	// Begin but do not confirm: the user has not proved they can generate a
	// code, so 2FA must not be reported as active.
	if _, _, err := ts.BeginSetup(ctx, "alice", "My Cloud"); err != nil {
		t.Fatal(err)
	}
	u, err := s.FindUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.HasTOTP {
		t.Fatal("unconfirmed enrolment reported as active")
	}
	if ts.Enabled(ctx, "alice") {
		t.Fatal("unconfirmed enrolment is enabled")
	}
}

func TestAuditLogWrites(t *testing.T) {
	db := testDB(t)
	logger := log.New(os.Stderr, "", 0)
	a := NewAuditLogger(db, logger)
	ctx := context.Background()
	a.Log(ctx, AuditEvent{Username: "alice", Action: "login.ok", IP: "1.2.3.4", OK: true})
	a.Log(ctx, AuditEvent{Username: "alice", Action: "login.fail", Detail: "bad password", IP: "1.2.3.4", OK: false})

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE username='alice'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 audit rows, got %d", n)
	}
	// Detail is bounded so a caller cannot write an unbounded blob.
	a.Log(ctx, AuditEvent{Username: "bob", Action: "x", Detail: strings.Repeat("z", 5000)})
	var detail string
	if err := db.QueryRow(`SELECT detail FROM audit_log WHERE username='bob'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail) > 200 {
		t.Fatalf("audit detail not bounded: %d bytes", len(detail))
	}
}

func TestDeleteUserCascades(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	token, _, _ := s.CreateSession(ctx, "alice", "UA", "1.2.3.4", time.Hour)
	aps := NewAppPasswordStore(db)
	aps.Create(ctx, "alice", "Finder")

	if err := s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	// The FK cascade must clear credentials, or a deleted user keeps access.
	if _, err := s.LookupSession(ctx, token, time.Hour); err != ErrNoSession {
		t.Fatal("session survived user deletion")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_passwords WHERE username='alice'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("app passwords survived user deletion")
	}
}
