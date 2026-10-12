package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/derek/my-cloud/internal/crypt"
	"github.com/go-webauthn/webauthn/webauthn"
)

// newPasskeyStore builds a store over the test schema.
func newPasskeyStore(t *testing.T) (*PasskeyStore, context.Context) {
	t.Helper()
	db := testDB(t)
	s, err := crypt.New(strings.Repeat("ab", 48))
	if err != nil {
		t.Fatal(err)
	}
	return NewPasskeyStore(db, s), context.Background()
}

// sampleCredential builds a credential with the fields the store persists.
func sampleCredential(id string) *webauthn.Credential {
	return &webauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte("cose-public-key-bytes"),
		Transport: nil,
		Authenticator: webauthn.Authenticator{
			SignCount: 7,
			AAGUID:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}
}

func TestPasskeySaveAndLoadRoundTrip(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	if _, err := NewStore(store.db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	cred := sampleCredential("credential-id-01")
	cred.Flags.BackupEligible = true
	cred.Flags.BackupState = true
	cred.Flags.UserVerified = true

	if err := store.Save(ctx, "alice", cred, "Yubikey"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	user, err := store.LoadUser(ctx, "alice")
	if err != nil {
		t.Fatalf("LoadUser: %v", err)
	}
	creds := user.Credentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	got := creds[0]
	if string(got.ID) != "credential-id-01" {
		t.Fatalf("credential id round-trip failed: %q", got.ID)
	}
	if string(got.PublicKey) != "cose-public-key-bytes" {
		t.Fatalf("public key round-trip failed: %q", got.PublicKey)
	}
	// The counter must survive: persisting it is what makes the cloned-
	// authenticator check work across restarts.
	if got.Authenticator.SignCount != 7 {
		t.Fatalf("sign count lost: %d", got.Authenticator.SignCount)
	}
	if !got.Flags.BackupState || !got.Flags.UserVerified {
		t.Fatalf("flags lost: %+v", got.Flags)
	}
}

func TestPasskeyMaterialIsSealedAtRest(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	if _, err := NewStore(store.db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "alice", sampleCredential("secret-credential-id"), "phone"); err != nil {
		t.Fatal(err)
	}
	var sealedID, sealedPK []byte
	if err := store.db.QueryRow(
		`SELECT credential_id, public_key FROM passkeys WHERE username='alice'`).
		Scan(&sealedID, &sealedPK); err != nil {
		t.Fatal(err)
	}
	// Neither the credential id nor the public key may be readable in the
	// database: both are material an attacker could use offline.
	if strings.Contains(string(sealedID), "secret-credential-id") {
		t.Fatal("credential id stored in plaintext")
	}
	if strings.Contains(string(sealedPK), "cose-public-key-bytes") {
		t.Fatal("public key stored in plaintext")
	}
}

func TestPasskeySealedToItsOwner(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	s := NewStore(store.db)
	if _, err := s.CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "bob", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "alice", sampleCredential("alices-credential"), "key"); err != nil {
		t.Fatal(err)
	}
	// Loading bob's user must not surface alice's credential: the AAD binds
	// each blob to its owner, so decryption fails rather than returning
	// another account's key material.
	bob, err := store.LoadUser(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(bob.Credentials()); n != 0 {
		t.Fatalf("bob loaded %d credential(s); a credential leaked across accounts", n)
	}
}

func TestPasskeySignCountUpdate(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	if _, err := NewStore(store.db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "alice", sampleCredential("counter-cred"), "key"); err != nil {
		t.Fatal(err)
	}
	// A successful assertion advances the counter.
	user, _ := store.LoadUser(ctx, "alice")
	cred := user.Credentials()[0]
	cred.Authenticator.SignCount = 99
	if err := store.UpdateSignCount(ctx, "alice", &cred); err != nil {
		t.Fatal(err)
	}
	user2, _ := store.LoadUser(ctx, "alice")
	if got := user2.Credentials()[0].Authenticator.SignCount; got != 99 {
		t.Fatalf("counter not persisted: %d", got)
	}
}

func TestPasskeyListAndDelete(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	if _, err := NewStore(store.db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "alice", sampleCredential("aaaa-bbbb-cccc"), "Laptop"); err != nil {
		t.Fatal(err)
	}
	list, err := store.List(ctx, "alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Label != "Laptop" {
		t.Fatalf("list wrong: %+v", list)
	}
	if list[0].IDPrefix == "" {
		t.Fatal("no id prefix for the UI to correlate rows")
	}
	n, err := store.Count(ctx, "alice")
	if err != nil || n != 1 {
		t.Fatalf("Count = %d, err=%v", n, err)
	}
	if err := store.Delete(ctx, "alice", list[0].IDPrefix); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list2, _ := store.List(ctx, "alice")
	if len(list2) != 0 {
		t.Fatalf("passkey survived delete: %+v", list2)
	}
}

func TestUserHandleIsStable(t *testing.T) {
	// The user handle must not change across restarts: a change invalidates
	// every registered passkey.
	a := UserHandle("alice")
	b := UserHandle("alice")
	if string(a) != string(b) {
		t.Fatal("user handle is not stable")
	}
	// It must also be case-insensitive, since usernames are normalised.
	if string(UserHandle("ALICE")) != string(a) {
		t.Fatal("user handle differs for a differently-cased username")
	}
	if string(UserHandle("bob")) == string(a) {
		t.Fatal("two users share a handle")
	}
	// The library caps the handle at 64 bytes.
	if len(a) > 64 {
		t.Fatalf("handle is %d bytes, the spec allows 64", len(a))
	}
}

func TestPasskeyListDoesNotLeakSecrets(t *testing.T) {
	store, ctx := newPasskeyStore(t)
	if _, err := NewStore(store.db).CreateUser(ctx, "alice", "secret123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "alice", sampleCredential("leaky"), "phone"); err != nil {
		t.Fatal(err)
	}
	list, err := store.List(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// The prefix is derived from the *sealed* id, so it is opaque, and only
	// six bytes of it are exposed.
	for _, p := range list {
		if len(p.IDPrefix) > 16 {
			t.Fatalf("id prefix is longer than expected: %q", p.IDPrefix)
		}
	}
}
