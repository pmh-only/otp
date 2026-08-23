package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyManagerIsDisabledWithoutDataOrSetupToken(t *testing.T) {
	manager, err := newPasskeyManager(filepath.Join(t.TempDir(), "passkeys.json"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if manager != nil {
		t.Fatal("passkeys should be disabled")
	}
}

func TestPasskeyManagerFailsClosedWhenRequiredDataIsMissing(t *testing.T) {
	manager, err := newPasskeyManager(filepath.Join(t.TempDir(), "passkeys.json"), "", true)
	if err == nil || manager != nil {
		t.Fatal("missing required passkey data did not prevent startup")
	}
}

func TestPasskeyOriginUsesAndPinsRequestHost(t *testing.T) {
	manager := &passkeyManager{}
	request := httptest.NewRequest("POST", "https://codes.example.com/api/passkeys/register/start", nil)
	request.Header.Set("Origin", "https://codes.example.com")
	origin, rpID, err := manager.requestOrigin(request)
	if err != nil {
		t.Fatal(err)
	}
	if origin != "https://codes.example.com" || rpID != "codes.example.com" {
		t.Fatalf("origin=%q rpID=%q", origin, rpID)
	}

	request.Header.Set("Origin", "https://attacker.example")
	if _, _, err := manager.requestOrigin(request); err == nil {
		t.Fatal("mismatched origin was accepted")
	}
}

func TestPasskeyDataPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "passkeys.json")
	manager := &passkeyManager{
		path: path,
		data: passkeyData{
			Origin:      "https://codes.example.com",
			RPID:        "codes.example.com",
			UserID:      []byte("stable-user-id"),
			Credentials: []webauthn.Credential{{ID: []byte("credential-id"), PublicKey: []byte("public-key")}},
		},
	}
	manager.mu.Lock()
	err := manager.saveLocked(manager.data)
	manager.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := newPasskeyManager(path, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.configured() || loaded.data.Origin != manager.data.Origin {
		t.Fatal("persisted passkey data was not restored")
	}
}

func TestPasskeyCommitKeepsPreviousStateWhenPersistenceFails(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := &passkeyManager{path: filepath.Join(parent, "passkeys.json"), data: passkeyData{Origin: "https://old.example"}}
	if err := manager.commitLocked(passkeyData{Origin: "https://new.example"}); err == nil {
		t.Fatal("commit unexpectedly succeeded")
	}
	if manager.data.Origin != "https://old.example" {
		t.Fatal("failed persistence changed in-memory state")
	}
}

func TestPasskeyCeremoniesArePrunedAndBounded(t *testing.T) {
	manager := &passkeyManager{ceremonies: make(map[string]passkeyCeremony)}
	for i := range maxPasskeyCeremonies {
		id := fmt.Sprintf("session-%d", i)
		manager.ceremonies[id] = passkeyCeremony{session: webauthn.SessionData{Expires: time.Now().Add(time.Minute)}}
	}
	ceremony := passkeyCeremony{session: webauthn.SessionData{Expires: time.Now().Add(time.Minute)}}
	if err := manager.storeCeremonyLocked("overflow", ceremony); err == nil {
		t.Fatal("ceremony limit was not enforced")
	}
	manager.ceremonies["session-0"] = passkeyCeremony{session: webauthn.SessionData{Expires: time.Now().Add(-time.Second)}}
	if err := manager.storeCeremonyLocked("replacement", ceremony); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyRegistrationRejectsCeremonyStartedBeforeEnrollment(t *testing.T) {
	session := "stale-registration-session"
	manager := &passkeyManager{
		data:       passkeyData{Credentials: []webauthn.Credential{{ID: []byte("enrolled")}}},
		ceremonies: map[string]passkeyCeremony{session: {kind: "register", session: webauthn.SessionData{Expires: time.Now().Add(time.Minute)}}},
	}
	if err := manager.finishRegistration(nil, session); err == nil || err.Error() != "initial passkey registration is already complete" {
		t.Fatalf("got %v", err)
	}
}

func TestPasskeySetupTokenComparison(t *testing.T) {
	manager := &passkeyManager{setupToken: "long-random-token"}
	if !manager.validSetupToken("long-random-token") {
		t.Fatal("valid setup token was rejected")
	}
	if manager.validSetupToken("wrong-token") {
		t.Fatal("invalid setup token was accepted")
	}
}
