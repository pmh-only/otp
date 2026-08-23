package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyManagerIsDisabledWithoutDataOrSetupToken(t *testing.T) {
	manager, err := newPasskeyManager(filepath.Join(t.TempDir(), "passkeys.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if manager != nil {
		t.Fatal("passkeys should be disabled")
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
	err := manager.saveLocked()
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
	loaded, err := newPasskeyManager(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.configured() || loaded.data.Origin != manager.data.Origin {
		t.Fatal("persisted passkey data was not restored")
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
