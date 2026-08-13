package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	tests := []struct {
		at       int64
		expected string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	item, err := parseTOTP("id", "test", "user", "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		if actual := item.code(time.Unix(test.at, 0)).Code; actual != test.expected {
			t.Errorf("code at %d = %s, want %s", test.at, actual, test.expected)
		}
	}
}

func TestBitwardenSourceUnlocksWithMasterPassword(t *testing.T) {
	unlocked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unlock" {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["password"] != "master-secret" {
				t.Error("wrong password")
			}
			unlocked = true
			fmt.Fprint(w, `{"success":true,"data":{}}`)
			return
		}
		if !unlocked {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"message":"Vault is locked."}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"data":{"data":[{"id":"id","name":"Login","login":{"totp":"JBSWY3DPEHPK3PXP"}}]}}`)
	}))
	defer server.Close()

	source := bitwardenSource{baseURL: server.URL, client: server.Client()}
	if _, err := source.list(context.Background()); !errors.Is(err, errBitwardenLocked) {
		t.Fatalf("got %v, want locked", err)
	}
	if err := source.unlock(context.Background(), "master-secret"); err != nil {
		t.Fatal(err)
	}
	items, err := source.list(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !unlocked || len(items) != 1 {
		t.Fatalf("unlocked=%v, items=%d", unlocked, len(items))
	}
}

func TestInactivityLocksVaultAndClearsCodes(t *testing.T) {
	locked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lock" {
			t.Errorf("path = %s", r.URL.Path)
		}
		locked = true
		fmt.Fprint(w, `{"success":true,"data":{}}`)
	}))
	defer server.Close()

	now := time.Now().UTC()
	store := &store{
		items:             []otpItem{{ID: "sms:1", Code: "123456", Source: "sms", ReceivedAt: now}},
		totpItems:         []totpItem{{ID: "totp", Secret: []byte("secret"), Period: 30, Digits: 6, Algorithm: "SHA1"}},
		status:            map[string]sourceStatus{"bitwarden": {OK: true}},
		bitwardenSource:   &bitwardenSource{baseURL: server.URL, client: server.Client()},
		inactivityTimeout: 5 * time.Minute,
		sessions:          map[string]time.Time{"expired-session-id-123456789012345": now.Add(-time.Minute)},
	}
	store.expireInactive(context.Background(), now)
	if !locked {
		t.Fatal("Bitwarden was not locked")
	}
	if !store.privacyLocked || len(store.items) != 0 || len(store.totpItems) != 0 {
		t.Fatalf("privacyLocked=%v items=%d totp=%d", store.privacyLocked, len(store.items), len(store.totpItems))
	}
	if !store.status["bitwarden"].RequiresUnlock {
		t.Fatal("unlock was not required")
	}
}

func TestActivityDefersInactivityLock(t *testing.T) {
	now := time.Now().UTC()
	session := "active-session-id-1234567890123456"
	store := &store{inactivityTimeout: 5 * time.Minute, sessions: map[string]time.Time{session: now.Add(time.Minute)}}
	store.recordActivity(session, now)
	store.expireInactive(context.Background(), now.Add(4*time.Minute))
	if store.privacyLocked {
		t.Fatal("active session was locked")
	}
}

func TestPrivacyLockBlocksReceivedCodes(t *testing.T) {
	now := time.Now().UTC()
	session := "authorized-session-id-123456789012"
	store := &store{privacyLocked: true, status: map[string]sourceStatus{}, maxAge: time.Hour, inactivityTimeout: 5 * time.Minute, sessions: map[string]time.Time{}, bitwardenSource: &bitwardenSource{}}
	store.mu.Lock()
	if !store.privacyLocked {
		t.Fatal("expected locked store")
	}
	store.mu.Unlock()

	result := store.snapshot("other-session-id-123456789012345")
	if !result.PrivacyLocked || len(result.Items) != 0 {
		t.Fatalf("privacyLocked=%v items=%d", result.PrivacyLocked, len(result.Items))
	}
	store.unlockPrivacy(session, now)
	if store.snapshot(session).PrivacyLocked {
		t.Fatal("successful unlock did not open workspace")
	}
}

func TestSessionIsolationHidesCodesFromOtherTabs(t *testing.T) {
	now := time.Now().UTC()
	owner := "owner-session-id-12345678901234567"
	other := "other-session-id-12345678901234567"
	store := &store{
		items:             []otpItem{{ID: "sms:1", Code: "123456", Source: "sms", ReceivedAt: now}},
		totpItems:         []totpItem{{ID: "totp", Secret: []byte("secret"), Period: 30, Digits: 6, Algorithm: "SHA1"}},
		status:            map[string]sourceStatus{"bitwarden": {OK: true}},
		bitwardenSource:   &bitwardenSource{},
		maxAge:            time.Hour,
		inactivityTimeout: 5 * time.Minute,
		sessions:          map[string]time.Time{owner: now.Add(5 * time.Minute)},
	}
	if got := store.snapshot(owner); got.PrivacyLocked || len(got.Items) != 2 {
		t.Fatalf("owner locked=%v items=%d", got.PrivacyLocked, len(got.Items))
	}
	if got := store.snapshot(other); !got.PrivacyLocked || len(got.Items) != 0 {
		t.Fatalf("other locked=%v items=%d", got.PrivacyLocked, len(got.Items))
	}
}

func TestParseTOTPRejectsHOTP(t *testing.T) {
	if _, err := parseTOTP("id", "test", "user", "otpauth://hotp/test?secret=GEZDGNBVGY3TQOJQ&counter=1"); err == nil {
		t.Fatal("expected HOTP to be rejected")
	}
}

func TestBitwardenSourceListsTOTPItems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/list/object/items" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer proxy-token" {
			t.Errorf("authorization header missing")
		}
		fmt.Fprint(w, `{"success":true,"data":{"data":[{"id":"vault-id","name":"Example","login":{"username":"user@example.com","totp":"JBSWY3DPEHPK3PXP"}},{"id":"plain","name":"No TOTP","login":{"username":"user"}}]}}`)
	}))
	defer server.Close()

	source := bitwardenSource{baseURL: server.URL, token: "proxy-token", client: server.Client()}
	items, err := source.list(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if items[0].Name != "Example" || items[0].Username != "user@example.com" {
		t.Fatalf("unexpected item: %+v", items[0])
	}
}
