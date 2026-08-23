package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyData struct {
	Origin      string                `json:"origin"`
	RPID        string                `json:"rpId"`
	UserID      []byte                `json:"userId"`
	Credentials []webauthn.Credential `json:"credentials"`
}

type passkeyUser struct {
	data passkeyData
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.data.UserID }
func (u passkeyUser) WebAuthnName() string                       { return "otp-owner" }
func (u passkeyUser) WebAuthnDisplayName() string                { return "Code Relay owner" }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.data.Credentials }

type passkeyCeremony struct {
	kind    string
	origin  string
	session webauthn.SessionData
}

type passkeyManager struct {
	mu         sync.Mutex
	path       string
	setupToken string
	data       passkeyData
	ceremonies map[string]passkeyCeremony
}

func newPasskeyManager(path, setupToken string) (*passkeyManager, error) {
	manager := &passkeyManager{path: path, setupToken: setupToken, ceremonies: make(map[string]passkeyCeremony)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if setupToken == "" {
			return nil, nil
		}
		return manager, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read passkey data: %w", err)
	}
	if err := json.Unmarshal(data, &manager.data); err != nil {
		return nil, fmt.Errorf("decode passkey data: %w", err)
	}
	if manager.data.Origin == "" || manager.data.RPID == "" || len(manager.data.UserID) == 0 || len(manager.data.Credentials) == 0 {
		return nil, errors.New("passkey data is incomplete")
	}
	return manager, nil
}

func (m *passkeyManager) configured() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data.Credentials) > 0
}

func (m *passkeyManager) beginRegistration(r *http.Request, browserSession, setupToken string) (any, error) {
	if !validSessionID(browserSession) {
		return nil, errors.New("valid browser session is required")
	}
	if !m.validSetupToken(setupToken) {
		return nil, errors.New("invalid setup token")
	}
	origin, rpID, err := m.requestOrigin(r)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data.Credentials) > 0 {
		return nil, errors.New("initial passkey registration is already complete")
	}
	data := m.data
	if len(data.UserID) == 0 {
		data.UserID = make([]byte, 64)
		if _, err := rand.Read(data.UserID); err != nil {
			return nil, fmt.Errorf("create passkey user: %w", err)
		}
	}
	provider, err := newWebAuthn(rpID, origin)
	if err != nil {
		return nil, err
	}
	creation, session, err := provider.BeginRegistration(passkeyUser{data: data},
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(data.Credentials).CredentialDescriptors()),
	)
	if err != nil {
		return nil, err
	}
	m.data.UserID = data.UserID
	m.ceremonies[browserSession] = passkeyCeremony{kind: "register", origin: origin, session: *session}
	return creation, nil
}

func (m *passkeyManager) finishRegistration(r *http.Request, browserSession string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ceremony, ok := m.consumeCeremony(browserSession, "register")
	if !ok {
		return errors.New("registration ceremony expired or was not started")
	}
	provider, err := newWebAuthn(ceremony.session.RelyingPartyID, ceremony.origin)
	if err != nil {
		return err
	}
	credential, err := provider.FinishRegistration(passkeyUser{data: m.data}, ceremony.session, r)
	if err != nil {
		return err
	}
	m.data.Origin = ceremony.origin
	m.data.RPID = ceremony.session.RelyingPartyID
	m.data.Credentials = append(m.data.Credentials, *credential)
	return m.saveLocked()
}

func (m *passkeyManager) beginLogin(r *http.Request, browserSession string) (any, error) {
	if !validSessionID(browserSession) {
		return nil, errors.New("valid browser session is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data.Credentials) == 0 {
		return nil, errors.New("no passkey is registered")
	}
	if err := m.validateStoredOrigin(r); err != nil {
		return nil, err
	}
	provider, err := newWebAuthn(m.data.RPID, m.data.Origin)
	if err != nil {
		return nil, err
	}
	assertion, session, err := provider.BeginLogin(passkeyUser{data: m.data}, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	m.ceremonies[browserSession] = passkeyCeremony{kind: "login", origin: m.data.Origin, session: *session}
	return assertion, nil
}

func (m *passkeyManager) finishLogin(r *http.Request, browserSession string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ceremony, ok := m.consumeCeremony(browserSession, "login")
	if !ok {
		return errors.New("login ceremony expired or was not started")
	}
	provider, err := newWebAuthn(m.data.RPID, m.data.Origin)
	if err != nil {
		return err
	}
	credential, err := provider.FinishLogin(passkeyUser{data: m.data}, ceremony.session, r)
	if err != nil {
		return err
	}
	for i := range m.data.Credentials {
		if bytes.Equal(m.data.Credentials[i].ID, credential.ID) {
			m.data.Credentials[i] = *credential
			return m.saveLocked()
		}
	}
	return errors.New("authenticated credential was not found")
}

func (m *passkeyManager) consumeCeremony(browserSession, kind string) (passkeyCeremony, bool) {
	ceremony, ok := m.ceremonies[browserSession]
	delete(m.ceremonies, browserSession)
	return ceremony, ok && ceremony.kind == kind && ceremony.session.Expires.After(time.Now())
}

func (m *passkeyManager) validSetupToken(value string) bool {
	return m.setupToken != "" && len(value) == len(m.setupToken) && subtle.ConstantTimeCompare([]byte(value), []byte(m.setupToken)) == 1
}

func (m *passkeyManager) requestOrigin(r *http.Request) (string, string, error) {
	origin := r.Header.Get("Origin")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("valid browser origin is required")
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return "", "", errors.New("origin and request host do not match")
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(local && parsed.Scheme == "http") {
		return "", "", errors.New("passkeys require HTTPS except on localhost")
	}
	return parsed.Scheme + "://" + parsed.Host, parsed.Hostname(), nil
}

func (m *passkeyManager) validateStoredOrigin(r *http.Request) error {
	origin, rpID, err := m.requestOrigin(r)
	if err != nil {
		return err
	}
	if origin != m.data.Origin || rpID != m.data.RPID {
		return errors.New("request origin does not match the registered passkey origin")
	}
	return nil
}

func (m *passkeyManager) saveLocked() error {
	data, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	temporary := m.path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(temporary, m.path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

func newWebAuthn(rpID, origin string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "Code Relay",
		RPID:          rpID,
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true},
			Registration: webauthn.TimeoutConfig{Enforce: true},
		},
	})
}
