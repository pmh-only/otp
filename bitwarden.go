package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bitwardenSource struct {
	baseURL string
	token   string
	client  *http.Client
	mu      sync.Mutex
}

var errBitwardenLocked = errors.New("Bitwarden vault is locked")

type bitwardenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Data []bitwardenItem `json:"data"`
	} `json:"data"`
}

type bitwardenItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Favorite bool   `json:"favorite"`
	Login    *struct {
		Username string `json:"username"`
		TOTP     string `json:"totp"`
	} `json:"login"`
}

type totpItem struct {
	ID        string
	Name      string
	Username  string
	Secret    []byte
	Period    int64
	Digits    int
	Algorithm string
}

func (source *bitwardenSource) list(ctx context.Context) ([]totpItem, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.baseURL+"/list/object/items", nil)
	if err != nil {
		return nil, err
	}
	if source.token != "" {
		request.Header.Set("Authorization", "Bearer "+source.token)
	}
	request.Header.Set("Accept", "application/json")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var result bitwardenResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.Success || response.StatusCode < 200 || response.StatusCode >= 300 {
		if strings.Contains(strings.ToLower(result.Message), "locked") {
			return nil, errBitwardenLocked
		}
		return nil, fmt.Errorf("Bitwarden request failed: %s", result.Message)
	}
	items := make([]totpItem, 0)
	for _, item := range result.Data.Data {
		if item.Login == nil || strings.TrimSpace(item.Login.TOTP) == "" {
			continue
		}
		parsed, err := parseTOTP(item.ID, item.Name, item.Login.Username, item.Login.TOTP)
		if err != nil {
			continue
		}
		items = append(items, parsed)
	}
	return items, nil
}

func (source *bitwardenSource) unlock(ctx context.Context, password string) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, source.baseURL+"/unlock", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if source.token != "" {
		request.Header.Set("Authorization", "Bearer "+source.token)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result bitwardenResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if !result.Success || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Bitwarden unlock failed")
	}
	return nil
}

func (source *bitwardenSource) lock(ctx context.Context) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, source.baseURL+"/lock", nil)
	if err != nil {
		return err
	}
	if source.token != "" {
		request.Header.Set("Authorization", "Bearer "+source.token)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result bitwardenResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if !result.Success || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Bitwarden lock failed")
	}
	return nil
}

func parseTOTP(id, name, username, raw string) (totpItem, error) {
	result := totpItem{ID: id, Name: name, Username: username, Period: 30, Digits: 6, Algorithm: "SHA1"}
	secret := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
		parsed, err := url.Parse(secret)
		if err != nil {
			return result, err
		}
		if !strings.EqualFold(parsed.Host, "totp") {
			return result, fmt.Errorf("unsupported OTP type")
		}
		secret = parsed.Query().Get("secret")
		if value := parsed.Query().Get("period"); value != "" {
			result.Period, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return result, err
			}
		}
		if value := parsed.Query().Get("digits"); value != "" {
			result.Digits, err = strconv.Atoi(value)
			if err != nil {
				return result, err
			}
		}
		if value := parsed.Query().Get("algorithm"); value != "" {
			result.Algorithm = strings.ToUpper(value)
		}
	}
	if result.Period <= 0 || (result.Digits != 6 && result.Digits != 8) {
		return result, fmt.Errorf("unsupported TOTP parameters")
	}
	if result.Algorithm != "SHA1" && result.Algorithm != "SHA256" && result.Algorithm != "SHA512" {
		return result, fmt.Errorf("unsupported TOTP algorithm")
	}
	secret = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(secret, " ", ""), "-", ""))
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	if err != nil || len(decoded) == 0 {
		return result, fmt.Errorf("invalid TOTP secret")
	}
	result.Secret = decoded
	return result, nil
}

func (item totpItem) code(now time.Time) otpItem {
	counter := uint64(now.Unix() / item.Period)
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	var algorithm func() hash.Hash
	switch item.Algorithm {
	case "SHA256":
		algorithm = sha256.New
	case "SHA512":
		algorithm = sha512.New
	default:
		algorithm = sha1.New
	}
	mac := hmac.New(algorithm, item.Secret)
	mac.Write(message)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % pow10(item.Digits)
	expiresAt := time.Unix(int64(counter+1)*item.Period, 0).UTC()
	return otpItem{ID: "bitwarden:" + item.ID, Code: fmt.Sprintf("%0*d", item.Digits, value), Source: "bitwarden", Sender: item.Username, Title: item.Name, ReceivedAt: now, ExpiresAt: &expiresAt}
}

func pow10(digits int) uint32 {
	value := uint32(1)
	for range digits {
		value *= 10
	}
	return value
}

func (s *store) refreshBitwarden(ctx context.Context) {
	s.mu.RLock()
	privacyLocked := s.privacyLocked
	s.mu.RUnlock()
	if privacyLocked {
		return
	}
	checkedAt := time.Now().UTC()
	items, err := s.bitwardenSource.list(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privacyLocked {
		return
	}
	if err != nil {
		if errors.Is(err, errBitwardenLocked) {
			s.totpItems = nil
		}
		s.status["bitwarden"] = sourceStatus{CheckedAt: &checkedAt, Error: err.Error(), RequiresUnlock: errors.Is(err, errBitwardenLocked)}
		return
	}
	s.totpItems = items
	s.status["bitwarden"] = sourceStatus{OK: true, CheckedAt: &checkedAt}
}
