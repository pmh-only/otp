package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed public
var publicFiles embed.FS

type config struct {
	Port              int
	PollInterval      time.Duration
	MaxAge            time.Duration
	ConnectURL        string
	ConnectToken      string
	MailURL           string
	MailToken         string
	BitwardenURL      string
	BitwardenToken    string
	InactivityTimeout time.Duration
}

type representation struct {
	MediaType string `json:"media_type"`
}

type resource struct {
	Name            string           `json:"name"`
	CollectionURL   string           `json:"collection_url"`
	Representations []representation `json:"representations"`
}

type discovery struct {
	Protocol struct {
		Version string `json:"version"`
	} `json:"protocol"`
	Resources []resource `json:"resources"`
}

type collection struct {
	Items []json.RawMessage `json:"items"`
}

type rostackSource struct {
	discoveryURL string
	token        string
	resourceName string
	client       *http.Client
	mu           sync.Mutex
	resource     *resource
}

type otpItem struct {
	ID         string     `json:"id"`
	Code       string     `json:"code"`
	Source     string     `json:"source"`
	Sender     string     `json:"sender"`
	Title      string     `json:"title"`
	ReceivedAt time.Time  `json:"receivedAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

type sourceStatus struct {
	OK             bool       `json:"ok"`
	CheckedAt      *time.Time `json:"checkedAt"`
	Error          string     `json:"error,omitempty"`
	RequiresUnlock bool       `json:"requiresUnlock,omitempty"`
}

type snapshot struct {
	Items         []otpItem               `json:"items"`
	Sources       map[string]sourceStatus `json:"sources"`
	RefreshedAt   time.Time               `json:"refreshedAt"`
	PrivacyLocked bool                    `json:"privacyLocked"`
}

type store struct {
	mu                sync.RWMutex
	refreshMu         sync.Mutex
	items             []otpItem
	status            map[string]sourceStatus
	maxAge            time.Duration
	smsSource         *rostackSource
	mailSource        *rostackSource
	bitwardenSource   *bitwardenSource
	totpItems         []totpItem
	inactivityTimeout time.Duration
	lastActivity      time.Time
	privacyLocked     bool
}

func main() {
	if err := loadDotEnv(".env"); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	cfg, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	store := &store{
		maxAge:            cfg.MaxAge,
		status:            map[string]sourceStatus{"sms": {}, "mail": {}, "bitwarden": {}},
		smsSource:         &rostackSource{discoveryURL: cfg.ConnectURL, token: cfg.ConnectToken, resourceName: "sms-messages", client: client},
		mailSource:        &rostackSource{discoveryURL: cfg.MailURL, token: cfg.MailToken, resourceName: "mailbox-entries", client: client},
		inactivityTimeout: cfg.InactivityTimeout,
		lastActivity:      time.Now().UTC(),
	}
	if cfg.BitwardenURL != "" {
		store.bitwardenSource = &bitwardenSource{baseURL: cfg.BitwardenURL, token: cfg.BitwardenToken, client: client}
		store.privacyLocked = true
		checkedAt := time.Now().UTC()
		store.status["bitwarden"] = sourceStatus{CheckedAt: &checkedAt, Error: errBitwardenLocked.Error(), RequiresUnlock: true}
	} else {
		delete(store.status, "bitwarden")
	}
	store.refresh(context.Background())
	go func() {
		ticker := time.NewTicker(cfg.PollInterval)
		defer ticker.Stop()
		for range ticker.C {
			store.refresh(context.Background())
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			store.expireInactive(context.Background(), time.Now().UTC())
		}
	}()

	assets, err := fs.Sub(publicFiles, "public")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/otps", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.snapshot())
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		streamSnapshots(w, r, store)
	})
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		store.refresh(r.Context())
		writeJSON(w, http.StatusOK, store.snapshot())
	})
	mux.HandleFunc("POST /api/activity", func(w http.ResponseWriter, _ *http.Request) {
		store.recordActivity(time.Now().UTC())
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/bitwarden/unlock", func(w http.ResponseWriter, r *http.Request) {
		if store.bitwardenSource == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Bitwarden is not configured"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var input struct {
			Password string `json:"password"`
		}
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&input) != nil || input.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Master password is required"})
			return
		}
		if err := store.bitwardenSource.unlock(r.Context(), input.Password); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unable to unlock vault"})
			return
		}
		store.unlockPrivacy(time.Now().UTC())
		store.refresh(r.Context())
		writeJSON(w, http.StatusOK, store.snapshot())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.Handle("GET /", http.FileServerFS(assets))

	address := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("OTP inbox listening on %s", address)
	log.Fatal(http.ListenAndServe(address, secureHeaders(mux)))
}

func (s *rostackSource) list(ctx context.Context) ([]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resource == nil {
		if err := s.discover(ctx); err != nil {
			return nil, err
		}
	}
	items, status, err := s.fetchCollection(ctx)
	if err == nil || (status != http.StatusNotFound && status != http.StatusNotAcceptable) {
		return items, err
	}
	if err := s.discover(ctx); err != nil {
		return nil, err
	}
	items, _, err = s.fetchCollection(ctx)
	return items, err
}

func (s *rostackSource) discover(ctx context.Context) error {
	var document discovery
	if _, err := s.request(ctx, s.discoveryURL, false, &document); err != nil {
		return err
	}
	if document.Protocol.Version != "rostack_v1" {
		return fmt.Errorf("%s does not advertise rostack_v1", s.discoveryURL)
	}
	for _, candidate := range document.Resources {
		if candidate.Name == s.resourceName {
			copy := candidate
			s.resource = &copy
			return nil
		}
	}
	return fmt.Errorf("resource %s is not advertised by %s", s.resourceName, s.discoveryURL)
}

func (s *rostackSource) fetchCollection(ctx context.Context) ([]json.RawMessage, int, error) {
	parsed, err := url.Parse(s.resource.CollectionURL)
	if err != nil {
		return nil, 0, err
	}
	query := parsed.Query()
	query.Set("limit", "100")
	parsed.RawQuery = query.Encode()
	var result collection
	status, err := s.request(ctx, parsed.String(), true, &result)
	return result.Items, status, err
}

func (s *rostackSource) request(ctx context.Context, endpoint string, authenticated bool, target any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	if authenticated {
		request.Header.Set("Authorization", "Rostack-Token "+s.token)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("Rostack request failed with %d", response.StatusCode)
	}
	return response.StatusCode, json.NewDecoder(response.Body).Decode(target)
}

func (s *store) refresh(ctx context.Context) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	var wait sync.WaitGroup
	count := 2
	if s.bitwardenSource != nil {
		count++
	}
	wait.Add(count)
	go func() {
		defer wait.Done()
		s.refreshSource(ctx, "sms", s.smsSource, normalizeSMS)
	}()
	if s.bitwardenSource != nil {
		go func() {
			defer wait.Done()
			s.refreshBitwarden(ctx)
		}()
	}
	go func() {
		defer wait.Done()
		s.refreshSource(ctx, "mail", s.mailSource, normalizeMail)
	}()
	wait.Wait()
}

func (s *store) refreshSource(ctx context.Context, name string, source *rostackSource, normalize func([]json.RawMessage) []otpItem) {
	checkedAt := time.Now().UTC()
	records, err := source.list(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privacyLocked {
		return
	}
	if err != nil {
		s.status[name] = sourceStatus{CheckedAt: &checkedAt, Error: err.Error()}
		return
	}
	retained := make([]otpItem, 0, len(s.items))
	for _, item := range s.items {
		if item.Source != name {
			retained = append(retained, item)
		}
	}
	s.items = append(retained, normalize(records)...)
	s.status[name] = sourceStatus{OK: true, CheckedAt: &checkedAt}
	s.pruneLocked()
}

func (s *store) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	items := append([]otpItem(nil), s.items...)
	for _, item := range s.totpItems {
		items = append(items, item.code(time.Now().UTC()))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Source == "bitwarden" && items[j].Source != "bitwarden" {
			return true
		}
		if items[j].Source == "bitwarden" && items[i].Source != "bitwarden" {
			return false
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	if items == nil {
		items = []otpItem{}
	}
	statuses := make(map[string]sourceStatus, len(s.status))
	for name, status := range s.status {
		statuses[name] = status
	}
	return snapshot{Items: items, Sources: statuses, RefreshedAt: time.Now().UTC(), PrivacyLocked: s.privacyLocked}
}

func (s *store) recordActivity(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privacyLocked && s.bitwardenSource != nil {
		return
	}
	s.privacyLocked = false
	s.lastActivity = at
}

func (s *store) unlockPrivacy(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.privacyLocked = false
	s.lastActivity = at
}

func (s *store) expireInactive(ctx context.Context, now time.Time) {
	s.mu.Lock()
	if s.privacyLocked || now.Sub(s.lastActivity) < s.inactivityTimeout {
		s.mu.Unlock()
		return
	}
	s.privacyLocked = true
	s.items = nil
	s.totpItems = nil
	if _, ok := s.status["bitwarden"]; ok {
		checkedAt := now.UTC()
		s.status["bitwarden"] = sourceStatus{CheckedAt: &checkedAt, Error: errBitwardenLocked.Error(), RequiresUnlock: true}
	}
	s.mu.Unlock()

	if s.bitwardenSource != nil {
		if err := s.bitwardenSource.lock(ctx); err != nil {
			log.Printf("Bitwarden lock failed: %v", err)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func streamSnapshots(w http.ResponseWriter, r *http.Request, store *store) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		payload, err := json.Marshal(store.snapshot())
		if err != nil {
			return
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func readConfig() (config, error) {
	port, err := positiveInt("PORT", 3000)
	if err != nil {
		return config{}, err
	}
	poll, err := positiveInt("POLL_INTERVAL_MS", 15000)
	if err != nil {
		return config{}, err
	}
	maxAge, err := positiveInt("OTP_MAX_AGE_MS", 86400000)
	if err != nil {
		return config{}, err
	}
	inactivity, err := positiveInt("INACTIVITY_TIMEOUT_MS", 300000)
	if err != nil {
		return config{}, err
	}
	connectToken, err := requiredEnv("CONNECT_ROSTACK_TOKEN")
	if err != nil {
		return config{}, err
	}
	mailToken, err := requiredEnv("MAIL_ROSTACK_TOKEN")
	if err != nil {
		return config{}, err
	}
	bitwardenURL := strings.TrimRight(os.Getenv("BITWARDEN_API_URL"), "/")
	bitwardenToken := os.Getenv("BITWARDEN_API_TOKEN")
	return config{
		Port: port, PollInterval: time.Duration(poll) * time.Millisecond, MaxAge: time.Duration(maxAge) * time.Millisecond,
		ConnectURL: envOr("CONNECT_DISCOVERY_URL", "http://connect-service.connect.svc.cluster.local:8080/.well-known/rostack"), ConnectToken: connectToken,
		MailURL: envOr("MAIL_DISCOVERY_URL", "http://mailui.mail.svc.cluster.local:3000/.well-known/rostack"), MailToken: mailToken,
		BitwardenURL: bitwardenURL, BitwardenToken: bitwardenToken,
		InactivityTimeout: time.Duration(inactivity) * time.Millisecond,
	}, nil
}

func requiredEnv(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func positiveInt(name string, fallback int) (int, error) {
	value := envOr(name, strconv.Itoa(fallback))
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected NAME=value", path, lineNumber+1)
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "" {
			return fmt.Errorf("%s:%d: empty variable name", path, lineNumber+1)
		}
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		if _, exists := os.LookupEnv(name); !exists {
			os.Setenv(name, value)
		}
	}
	return nil
}
