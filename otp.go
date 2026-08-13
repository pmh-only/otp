package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	codePattern    = regexp.MustCompile(`[0-9]{4,8}`)
	englishTerm    = regexp.MustCompile(`(?i)(^|[^a-z0-9])(otp|code|one[ -]time( password| passcode)?|verification|verify|security|authentication|confirmation|login|sign[ -]?in|passcode|auth)([^a-z0-9]|$)`)
	koreanTerm     = regexp.MustCompile(`인증\s*(번호|코드)|확인\s*(번호|코드)|보안\s*(번호|코드)|로그인\s*(번호|코드)|일회용\s*비밀번호|본인\s*확인`)
	extraContext   = regexp.MustCompile(`(?i)(expires?|valid|minutes?|mins?|do not share|don't share|유효|만료|[0-9]+\s*분|공유하지|알려주지)`)
	koreanSuffixes = []string{"입니다", "이에요", "예요", "이며", "이고", "은", "는", "이", "가", "을", "를"}
)

type candidate struct {
	code  string
	score int
	index int
}

func extractOTP(text string) string {
	matches := codePattern.FindAllStringIndex(text, -1)
	candidates := make([]candidate, 0, len(matches))
	for _, match := range matches {
		if !validCodeBoundaries(text, match[0], match[1]) {
			continue
		}
		before := text[max(0, match[0]-64):match[0]]
		after := text[match[1]:min(len(text), match[1]+96)]
		score := 0
		if hasOTPTerm(before) {
			score += 3
		}
		if hasOTPTerm(after) {
			score += 2
		}
		if extraContext.MatchString(after) {
			score++
		}
		if match[1]-match[0] == 6 {
			score++
		}
		candidates = append(candidates, candidate{code: text[match[0]:match[1]], score: score, index: match[0]})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].index < candidates[j].index
		}
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > 0 && candidates[0].score >= 2 {
		return candidates[0].code
	}
	return ""
}

func hasOTPTerm(value string) bool {
	return englishTerm.MatchString(value) || koreanTerm.MatchString(value)
}

func validCodeBoundaries(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}
	remainder := text[end:]
	for _, suffix := range koreanSuffixes {
		if strings.HasPrefix(remainder, suffix) {
			remainder = remainder[len(suffix):]
			break
		}
	}
	if remainder == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(remainder)
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}

type smsRecord struct {
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
	Value      []struct {
		ID        int64  `json:"id"`
		Address   string `json:"address"`
		Body      string `json:"body"`
		Timestamp int64  `json:"timestamp"`
	} `json:"value"`
}

type mailEntry struct {
	ID         int64      `json:"id"`
	Subject    string     `json:"subject"`
	From       string     `json:"from"`
	Preview    string     `json:"preview"`
	ReceivedAt *time.Time `json:"receivedAt"`
}

func normalizeSMS(records []json.RawMessage) []otpItem {
	var result []otpItem
	for _, raw := range records {
		var record smsRecord
		if json.Unmarshal(raw, &record) != nil {
			continue
		}
		for _, message := range record.Value {
			code := extractOTP(message.Body)
			if code == "" {
				continue
			}
			title := record.DeviceName
			if title == "" {
				title = "SMS"
			}
			sender := message.Address
			if sender == "" {
				sender = "Unknown sender"
			}
			result = append(result, otpItem{ID: "sms:" + record.DeviceID + ":" + strconvFormat(message.ID), Code: code, Source: "sms", Sender: sender, Title: title, ReceivedAt: time.UnixMilli(message.Timestamp).UTC()})
		}
	}
	return result
}

func normalizeMail(records []json.RawMessage) []otpItem {
	var result []otpItem
	for _, raw := range records {
		var entry mailEntry
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}
		code := extractOTP(entry.Subject + "\n" + entry.Preview)
		if code == "" {
			continue
		}
		title := entry.Subject
		if title == "" {
			title = "Email verification code"
		}
		sender := entry.From
		if sender == "" {
			sender = "Unknown sender"
		}
		receivedAt := time.Unix(0, 0).UTC()
		if entry.ReceivedAt != nil {
			receivedAt = entry.ReceivedAt.UTC()
		}
		result = append(result, otpItem{ID: "mail:" + strconvFormat(entry.ID), Code: code, Source: "mail", Sender: sender, Title: title, ReceivedAt: receivedAt})
	}
	return result
}

func (s *store) pruneLocked() {
	cutoff := time.Now().Add(-s.maxAge)
	unique := make(map[string]otpItem, len(s.items))
	for _, item := range s.items {
		if !item.ReceivedAt.Before(cutoff) {
			unique[item.ID] = item
		}
	}
	s.items = s.items[:0]
	for _, item := range unique {
		s.items = append(s.items, item)
	}
	sort.Slice(s.items, func(i, j int) bool { return s.items[i].ReceivedAt.After(s.items[j].ReceivedAt) })
}

func strconvFormat(value int64) string {
	return strconv.FormatInt(value, 10)
}
