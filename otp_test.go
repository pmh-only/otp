package main

import "testing"

func TestExtractOTP(t *testing.T) {
	tests := []struct{ text, expected string }{
		{"Your verification code is 482901. Do not share it.", "482901"},
		{"OTP: 4432, valid for 5 minutes", "4432"},
		{"Use 82736419 as your login code", "82736419"},
		{"인증번호는 482901입니다. 타인에게 알려주지 마세요.", "482901"},
		{"로그인 코드: 4432 (5분간 유효)", "4432"},
		{"82736419은 본인 확인 번호입니다.", "82736419"},
		{"Your order 482901 shipped on 2026-08-13", ""},
		{"주문번호 482901 상품이 배송되었습니다", ""},
	}
	for _, test := range tests {
		if actual := extractOTP(test.text); actual != test.expected {
			t.Errorf("extractOTP(%q) = %q, want %q", test.text, actual, test.expected)
		}
	}
}
