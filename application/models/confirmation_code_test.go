package models

import (
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewConfirmationCode(t *testing.T) {
	allowedVariation := 1 * time.Second
	now := time.Now()
	upperLim := now.Add(TTLInMin * time.Minute).Add(allowedVariation)
	lowerLim := now.Add(TTLInMin * time.Minute).Add(-allowedVariation)
	code, err := NewConfirmationCode("1", "example@email.com", TypeCreateAccount, "")
	if err != nil {
		t.Fatalf("error cresting new confirmation code: %v", err)
	}
	if code.expireAt.After(upperLim) || code.expireAt.Before(lowerLim) {
		t.Fatalf("expireAt outside the limit :\n\texpireAt: %s\n\tupperLim: %s\n\tloweLim: %s", code.expireAt.String(), upperLim.String(), lowerLim.String())
	}
}

func TestGenerateCode(t *testing.T) {
	for range 1_000_000 {
		code, err := generateCode()
		if err != nil {
			t.Fatalf("error generating code: %v", err)
		}
		if utf8.RuneCountInString(code) != 7 {
			t.Fatalf("error validating code:\n\tcode:%s\n", code)
		}
	}
}
