package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/text/unicode/norm"
)

type Validator interface {
	validatePassword(password *string) error
}

type (
	NISTSingleFactorPassworsValidator struct{}
	NISTMultiFactorPassworsValidator  struct{}
)

func newDefaultValidator() *NISTSingleFactorPassworsValidator {
	return new(NISTSingleFactorPassworsValidator)
}

// Requirements:
// Passwords as single factor authentication must require at least 15 characters ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
// Max length may be at least 64 characters. ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
// Verifiers SHOULD accept Unicode [ISO/ISC 10646] characters in passwords. Each Unicode code point SHALL be counted as a single character when evaluating password length.
// Verifiers SHALL NOT impose other composition rules (e.g., requiring mixtures of different character types) for passwords.
// If Unicode characters are accepted in passwords, the verifier SHOULD apply the normalization process for stabilized strings using the Normalization Form Canonical Composition (NFC)
func (v *NISTSingleFactorPassworsValidator) validatePassword(password *string) error {
	minLen := 15
	maxLen := 128

	if len(*password) < minLen {
		return fmt.Errorf("[Validation Error] password must be at least %d characters long", minLen)
	}
	if len(*password) > maxLen {
		return fmt.Errorf("[Validation Error] password must be at most %d characters long", maxLen)
	}

	*password = normalizeUnicodeString(*password)

	found, err := isInThePasswordsBlocklist(*password)
	if err != nil {
		return err
	}

	if found {
		return errors.New(ErrorFoundInBlocklist)
	}

	return nil
}

// Requirements:
// Verifiers MAY allow passwords that are only used as part of multi-factor authentication processes to be shorter but SHALL require them to be a minimum of eight characters in length ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
// Max length may be at least 64 characters. ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
// Verifiers SHOULD accept Unicode [ISO/ISC 10646] characters in passwords. Each Unicode code point SHALL be counted as a single character when evaluating password length.
// Verifiers SHALL NOT impose other composition rules (e.g., requiring mixtures of different character types) for passwords.
// If Unicode characters are accepted in passwords, the verifier SHOULD apply the normalization process for stabilized strings using the Normalization Form Canonical Composition (NFC)
func (NISTMultiFactorPassworsValidator) validatePassword(password *string) error {
	minLen := 8
	maxLen := 128

	if len(*password) < minLen {
		return fmt.Errorf("password must be at least %d characters long", minLen)
	}
	if len(*password) > maxLen {
		return fmt.Errorf("password must be at most %d characters long", maxLen)
	}

	*password = normalizeUnicodeString(*password)

	found, err := isInThePasswordsBlocklist(*password)
	if err != nil {
		return err
	}

	if found {
		return errors.New(ErrorFoundInBlocklist)
	}

	return nil
}

func normalizeUnicodeString(password string) string {
	return norm.NFC.String(password)
}

func isInThePasswordsBlocklist(password string) (bool, error) {
	data, err := os.ReadFile("10k-worst-passwords.txt")
	if err != nil {
		return false, errors.New("[Error] unable to read file")
	}

	return bytes.Contains(data, []byte(password)), nil
}
