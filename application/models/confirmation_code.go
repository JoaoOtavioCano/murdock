package models

import (
	"crypto/rand"
	"math/big"
	"strings"
	"time"
)

const (
	maxGenNumber = 999_999
	TTLInMin     = 60
	codeBytesLen = 7
)

type ConfirmationCode struct {
	code     string
	expireAt time.Time
}

func NewConfirmationCode() (*ConfirmationCode, error) {
	code, err := generateCode()
	if err != nil {
		return nil, err
	}
	expireAt := time.Now().Add(TTLInMin * time.Minute)
	return &ConfirmationCode{code: code, expireAt: expireAt}, nil
}

func (c *ConfirmationCode) GetCode() string {
	return c.code
}

// https://pages.nist.gov/800-63-4/sp800-63b.html#issuedrecovery
// code SHALL include at least six decimal digits (or equivalent) from an approved random bit generator
// Issued recovery codes SHALL be valid for at most: 24 hours when sent to an email address
func generateCode() (string, error) {
	var count int
	builder := strings.Builder{}
	builder.Grow(codeBytesLen)

	max := big.NewInt(maxGenNumber)
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	numStr := num.String()
	leadingZeros := codeBytesLen - len(numStr) - 1
	if leadingZeros > 0 {
		for range leadingZeros {
			_, err := builder.WriteRune('0')
			if err != nil {
				return "", err
			}
			count++

			if count == 3 {
				_, err := builder.WriteRune('-')
				if err != nil {
					return "", err
				}
				count++
			}
		}
	}
	for _, r := range numStr {

		if count == 3 {
			_, err := builder.WriteRune('-')
			if err != nil {
				return "", err
			}
		}

		_, err := builder.WriteRune(r)
		if err != nil {
			return "", err
		}

		count++

	}

	return builder.String(), nil
}
