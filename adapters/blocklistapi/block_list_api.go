package blocklistapi

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	url        = "https://api.pwnedpasswords.com/range"
	prefixSize = 5
)

type HaveIBeenPwnedAPIClient struct{ url string }

func NewHaveIBeenPwnedAPIClient() *HaveIBeenPwnedAPIClient {
	return &HaveIBeenPwnedAPIClient{
		url: url,
	}
}

func (c *HaveIBeenPwnedAPIClient) isInPasswordsBlocklist(password string) (bool, error) {
	s1 := sha1.New()
	s1.Write([]byte(password))
	passHash := s1.Sum(nil)
	passHashHex := strings.ToUpper(hex.EncodeToString(passHash))

	var runeCounter int
	var searchPrefix string
	sufix := make([]byte, 0, len(passHashHex)-prefixSize)
	for i, r := range passHashHex {
		if runeCounter == prefixSize {
			sufix = append(sufix, []byte(passHashHex[i:])...)
			break
		}
		searchPrefix += string(r)
		runeCounter++
	}

	client := http.Client{}
	resp, err := client.Get(c.url + "/" + searchPrefix)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("status code was not 200")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	return bytes.Contains(body, sufix), nil
}
