package murdock

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"strings"
)

var Pepper = os.Getenv("PEPPER")

type authMethod interface {
	checkCredentials() error
	authenticate() error
}

type emailPasswordMethod struct {
	email    string
	password string
}

func (method *emailPasswordMethod) checkCredentials() error {
	var err error
	err = isValidEmail(method.email)
	if err != nil {
		return err
	}
	err = isValidPassword(method.password)

	return err
}

func (method *emailPasswordMethod) authenticate() ([]byte, error) {
	var db Database
	user, err := db.GetUserByEmail(method.email)
	if err != nil {
		return nil, fmt.Errorf("[Error] user not found")
	}

	encryptedPassword, err := encryptPassword(method.password, Pepper, user.Salt)
	if err != nil {
		return nil, fmt.Errorf("[Error] not able to encrypt password")
	}
	if !isTheCorrectPassword(encryptedPassword, user.EncryptedPassword) {
		return nil, fmt.Errorf("[Error] wrong password")
	}

	jwt, err := issueJWT(user)
	if err != nil {
		return nil, fmt.Errorf("[Error] not able to issue JWT")
	}

	return jwt, nil

}

func authenticate(method authMethod) error {
	var err error
	if err = method.checkCredentials(); err != nil {
		return err
	}

	if err = method.authenticate(); err != nil {
		return err
	}

	return nil
}

func isValidEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

func isValidPassword(password string) error {
	return nil
}

func isTheCorrectPassword(password01, password02 string) bool {
	if strings.Compare(password01, password02) != 0 {
		return false
	}

	return true
}

func encryptPassword(password, salt, pepper string) (string, error) {
	encryptedPassword, err := pbkdf2.Key(sha256.New, password+pepper, []byte(salt), 4096, 32)
	if err != nil {
		return "", err
	}
	return string(encryptedPassword), nil
}

func issueJWT(payload any) ([]byte, error) {
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: "HS256",
		Typ: "JWT",
	}

	secret := "a-string-secret-at-least-256-bits-long"

	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	headerBase64UrlEncoded := base64UrlEncode(jsonHeader)
	payloadBase64UrlEncoded := base64UrlEncode(jsonPayload)

	result := []byte(string(headerBase64UrlEncoded) + "." + string(payloadBase64UrlEncoded))
	r := hmac.New(sha256.New, []byte(secret))
	r.Write(result)

	signature := r.Sum([]byte(""))
	signatureBase64UrlEncoded := base64UrlEncode(signature)

	result = []byte(string(result) + "." + string(signatureBase64UrlEncoded))

	return result, nil

}

func base64UrlEncode(src []byte) []byte {
	base64Encoded := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(base64Encoded, src)

	base64UrlEncoded := bytes.ReplaceAll(base64Encoded, []byte("+"), []byte("-"))
	base64UrlEncoded = bytes.ReplaceAll(base64UrlEncoded, []byte("/"), []byte("_"))
	base64UrlEncoded = bytes.ReplaceAll(base64UrlEncoded, []byte("="), []byte(""))

	return base64UrlEncoded
}
