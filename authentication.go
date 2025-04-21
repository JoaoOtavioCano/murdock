package main

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

const (
	ErrorUserNotFound               = "[Error] user not found"
	ErrorWrongPassword              = "[Error] wrong password"
	ErrorNotAbleToEncryptPassword   = "[Error] not able to encrypt password"
	ErrorNotAbleToIssueJWT          = "[Error] not able to issue JWT"
	ErrorEmptyPassword              = "[Error] empty password"
	ErrorFoundInWorstPassowordsList = "[Error] found in worst passwords list"
	ErrorEmptyEmail                 = "[Error] empty email"
)

type authMethod interface {
	validateCredentials() error
	login() ([]byte, error)
}

type EmailPasswordMethod struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (method *EmailPasswordMethod) validateCredentials() error {
	var err error
	err = isValidEmail(method.Email)
	if err != nil {
		return err
	}
	err = isValidPassword(method.Password)

	return err
}

func (method *EmailPasswordMethod) login() ([]byte, error) {
	var db Database
	user, err := db.GetUserByEmail(method.Email)
	if err != nil {
		return nil, fmt.Errorf(ErrorUserNotFound)
	}

	encryptedPassword, err := encryptPassword(method.Password, Pepper, user.Salt)
	if err != nil {
		return nil, fmt.Errorf(ErrorNotAbleToEncryptPassword)
	}
	if !isTheCorrectPassword(encryptedPassword, user.EncryptedPassword) {
		return nil, fmt.Errorf(ErrorWrongPassword)
	}

	jwt, err := issueJWT(user)
	if err != nil {
		return nil, fmt.Errorf(ErrorNotAbleToIssueJWT)
	}

	return jwt, nil

}

func login(method authMethod) ([]byte, error) {
	var err error

	if err = method.validateCredentials(); err != nil {
		return nil, err
	}

	jwt, err := method.login()
	if err != nil {
		return nil, err
	}

	return jwt, nil
}

func authenticate(jwt []byte) (bool, error) {
	var err error

	jwtSections := bytes.Split(jwt, []byte("."))

	header := jwtSections[0]
	payload := jwtSections[1]
	signature, err := base64UrlpDecode(jwtSections[2])
	if err != nil {
		return false, err
	}

	jwtContent := []byte(string(header) + "." + string(payload))
	expectedSignature := signJWT(jwtContent)

	signature = signature[:len(signature)-1]

	return hmac.Equal(signature, expectedSignature), nil
}

func isValidEmail(email string) error {
	if email == "" {
		return fmt.Errorf(ErrorEmptyEmail)
	}
	_, err := mail.ParseAddress(email)
	return err
}

func isValidPassword(password string) error {
	if password == "" {
		return fmt.Errorf(ErrorEmptyPassword)
	}

	found, err := isInThe10kWorstPasswords(password)
	if err != nil {
		return err
	}

	if found {
		return fmt.Errorf(ErrorFoundInWorstPassowordsList)
	}

	return nil
}

func isTheCorrectPassword(password01, password02 string) bool {
	if strings.Compare(password01, password02) != 0 {
		return false
	}

	return true
}

func encryptPassword(password, salt, pepper string) (string, error) {
	encryptedPassword, err := pbkdf2.Key(sha256.New, password+pepper, []byte(salt), 10000, 32)
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

	signature := signJWT(result)
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

func base64UrlpDecode(encodedData []byte) ([]byte, error) {
	encodedData = bytes.ReplaceAll(encodedData, []byte("-"), []byte("+"))
	encodedData = bytes.ReplaceAll(encodedData, []byte("_"), []byte("/"))
	if (len(encodedData) % 4) != 0 {
		for range 4 - len(encodedData)%4 {
			encodedData = append(encodedData, []byte("=")...)
		}
	}

	decodedData := make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))

	_, err := base64.StdEncoding.Decode(decodedData, encodedData)
	if err != nil {
		return nil, fmt.Errorf("[Error] unable to decode base 64 url")
	}

	return decodedData, nil

}

func isInThe10kWorstPasswords(password string) (bool, error) {
	data, err := os.ReadFile("10k-worst-passwords.txt")
	if err != nil {
		return false, fmt.Errorf("[Error] unable to read file")
	}

	return bytes.Contains(data, []byte(password)), nil
}

func signJWT(jwtContent []byte) []byte {
	secret := os.Getenv("JWT_SECRET")

	r := hmac.New(sha256.New, []byte(secret))
	r.Write(jwtContent)

	signature := r.Sum(nil)

	return signature
}

func (method *EmailPasswordMethod) createUser() error {
	err := method.validateCredentials()
	if err != nil {
		return err
	}

	user := newUser()
	user.Email = method.Email
	user.EncryptedPassword, err = encryptPassword(method.Password, user.Salt, Pepper)
	if err != nil {
		return err
	}

	return nil
}
