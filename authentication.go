package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

const (
	ErrorUserNotFound             = "[Error] user not found"
	ErrorWrongPassword            = "[Error] wrong password"
	ErrorNotAbleToEncryptPassword = "[Error] not able to encrypt password"
	ErrorNotAbleToIssueJWT        = "[Error] not able to issue JWT"
	ErrorEmptyPassword            = "[Error] empty password"
	ErrorFoundInBlocklist         = "[Error] password found in blocklist"
	ErrorEmptyEmail               = "[Error] empty email"
	ErrorUserAlreadyExists        = "[Error] user already exists"
	ErrorUserLocked               = "user is locked"
)

type authMethod interface {
	validateCredentials() error
	login(db *Database, lt *LoginThrottler) ([]byte, error)
	createUser(idGenerator idGenerator, db Database) error
}

type EmailPasswordMethod struct {
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Validator Validator `json:"-"`
}

func (method *EmailPasswordMethod) validateCredentials() error {
	var err error
	err = isValidEmail(method.Email)
	if err != nil {
		return err
	}

	err = method.Validator.validatePassword(&method.Password)

	return err
}

func (method *EmailPasswordMethod) login(db *Database, lt *LoginThrottler) ([]byte, error) {
	tx, err := db.con.Begin()
	if err != nil {
		return nil, fmt.Errorf("[Error][EmailPasswordMethod.login] %s", err)
	}
	user, err := getUserByEmailInDB(tx, method.Email)
	if err != nil {
		return nil, errors.New(ErrorUserNotFound)
	}

	if user.Status == "locked" {
		return nil, errors.New(ErrorUserLocked)
	}
	encryptedPassword, err := encryptPassword(method.Password, user.Salt, Pepper)
	if err != nil {
		return nil, errors.New(ErrorNotAbleToEncryptPassword)
	}
	if !isTheCorrectPassword(encryptedPassword, user.EncryptedPassword) {
		if err = lt.HandleLoginFailure(user.Id, db); err != nil {
			return nil, err
		}
		return nil, errors.New(ErrorWrongPassword)
	}

	jwt, err := issueJWT(user)
	if err != nil {
		return nil, errors.New(ErrorNotAbleToIssueJWT)
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
		return errors.New(ErrorEmptyEmail)
	}
	_, err := mail.ParseAddress(email)
	return err
}

func isTheCorrectPassword(password01, password02 string) bool {
	return strings.Compare(password01, password02) == 0
}

// PBKDF2 of at least 10,000 iterations
// Link to NIST SP800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html#For%20PBKDF2,%20the%20cost%20factor%20is%20an%20iteration%20count:%20the%20more%20times%20the%20PBKDF2%20function%20is%20iterated,%20the%20longer%20it%20takes%20to%20compute%20the%20password%20hash.%20Therefore,%20the%20iteration%20count%20SHOULD%20be%20as%20large%20as%20verification%20server%20performance%20will%20allow,%20typically%20at%20least%2010,000%20iterations.:~:text=For%20PBKDF2%2C%20the%20cost%20factor%20is%20an%20iteration%20count%3A%20the%20more%20times%20the%20PBKDF2%20function%20is%20iterated%2C%20the%20longer%20it%20takes%20to%20compute%20the%20password%20hash.%20Therefore%2C%20the%20iteration%20count%20SHOULD%20be%20as%20large%20as%20verification%20server%20performance%20will%20allow%2C%20typically%20at%20least%2010%2C000%20iterations.
func encryptPassword(password, salt, pepper string) (string, error) {
	encryptedPassword, err := pbkdf2.Key(sha256.New, password+pepper, []byte(salt), 10000, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedPassword), nil
}

// Json Web Token (JWT) implementation
// link: https://jwt.io/introduction
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
		return nil, errors.New("[Error] unable to decode base 64 url")
	}

	return decodedData, nil
}

func signJWT(jwtContent []byte) []byte {
	r := hmac.New(sha256.New, []byte(jwtSecret))
	r.Write(jwtContent)

	signature := r.Sum(nil)

	return signature
}

func (method *EmailPasswordMethod) createUser(idGenerator idGenerator, db Database) error {
	err := method.validateCredentials()
	if err != nil {
		return err
	}

	user := newUser()
	user.Id = hex.EncodeToString(idGenerator.generateId())
	user.Email = method.Email
	user.Salt = createSalt()
	user.Status = "active"
	user.EncryptedPassword, err = encryptPassword(method.Password, user.Salt, Pepper)
	if err != nil {
		return err
	}

	tx, err := db.con.Begin()
	if err != nil {
		return err
	}

	if err = crateUserInDB(tx, *user); err != nil {
		tx.Rollback()
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			err = errors.New(ErrorUserAlreadyExists)
		}
		return err
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}

	return nil
}
