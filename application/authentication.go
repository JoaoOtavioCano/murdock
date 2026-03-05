package application

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

	"github.com/JoaoOtavioCano/murdock/application/models"
	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"
)

type authMethod interface {
	validateCredentials() error
	login(db outbound.Database, lt *LoginThrottler) ([]byte, error)
	createUser(idGenerator idGenerator, db outbound.Database) error
	authenticate(token []byte) (bool, error)
	parseAuthReq(inbound.AuthReq)
}

type EmailPasswordMethod struct {
	Email        string                    `json:"email"`
	Password     string                    `json:"password"`
	Validator    Validator                 `json:"-"`
	Pepper       string                    `json:"-"`
	jwtSecret    string                    `json:"-"`
	emailService outbound.NotificationPort `json:"-"`
}

func newEmailPasswordMethod(pepper, secKey string, emailService outbound.NotificationPort) *EmailPasswordMethod {
	return &EmailPasswordMethod{
		Validator:    newDefaultValidator(),
		Pepper:       pepper,
		jwtSecret:    secKey,
		emailService: emailService,
	}
}

func (method *EmailPasswordMethod) parseAuthReq(r inbound.AuthReq) {
	method.Email = r.Data["email"]
	method.Password = r.Data["password"]
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

func (method *EmailPasswordMethod) login(db outbound.Database, lt *LoginThrottler) ([]byte, error) {
	user, err := db.GetUserByEmailInDB(method.Email, nil)
	if err != nil {
		return nil, customErr.UserNotFoundError{}
	}

	if user.Status == models.StatusLocked {
		return nil, customErr.UserLockedError{}
	}
	encryptedPassword, err := EncryptPassword(method.Password, user.Salt, method.Pepper)
	if err != nil {
		return nil, customErr.NotAbleToEncryptPasswordError{}
	}
	if !isTheCorrectPassword(encryptedPassword, user.EncryptedPassword) {
		if err = lt.HandleLoginFailure(user.Id); err != nil {
			return nil, err
		}
		return nil, customErr.WrongPasswordError{}
	}

	jwt, err := issueJWT(user, method.jwtSecret)
	if err != nil {
		return nil, customErr.NotAbleToIssueJWTError{}
	}

	return jwt, nil
}

func (method *EmailPasswordMethod) authenticate(token []byte) (bool, error) {
	var err error

	jwtSections := bytes.Split(token, []byte("."))

	header := jwtSections[0]
	payload := jwtSections[1]
	signature, err := base64UrlpDecode(jwtSections[2])
	if err != nil {
		return false, err
	}

	jwtContent := []byte(string(header) + "." + string(payload))
	expectedSignature := signJWT(jwtContent, method.jwtSecret)

	signature = signature[:len(signature)-1]

	return hmac.Equal(signature, expectedSignature), nil
}

func isValidEmail(email string) error {
	if email == "" {
		return customErr.EmptyEmailError{}
	}
	_, err := mail.ParseAddress(email)
	return err
}

func isTheCorrectPassword(password01, password02 string) bool {
	return strings.Compare(password01, password02) == 0
}

// PBKDF2 of at least 10,000 iterations
// Link to NIST SP800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html#For%20PBKDF2,%20the%20cost%20factor%20is%20an%20iteration%20count:%20the%20more%20times%20the%20PBKDF2%20function%20is%20iterated,%20the%20longer%20it%20takes%20to%20compute%20the%20password%20hash.%20Therefore,%20the%20iteration%20count%20SHOULD%20be%20as%20large%20as%20verification%20server%20performance%20will%20allow,%20typically%20at%20least%2010,000%20iterations.:~:text=For%20PBKDF2%2C%20the%20cost%20factor%20is%20an%20iteration%20count%3A%20the%20more%20times%20the%20PBKDF2%20function%20is%20iterated%2C%20the%20longer%20it%20takes%20to%20compute%20the%20password%20hash.%20Therefore%2C%20the%20iteration%20count%20SHOULD%20be%20as%20large%20as%20verification%20server%20performance%20will%20allow%2C%20typically%20at%20least%2010%2C000%20iterations.
func EncryptPassword(password, salt, pepper string) (string, error) {
	encryptedPassword, err := pbkdf2.Key(sha256.New, password+pepper, []byte(salt), 10000, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedPassword), nil
}

// Json Web Token (JWT) implementation
// link: https://jwt.io/introduction
func issueJWT(payload any, jwtSecret string) ([]byte, error) {
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

	signature := signJWT(result, jwtSecret)
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

func signJWT(jwtContent []byte, jwtSecret string) []byte {
	r := hmac.New(sha256.New, []byte(jwtSecret))
	r.Write(jwtContent)

	signature := r.Sum(nil)

	return signature
}

func (method *EmailPasswordMethod) createUser(idGenerator idGenerator, db outbound.Database) error {
	err := method.validateCredentials()
	if err != nil {
		return err
	}

	user := models.NewUser()
	user.Id = hex.EncodeToString(idGenerator.generateId())
	user.Email = method.Email
	user.Salt = models.CreateSalt()
	user.Status = models.StatusPending
	user.EncryptedPassword, err = EncryptPassword(method.Password, user.Salt, method.Pepper)
	if err != nil {
		return err
	}

	dbTx, err := db.BeginTx()
	if err != nil {
		return err
	}
	defer dbTx.Rollback()

	if err = db.CreateUserInDB(*user, dbTx); err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			err = customErr.UserAlreadyExistsError{}
		}
		return err
	}

	code, err := models.NewConfirmationCode(user.Id, user.Email, models.TypeCreateAccount, "")
	if err != nil {
		return err
	}

	if err = db.SaveConfirmationCode(code, dbTx); err != nil {
		return err
	}

	dbTx.Commit()

	msg := fmt.Sprintf("Please use the following confirmation code to complete your setup. This code will expire in %d minutes.", models.TTLInMin)
	if err = method.emailService.SendConfirmationCode(user.Email, []byte(msg), code.GetCode()); err != nil {
		return err
	}

	return nil
}
