package application

import (
	"errors"
	"log"

	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"

	_ "github.com/lib/pq"
)

type AuthService struct {
	jwtSecretKey   string
	database       outbound.Database
	loginThrottler *LoginThrottler
	pepper         string
}

func NewAuthService(db outbound.Database, lt *LoginThrottler, secKey, pepper string) *AuthService {
	return &AuthService{
		database:       db,
		loginThrottler: lt,
		jwtSecretKey:   secKey,
		pepper:         pepper,
	}
}

func (authSer *AuthService) Login(r inbound.AuthReq) ([]byte, error) {
	var authMethod authMethod
	switch r.Method {
	case "EmailPasswordMethod":
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey)
		authMethod.parseAuthReq(r)
	default:
		return nil, errors.New("authentication method not found")
	}

	var jwt []byte
	err := authMethod.validateCredentials()

	if err == nil {
		jwt, err = authMethod.login(authSer.database, authSer.loginThrottler)
	}

	if err != nil {
		log.Println(err.Error())
		switch err.(type) {
		case customErr.UserNotFoundError, customErr.WrongPasswordError:
			return nil, errors.New("invalid email and/or password")
		case customErr.EmptyPasswordError, customErr.EmptyEmailError:
			return nil, errors.New("missing values")
		case customErr.UserLockedError, customErr.UserExceededMaxNumOfAttemptsError:
			return nil, err
		default:
			return nil, errors.New("somethig went wrong")
		}
	}

	return jwt, nil
}

func (authSer *AuthService) Check(r inbound.AuthReq) error {
	token := r.Data["token"]
	var authMethod authMethod
	switch r.Method {
	case "EmailPasswordMethod":
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey)
	default:
		return errors.New("authentication method not found")
	}

	if token == "" {
		err := errors.New("token not found")
		log.Println(err.Error())
		return err
	}
	authenticated, err := authMethod.authenticate([]byte(token))
	if err != nil {
		log.Println(err)
		return errors.New("somethig went wrong")
	}

	if !authenticated {
		return errors.New("invalid token")
	}

	return nil
}

func (authSer *AuthService) Signup(r inbound.AuthReq) error {
	var authMethod authMethod
	switch r.Method {
	case "EmailPasswordMethod":
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey)
		authMethod.parseAuthReq(r)
	default:
		return errors.New("authentication method not found")
	}

	idGenerator := &UUIDv7Generator{}

	if err := authMethod.createUser(idGenerator, authSer.database); err != nil {
		return err
	}

	return nil
}

func (authSer *AuthService) Delete(r inbound.AuthReq) error {
	return nil
}
