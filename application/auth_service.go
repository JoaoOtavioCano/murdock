package application

import (
	"errors"
	"log"
	"time"

	"github.com/JoaoOtavioCano/murdock/application/models"
	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"

	_ "github.com/lib/pq"
)

type AuthService struct {
	jwtSecretKey         string
	database             outbound.Database
	loginThrottler       *LoginThrottler
	pepper               string
	notificationServices map[outbound.NotificationType]outbound.NotificationPort
	blockList            outbound.PasswordBlockListPort
}

func NewAuthService(db outbound.Database, lt *LoginThrottler, secKey, pepper string, notificationServices map[outbound.NotificationType]outbound.NotificationPort, blockList outbound.PasswordBlockListPort) *AuthService {
	return &AuthService{
		database:             db,
		loginThrottler:       lt,
		jwtSecretKey:         secKey,
		pepper:               pepper,
		notificationServices: notificationServices,
		blockList:            blockList,
	}
}

func (authSer *AuthService) Login(r inbound.AuthReq) ([]byte, error) {
	var authMethod authMethod
	switch r.Method {
	case "EmailPasswordMethod":
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey, nil, authSer.blockList)
		authMethod.parseAuthReq(r)
	default:
		return nil, customErr.AuthMethodNotFoundError{}
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
		case customErr.UserLockedError, customErr.UserExceededMaxNumOfAttemptsError, customErr.AccountPendingError:
			return nil, err
		default:
			return nil, customErr.SomethingWentWrongError{}
		}
	}

	return jwt, nil
}

func (authSer *AuthService) Check(r inbound.AuthReq) error {
	token := r.Data["token"]
	var authMethod authMethod
	switch r.Method {
	case "EmailPasswordMethod":
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey, nil, authSer.blockList)
	default:
		return customErr.AuthMethodNotFoundError{}
	}

	if token == "" {
		err := errors.New("token not found")
		log.Println(err)
		return err
	}
	authenticated, err := authMethod.authenticate([]byte(token))
	if err != nil {
		log.Println(err)
		return customErr.SomethingWentWrongError{}
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
		authMethod = newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey, authSer.notificationServices[outbound.EmailNotification], authSer.blockList)
		authMethod.parseAuthReq(r)
	default:
		return customErr.AuthMethodNotFoundError{}
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

func (authSer *AuthService) ConfirmationCodeValidation(digitalAddr, code string) error {
	if digitalAddr == "" || code == "" {
		errMsg := "digitalAddr and code cannot be empty strings"
		log.Println(errMsg)
		return errors.New(errMsg)
	}

	tx, err := authSer.database.BeginTx()
	if err != nil {
		log.Println(err)
		return customErr.SomethingWentWrongError{}
	}
	defer tx.Rollback()

	cc, err := authSer.database.GetConfirmationCode(code, digitalAddr, tx)
	if err != nil {
		log.Println(err)
		return customErr.SomethingWentWrongError{}
	}

	now := time.Now()

	if cc.GetExpireAt().Before(now) {
		return customErr.ConfirmationCodeExpiredError{}
	}

	switch cc.GetCodeType() {
	case models.TypeUpdateEmail:
		if err = authSer.database.UpdateUserEmail(cc.GetUserId(), cc.GetData(), tx); err != nil {
			log.Println(err)
			return customErr.SomethingWentWrongError{}
		}

	case models.TypeCreateAccount:
		if err = authSer.database.ActivateUser(cc.GetUserId(), tx); err != nil {
			log.Println(err)
			return customErr.SomethingWentWrongError{}
		}
	case models.TypeUpdatePassword:
		if err = authSer.database.UpdateUserPassword(cc.GetUserId(), cc.GetData(), tx); err != nil {
			log.Println(err)
			return customErr.SomethingWentWrongError{}
		}
	}

	if err = authSer.database.DeleteConfirmationCode(code, digitalAddr, tx); err != nil {
		log.Println(err)
		return customErr.SomethingWentWrongError{}
	}

	if err = tx.Commit(); err != nil {
		if err = tx.Commit(); err != nil {
			log.Println(err)
			return customErr.SomethingWentWrongError{}
		}
	}

	return nil
}

func (authSer *AuthService) ChangePasswordRequest(r inbound.AuthReq) error {
	authMethod := newEmailPasswordMethod(authSer.pepper, authSer.jwtSecretKey, authSer.notificationServices[outbound.EmailNotification], authSer.blockList)
	authMethod.parseAuthReq(r)
	log.Println(authMethod)

	err := authMethod.changePasswordRequest(authSer.database)
	if err != nil {
		log.Println(err)
		if _, ok := err.(customErr.UserNotFoundError); ok {
			return nil
		}
		return customErr.SomethingWentWrongError{}
	}

	return nil
}
