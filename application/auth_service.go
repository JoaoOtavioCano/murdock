package application

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/JoaoOtavioCano/murdock/application/models"
	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound/commands"
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

func (authSer *AuthService) Login(cmd commands.LoginCmd) ([]byte, error) {
	var authMethod authMethod
	switch aux := cmd.(type) {
	case commands.LoginCmdEmailPasswordMethod:
		authMethod = newEmailPasswordMethod(
			authSer.pepper,
			authSer.jwtSecretKey,
			nil,
			authSer.blockList,
			&aux.Email,
			&aux.Password,
		)
	default:
		return nil, customErr.AuthMethodNotFoundError{}
	}

	var jwt []byte
	// err := authMethod.validateCredentials()

	// if err == nil {
	// 	jwt, err = authMethod.login(authSer.database, authSer.loginThrottler)
	// }

	jwt, err := authMethod.login(authSer.database, authSer.loginThrottler)
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

func (authSer *AuthService) CheckSessionStatus(cmd commands.CheckSessionStatusCmd) error {
	token := cmd.GetToken()
	var authMethod authMethod
	switch cmd.(type) {
	case commands.CheckSessionStatusCmdEmailPasswordMethod:
		authMethod = newEmailPasswordMethod(
			authSer.pepper,
			authSer.jwtSecretKey,
			nil,
			authSer.blockList,
			nil,
			nil,
		)
	default:
		return customErr.AuthMethodNotFoundError{}
	}

	if token == "" {
		err := customErr.NoTokenReceivedError{}
		log.Println(err)
		return err
	}
	authenticated, err := authMethod.authenticate([]byte(token))
	if err != nil {
		log.Println(err)
		return customErr.SomethingWentWrongError{}
	}

	if !authenticated {
		return customErr.InvalidTokeError{}
	}

	return nil
}

func (authSer *AuthService) Signup(cmd commands.SignupCmd) error {
	var authMethod authMethod
	switch aux := cmd.(type) {
	case commands.SignupCmdEmailPasswordMethod:
		authMethod = newEmailPasswordMethod(
			authSer.pepper,
			authSer.jwtSecretKey,
			authSer.notificationServices[outbound.EmailNotification],
			authSer.blockList,
			&aux.Email,
			&aux.Password,
		)
	default:
		return customErr.AuthMethodNotFoundError{}
	}

	idGenerator := &UUIDv7Generator{}

	if err := authMethod.createUser(idGenerator, authSer.database); err != nil {
		return err
	}

	return nil
}

func (authSer *AuthService) Delete(cmd commands.DeleteCmd) error {
	if err := authSer.CheckSessionStatus(cmd.ToCheckSessionStatusCmd()); err != nil {
		log.Println("[Error authSer.Check] " + err.Error())
		return err
	}

	tx, err := authSer.database.BeginTx()
	if err != nil {
		log.Println("[Error database.BeginTx] " + err.Error())
		return customErr.SomethingWentWrongError{}
	}
	defer tx.Rollback()

	jwt := cmd.GetToken()
	jwtPayloadStart := strings.Index(jwt, ".") + 1
	jwtPayloadEnd := strings.LastIndex(jwt, ".")

	payload, err := base64UrlpDecode([]byte(jwt[jwtPayloadStart:jwtPayloadEnd]))
	if err != nil {
		log.Println("[Error base64UrlpDecode] " + err.Error())
		return customErr.SomethingWentWrongError{}
	}

	usr := models.NewUser()
	err = json.Unmarshal(payload, usr)
	if err != nil {
		log.Println("[Error json.Unmarshal] " + err.Error())
		return customErr.SomethingWentWrongError{}
	}

	err = authSer.database.DeleteUserInDB(usr.Id, tx)
	if err != nil {
		log.Println("[Error database.DeleteUserInDB] " + err.Error())
		return customErr.SomethingWentWrongError{}
	}

	if err = tx.Commit(); err != nil {
		if err = tx.Commit(); err != nil {
			return err
		}
	}

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

func (authSer *AuthService) ChangePasswordRequest(cmd commands.ChangePasswordRequestCmdEmailPasswordMethod) error {
	authMethod := newEmailPasswordMethod(
		authSer.pepper,
		authSer.jwtSecretKey,
		authSer.notificationServices[outbound.EmailNotification],
		authSer.blockList,
		&cmd.Email,
		&cmd.Password,
	)

	err := authMethod.changePasswordRequest(authSer.database)
	if err != nil {
		log.Println(err)
		switch err.(type) {
		case customErr.UserNotFoundError:
			return nil
		case customErr.FoundInBlocklistError:
			return err
		default:
			return customErr.SomethingWentWrongError{}
		}
	}

	return nil
}
