package application

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/JoaoOtavioCano/murdock/application/models"
	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
)

// ==========================================================
// Email Service Mock
// ==========================================================

type MockEmailService struct {
	sendNotificationFunc     func(address string, msg []byte) error
	sendConfirmationCodeFunc func(address string, msg []byte, code string) error
}

func (m *MockEmailService) SendNotification(address string, msg []byte) error {
	return m.sendNotificationFunc(address, msg)
}

func (m *MockEmailService) SendConfirmationCode(address string, msg []byte, code string) error {
	return m.sendConfirmationCodeFunc(address, msg, code)
}

func sendConfirmationCodeSuccess(address string, msg []byte, code string) error {
	fmt.Printf("Sending email\n\tto: %s\n\tmsg : %s\n\tcode:%s", address, string(msg), code)
	return nil
}

func sendConfirmationCodeError(address string, msg []byte, code string) error {
	return errors.New("email service failed to send confirmation code")
}

// ==========================================================
// Database Mock
// ==========================================================

type MockDB struct {
	getUserByEmailInDBFunc func(emailAddr string) (*models.User, error)
	createUserInDBFunc     func(u models.User) error
	lockUserFunc           func(usrID string) error
	deleteUserInDBFunc     func(id string) error
}

func (m *MockDB) GetUserByEmailInDB(emailAddr string) (*models.User, error) {
	return m.getUserByEmailInDBFunc(emailAddr)
}

func (m *MockDB) CreateUserInDB(u models.User) error {
	return m.createUserInDBFunc(u)
}

func (m *MockDB) LockUser(usrID string) error {
	return m.lockUserFunc(usrID)
}

func (m *MockDB) DeleteUserInDB(id string) error {
	return m.deleteUserInDBFunc(id)
}

func getUserByEmailInDBSuccess(emailAddr string) (*models.User, error) {
	return &models.User{
		Email: emailAddr,
	}, nil
}

func getUserByEmailInDBError(emailAddr string) (*models.User, error) {
	return nil, fmt.Errorf("error getting user by email: %s", emailAddr)
}

func createUserInDBSuccess(u models.User) error {
	fmt.Printf("User created in DB: %v\n", u)
	return nil
}

func createUserInDBError(u models.User) error {
	return errors.New("static generic database error")
}

func createUserInDBDuplicateKeyError(u models.User) error {
	return errors.New("duplicate key value violates unique constraint")
}

func lockUserSuccess(usrID string) error {
	fmt.Printf("User with ID %s locked successfully\n", usrID)
	return nil
}

func lockUserError(usrID string) error {
	return fmt.Errorf("error locking user with ID: %s", usrID)
}

func deleteUserInDBSuccess(id string) error {
	fmt.Printf("User with ID %s deleted successfully\n", id)
	return nil
}

func deleteUserInDBError(id string) error {
	return fmt.Errorf("error deleting user with ID: %s", id)
}

// ==========================================================
// Test cases
// ==========================================================

func TestCreateUserSuccess(t *testing.T) {
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeSuccess,
		},
		Email:    "example@email.com",
		Password: "password1234567890",
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBSuccess,
	}

	err := method.createUser(idGenerator, db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateUserReturnsUserAlreadyExistsErrorWhenDBDuplicateKeyErrorHappens(t *testing.T) {
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeSuccess,
		},
		Email:    "example@email.com",
		Password: "password1234567890",
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBDuplicateKeyError,
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned")
	}

	if _, ok := err.(customErr.UserAlreadyExistsError); !ok {
		t.Fatalf("an UserAlreadyExistsError should be returned but the error was: %s", err.Error())
	}
}

func TestCreateUserReturnsErrorWhenEmailIsInvalid(t *testing.T) {
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeSuccess,
		},
		Email:    "invalid-email", // Invalid email
		Password: "password1234567890",
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBSuccess,
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for invalid email")
	}

	if err.Error() != "mail: missing '@' or angle-addr" {
		t.Fatalf("expected 'mail: missing '@' or angle-addr' error, got: %s", err.Error())
	}
}

func TestCreateUserReturnsErrorWhenPasswordIsTooShort(t *testing.T) {
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeSuccess,
		},
		Email:    "test@example.com",
		Password: "short", // Password too short
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBSuccess,
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for too short password")
	}
	if !strings.Contains(err.Error(), "password must be at least") {
		t.Fatalf("an PasswordTooShortError should be returned but the error was: %s", err.Error())
	}
}

func TestCreateUserReturnsGenericDBError(t *testing.T) {
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeSuccess,
		},
		Email:    "test@example.com",
		Password: "password1234567890",
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBError,
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for generic DB error")
	}

	expectedErr := errors.New("static generic database error")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}

func TestCreateUserReturnsErrorWhenEmailServiceFailsAndUserIsDeleted(t *testing.T) {
	deleteUserCalled := false
	method := &EmailPasswordMethod{
		Validator: newDefaultValidator(),
		Pepper:    "pepper",
		jwtSecret: "secKey",
		emailService: &MockEmailService{
			sendConfirmationCodeFunc: sendConfirmationCodeError, // Make email service fail
		},
		Email:    "test@example.com",
		Password: "password1234567890",
	}

	idGenerator := &UUIDv7Generator{}
	db := &MockDB{
		createUserInDBFunc: createUserInDBSuccess,
		deleteUserInDBFunc: func(id string) error {
			deleteUserCalled = true
			return nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned when email service fails")
	}

	if !deleteUserCalled {
		t.Fatal("DeleteUserInDB should have been called when email service fails")
	}
	expectedErr := errors.New("email service failed to send confirmation code")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}
