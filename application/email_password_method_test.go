package application

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/JoaoOtavioCano/murdock/application/models"
	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"
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
	getUserByEmailInDBFunc     func(emailAddr string, tx outbound.Transaction) (*models.User, error)
	createUserInDBFunc       func(u models.User, tx outbound.Transaction) error
	lockUserFunc             func(usrID string, tx outbound.Transaction) error
	deleteUserInDBFunc       func(id string, tx outbound.Transaction) error
	saveConfirmationCodeFunc func(code *models.ConfirmationCode, tx outbound.Transaction) error
	deleteConfirmationCodeFunc func(code, digitalAddr string, tx outbound.Transaction) error
	getConfirmationCodeFunc    func(code, digitalAddr string, tx outbound.Transaction) (*models.ConfirmationCode, error)
	updateUserEmailFunc        func(id, email string, tx outbound.Transaction) error
	updateUserPasswordFunc     func(id, password string, tx outbound.Transaction) error
	activateUserFunc           func(id string, tx outbound.Transaction) error
	beginTxFunc              func() (outbound.Transaction, error)
}

func (m *MockDB) GetUserByEmailInDB(emailAddr string, tx outbound.Transaction) (*models.User, error) {
	return m.getUserByEmailInDBFunc(emailAddr, tx)
}

func (m *MockDB) CreateUserInDB(u models.User, tx outbound.Transaction) error {
	return m.createUserInDBFunc(u, tx)
}

func (m *MockDB) LockUser(usrID string, tx outbound.Transaction) error {
	return m.lockUserFunc(usrID, tx)
}

func (m *MockDB) DeleteUserInDB(id string, tx outbound.Transaction) error {
	return m.deleteUserInDBFunc(id, tx)
}

func (m *MockDB) SaveConfirmationCode(code *models.ConfirmationCode, tx outbound.Transaction) error {
	return m.saveConfirmationCodeFunc(code, tx)
}

func (m *MockDB) DeleteConfirmationCode(code, digitalAddr string, tx outbound.Transaction) error {
	return m.deleteConfirmationCodeFunc(code, digitalAddr, tx)
}

func (m *MockDB) GetConfirmationCode(code, digitalAddr string, tx outbound.Transaction) (*models.ConfirmationCode, error) {
	return m.getConfirmationCodeFunc(code, digitalAddr, tx)
}

func (m *MockDB) UpdateUserEmail(id, email string, tx outbound.Transaction) error {
	return m.updateUserEmailFunc(id, email, tx)
}

func (m *MockDB) UpdateUserPassword(id, password string, tx outbound.Transaction) error {
	return m.updateUserPasswordFunc(id, password, tx)
}

func (m *MockDB) ActivateUser(id string, tx outbound.Transaction) error {
	return m.activateUserFunc(id, tx)
}

func (m *MockDB) BeginTx() (outbound.Transaction, error) {
	return m.beginTxFunc()
}

// MockTransaction implements outbound.Transaction interface for testing
type MockTransaction struct {
	CommitFunc   func() error
	RollbackFunc func() error
	ExecFunc     func(query string, args ...any) (any, error)
	QueryFunc    func(query string, args ...any) (any, error)
}

func (m *MockTransaction) Commit() error {
	return m.CommitFunc()
}

func (m *MockTransaction) Rollback() error {
	return m.RollbackFunc()
}

func (m *MockTransaction) Exec(query string, args ...any) (any, error) {
	return m.ExecFunc(query, args...)
}

func (m *MockTransaction) Query(query string, args ...any) (any, error) {
	return m.QueryFunc(query, args...)
}

func getUserByEmailInDBSuccess(emailAddr string, tx outbound.Transaction) (*models.User, error) {
	return &models.User{
		Email: emailAddr,
	}, nil
}

func getUserByEmailInDBError(emailAddr string, tx outbound.Transaction) (*models.User, error) {
	return nil, fmt.Errorf("error getting user by email: %s", emailAddr)
}

func createUserInDBSuccess(u models.User, tx outbound.Transaction) error {
	fmt.Printf("User created in DB: %v\n", u)
	return nil
}

func createUserInDBError(u models.User, tx outbound.Transaction) error {
	return errors.New("static generic database error")
}

func createUserInDBDuplicateKeyError(u models.User, tx outbound.Transaction) error {
	return errors.New("duplicate key value violates unique constraint")
}

func lockUserSuccess(usrID string, tx outbound.Transaction) error {
	fmt.Printf("User with ID %s locked successfully\n", usrID)
	return nil
}

func lockUserError(usrID string, tx outbound.Transaction) error {
	return fmt.Errorf("error locking user with ID: %s", usrID)
}

func deleteUserInDBSuccess(id string, tx outbound.Transaction) error {
	fmt.Printf("User with ID %s deleted successfully\n", id)
	return nil
}

func deleteUserInDBError(id string, tx outbound.Transaction) error {
	return fmt.Errorf("error deleting user with ID: %s", id)
}

func saveConfirmationCodeSuccess(code *models.ConfirmationCode, tx outbound.Transaction) error {
	fmt.Printf("Confirmation code %s saved successfully\n", code.GetCode())
	return nil
}

func saveConfirmationCodeError(code *models.ConfirmationCode, tx outbound.Transaction) error {
	return fmt.Errorf("error saving confirmation code %s", code.GetCode())
}

// ==========================================================
// Test cases
// ==========================================================

func TestCreateUserSuccess(t *testing.T) {
	commitCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBSuccess(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeSuccess(code, tx)
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error {
					commitCalled = true
					return nil
				},
				RollbackFunc: func() error { return nil },
				ExecFunc:     func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc:    func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err != nil {
		t.Fatal(err)
	}

	if !commitCalled {
		t.Fatal("Commit was not called")
	}
}

func TestCreateUserReturnsUserAlreadyExistsErrorWhenDBDuplicateKeyErrorHappens(t *testing.T) {
	rollbackCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBDuplicateKeyError(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeSuccess(code, tx)
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error { return nil },
				RollbackFunc: func() error {
					rollbackCalled = true
					return nil
				},
				ExecFunc:  func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc: func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned")
	}

	if _, ok := err.(customErr.UserAlreadyExistsError); !ok {
		t.Fatalf("an UserAlreadyExistsError should be returned but the error was: %s", err.Error())
	}

	if !rollbackCalled {
		t.Fatal("Rollback was not called")
	}
}

func TestCreateUserReturnsErrorWhenEmailIsInvalid(t *testing.T) {
	rollbackCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBSuccess(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeSuccess(code, tx)
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error { return nil },
				RollbackFunc: func() error {
					rollbackCalled = true
					return nil
				},
				ExecFunc:  func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc: func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for invalid email")
	}

	if err.Error() != "mail: missing '@' or angle-addr" {
		t.Fatalf("expected 'mail: missing '@' or angle-addr' error, got: %s", err.Error())
	}

	if rollbackCalled {
		t.Fatal("Rollback should not be called")
	}
}

func TestCreateUserReturnsErrorWhenPasswordIsTooShort(t *testing.T) {
	rollbackCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBSuccess(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeSuccess(code, tx)
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error { return nil },
				RollbackFunc: func() error {
					rollbackCalled = true
					return nil
				},
				ExecFunc:  func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc: func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for too short password")
	}
	if !strings.Contains(err.Error(), "password must be at least") {
		t.Fatalf("an PasswordTooShortError should be returned but the error was: %s", err.Error())
	}

	if rollbackCalled {
		t.Fatal("Rollback was called")
	}
}

func TestCreateUserReturnsGenericDBError(t *testing.T) {
	rollbackCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBError(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeSuccess(code, tx)
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error { return nil },
				RollbackFunc: func() error {
					rollbackCalled = true
					return nil
				},
				ExecFunc:  func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc: func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned for generic DB error")
	}

	expectedErr := errors.New("static generic database error")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}

	if !rollbackCalled {
		t.Fatal("Rollback was not called")
	}
}

func TestCreateUserReturnsErrorWhenSaveConfirmationCodeFails(t *testing.T) {
	rollbackCalled := false
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
		createUserInDBFunc: func(u models.User, tx outbound.Transaction) error {
			return createUserInDBSuccess(u, tx)
		},
		saveConfirmationCodeFunc: func(code *models.ConfirmationCode, tx outbound.Transaction) error {
			return saveConfirmationCodeError(code, tx) // Make save confirmation code fail
		},
		beginTxFunc: func() (outbound.Transaction, error) {
			return &MockTransaction{
				CommitFunc: func() error { return nil },
				RollbackFunc: func() error {
					rollbackCalled = true
					return nil
				},
				ExecFunc:  func(query string, args ...any) (any, error) { return nil, nil },
				QueryFunc: func(query string, args ...any) (any, error) { return nil, nil },
			}, nil
		},
	}

	err := method.createUser(idGenerator, db)
	if err == nil {
		t.Fatal("an error should be returned when saving confirmation code fails")
	}

	// We expect the error from saveConfirmationCodeError
	expectedErr := fmt.Errorf("error saving confirmation code") // Generalizing the error message
	if !strings.Contains(err.Error(), expectedErr.Error()) {
		t.Fatalf("expected error containing: %s, got: %s", expectedErr.Error(), err.Error())
	}

	if !rollbackCalled {
		t.Fatal("Rollback was not called")
	}
}
