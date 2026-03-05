package outbound

import "github.com/JoaoOtavioCano/murdock/application/models"

type Database interface {
	GetUserByEmailInDB(emailAddr string, tx Transaction) (*models.User, error)
	CreateUserInDB(u models.User, tx Transaction) error
	LockUser(usrID string, tx Transaction) error
	DeleteUserInDB(id string, tx Transaction) error
	SaveConfirmationCode(code *models.ConfirmationCode, tx Transaction) error
	DeleteConfirmationCode(code, digitalAddr string, tx Transaction) error
	GetConfirmationCode(code, digitalAddr string, tx Transaction) (*models.ConfirmationCode, error)
	UpdateUserEmail(id, email string, tx Transaction) error
	UpdateUserPassword(id, encryptedPassword string, tx Transaction) error
	ActivateUser(id string, tx Transaction) error
	BeginTx() (Transaction, error)
}

type Transaction interface {
	Commit() error
	Rollback() error
	Exec(query string, args ...any) (any, error)
	Query(query string, args ...any) (any, error)
}
