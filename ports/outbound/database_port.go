package outbound

import "github.com/JoaoOtavioCano/murdock/application/models"

type Database interface {
	GetUserByEmailInDB(emailAddr string) (*models.User, error)
	CreateUserInDB(u models.User) error
	LockUser(usrID string) error
	DeleteUserInDB(id string) error
}
