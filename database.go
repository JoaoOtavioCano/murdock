package murdock

type Database struct {
	user string
}

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"encryptedPassword"`
	Salt              string `json:"salt"`
}

func (db *Database) GetUserByEmail(emailAddr string) (User, error) {
	return User{
		Id:                "123456789",
		Email:             "teste@email.com",
		EncryptedPassword: "",
		Salt:              "",
	}, nil
}
