package main

import (
	"bytes"
	"fmt"
)

type Database struct {
	user string
}

func (db *Database) GetUserByEmail(emailAddr string) (User, error) {
	if !bytes.Equal([]byte(emailAddr), []byte("example@email.com")) {
		return User{}, fmt.Errorf("[Error] invalid email address")
	}
	e, err := encryptPassword("senha1234", "", Pepper)
	if err != nil {
		return User{}, err
	}
	return User{
		Id:                "123456789",
		Email:             "example@email.com",
		EncryptedPassword: e,
		Salt:              "",
	}, nil
}
