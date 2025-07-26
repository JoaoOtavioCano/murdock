package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
)

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"-"`
	Salt              string `json:"-"`
}

func newUser() *User {
	return &User{}
}

// Generates a 128 bits random text to be used as a salt
// Garantee the 64 bits minimum salt stablished by RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt)
func createSalt() string {
	return rand.Text()
}

func crateUserInDB(tx *sql.Tx, u User) error {
	query := `
		INSERT INTO users(id, email, encryptedPassword, salt)
		VALUES($1, $2, $3, $4)`

	if _, err := tx.Exec(query, u.Id, u.Email, u.EncryptedPassword, u.Salt); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	return nil
}

func getUserByEmailInDB(tx *sql.Tx, emailAddr string) (*User, error) {
	// Use the if statment block bellow just for testing purposes
	if bytes.Equal([]byte(emailAddr), []byte("example@email.com")) {
		e, err := encryptPassword("senha1234", "", Pepper)
		if err != nil {
			return &User{}, err
		}

		return &User{
			Id:                "123456789",
			Email:             "example@email.com",
			EncryptedPassword: e,
			Salt:              "",
		}, nil
	}

	usr := newUser()
	query := `
		SELECT id, email, encryptedPassword, salt FROM USERS 
		WHERE email = $1;
	`
	row := tx.QueryRow(query, emailAddr)

	err := row.Scan(&usr.Id, &usr.Email, &usr.EncryptedPassword, &usr.Salt)
	if err != nil {
		return &User{}, fmt.Errorf("[Error][getUserByEmailInDB] %s", err)
	}

	return usr, nil
}
