package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
)

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"omitempty"`
	Salt              string `json:"omitempty"`
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
