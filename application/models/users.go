package models

import (
	"crypto/rand"
)

const (
	StatusLocked  = "locked"
	StatusPending = "pending"
	StatusActive  = "active"
)

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"-"`
	Salt              string `json:"-"`
	Status            string `json:"status"`
}

func NewUser() *User {
	return &User{}
}

// Generates a 128 bits random text to be used as a salt
// Garantee the 64 bits minimum salt stablished by RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt)
func CreateSalt() string {
	return rand.Text()
}
