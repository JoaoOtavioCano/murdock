package main

import "crypto/rand"

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"omitempty"`
	Salt              string `json:"omitempty"`
}

func newUser() *User {
	return &User{}
}

//Generates a 128 bits random text to be used as a salt
//Garantee the 64 bits minimum salt stablished by RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt)
func createSalt() string {
	return rand.Text()
}