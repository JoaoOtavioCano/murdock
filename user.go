package main

type User struct {
	Id                string `json:"id"`
	Email             string `json:"email"`
	EncryptedPassword string `json:"omitempty"`
	Salt              string `json:"omitempty"`
}

func newUser() *User {
	return &User{}
}
