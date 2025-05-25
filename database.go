package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
)

type Database struct {
	db *sql.DB
}

func NewDatabase() (*Database, error) {
	db := &Database{}
	var err error
	dbConnStr := fmt.Sprintf("user=%s dbname=%s sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSL_MODE"))
	db.db, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		return nil, err
	}
	return db, nil
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
