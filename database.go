package main

import (
	"database/sql"
	"fmt"
	"os"
)

type Database struct {
	con *sql.DB
}

func NewDatabase() (*Database, error) {
	db := &Database{}
	var err error
	dbConnStr := fmt.Sprintf("user=%s dbname=%s sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSL_MODE"))
	db.con, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		return nil, err
	}
	return db, nil
}
