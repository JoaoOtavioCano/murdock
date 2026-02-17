package postgres

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"

	"github.com/JoaoOtavioCano/murdock/application"
	"github.com/JoaoOtavioCano/murdock/application/models"
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

func (db *Database) GetUserByEmailInDB(emailAddr string) (*models.User, error) {
	tx, err := db.con.Begin()
	if err != nil {
		return nil, fmt.Errorf("[Error][EmailPasswordMethod.login] %s", err)
	}

	// Use the if statment block bellow just for testing purposes
	if bytes.Equal([]byte(emailAddr), []byte("example@email.com")) {
		e, err := application.EncryptPassword("senha1234", "", os.Getenv("PEPPER"))
		if err != nil {
			return &models.User{}, err
		}

		return &models.User{
			Id:                "123456789",
			Email:             "example@email.com",
			EncryptedPassword: e,
			Salt:              "",
			Status:            "active",
		}, nil
	}

	usr := models.NewUser()
	query := `
		SELECT id, email, encryptedPassword, salt, status FROM USERS 
		WHERE email = $1;
	`
	row := tx.QueryRow(query, emailAddr)

	err = row.Scan(&usr.Id, &usr.Email, &usr.EncryptedPassword, &usr.Salt, &usr.Status)
	if err != nil {
		return &models.User{}, fmt.Errorf("[Error][getUserByEmailInDB] %s", err)
	}

	return usr, nil
}

func (db *Database) LockUser(usrID string) error {
	tx, err := db.con.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `
		UPDATE users SET status='locked' WHERE id=$1;
	`
	_, err = tx.Exec(query, usrID)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		if err = tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

func (db *Database) CreateUserInDB(u models.User) error {
	tx, err := db.con.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO users(id, email, encryptedPassword, salt, status)
		VALUES($1, $2, $3, $4, $5)`

	if _, err := tx.Exec(query, u.Id, u.Email, u.EncryptedPassword, u.Salt, u.Status); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if err = tx.Commit(); err != nil {
		if err = tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}
