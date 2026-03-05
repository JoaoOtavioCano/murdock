package postgres

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/JoaoOtavioCano/murdock/application"
	"github.com/JoaoOtavioCano/murdock/application/models"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"
)

type sqlTx struct {
	tx *sql.Tx
}

func (db *Database) BeginTx() (outbound.Transaction, error) {
	tx, err := db.con.Begin()
	if err != nil {
		return nil, fmt.Errorf("[Error][sqlTx creation] %s", err)
	}

	return &sqlTx{
		tx: tx,
	}, nil
}

func (t *sqlTx) Commit() error {
	return t.tx.Commit()
}

func (t *sqlTx) Rollback() error {
	return t.tx.Rollback()
}

func (t *sqlTx) Exec(query string, args ...any) (any, error) {
	return t.tx.Exec(query, args...)
}

func (t *sqlTx) Query(query string, args ...any) (any, error) {
	return t.tx.Query(query, args...)
}

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

func (db *Database) GetUserByEmailInDB(emailAddr string, tx outbound.Transaction) (*models.User, error) {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return nil, fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	// Use the if statment block bellow just for testing purposes
	if bytes.Equal([]byte(emailAddr), []byte("example@email.com")) {
		e, err := application.EncryptPassword("senha1234", "", os.Getenv("PEPPER"))
		if err != nil {
			return &models.User{}, err
		}

		if !fullControl {
			if err = tx.Commit(); err != nil {
				if err = tx.Commit(); err != nil {
					return &models.User{}, err
				}
			}
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
	rowsAny, err := tx.Query(query, emailAddr)
	rows, ok := rowsAny.(*sql.Rows)
	if !ok {
		return nil, errors.New("type should be *sql.Rows")
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&usr.Id, &usr.Email, &usr.EncryptedPassword, &usr.Salt, &usr.Status)
		if err != nil {
			return &models.User{}, fmt.Errorf("[Error][getUserByEmailInDB] %s", err)
		}
		break
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return &models.User{}, err
			}
		}
	}

	return usr, nil
}

func (db *Database) LockUser(usrID string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}
	query := `
		UPDATE users SET status='locked' WHERE id=$1;
	`
	_, err = tx.Exec(query, usrID)
	if err != nil {
		return err
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *Database) CreateUserInDB(u models.User, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `
		INSERT INTO users(id, email, encryptedPassword, salt, status)
		VALUES($1, $2, $3, $4, $5)`

	if _, err := tx.Exec(query, u.Id, u.Email, u.EncryptedPassword, u.Salt, u.Status); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *Database) DeleteUserInDB(id string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `DELETE FROM users WHERE id=$1`

	if _, err := tx.Exec(query, id); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *Database) UpdateUserEmail(id, email string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `UPDATE users SET email=$1 WHERE id=$2`

	if _, err := tx.Exec(query, id, email); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *Database) UpdateUserPassword(id, password string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `UPDATE users SET encryptedPassword=$1 WHERE id=$2`

	if _, err := tx.Exec(query, password, id); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *Database) ActivateUser(id string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `UPDATE users SET status=$1 WHERE id=$2;`

	if _, err := tx.Exec(query, models.StatusActive, id); err != nil {
		return fmt.Errorf("[DATABASE ERROR] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *Database) SaveConfirmationCode(code *models.ConfirmationCode, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `
		INSERT INTO confirmation_codes(code, expireAt, userID, codeType, data, digitalAddr) VALUES($1, $2, $3, $4, $5, $6)`

	if _, err = tx.Exec(query, code.GetCode(), code.GetExpireAt(), code.GetUserId(), code.GetCodeType(), code.GetData(), code.GetDigitalAddr()); err != nil {
		return fmt.Errorf("[DATABASE ERROR][query execution] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *Database) DeleteConfirmationCode(code, digitalAddr string, tx outbound.Transaction) error {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `DELETE FROM confirmation_codes WHERE code=$1 AND digitalAddr=$2`

	if _, err = tx.Exec(query, code, digitalAddr); err != nil {
		return fmt.Errorf("[DATABASE ERROR][query execution] %s", err.Error())
	}

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *Database) GetConfirmationCode(code, digitalAddr string, tx outbound.Transaction) (*models.ConfirmationCode, error) {
	var err error
	fullControl := true
	if tx == nil {
		fullControl = false
		tx, err = db.BeginTx()
		if err != nil {
			return nil, fmt.Errorf("[DATABASE ERROR][transaction creation] %s", err.Error())
		}
		defer tx.Rollback()
	}

	query := `SELECT code, expireAt, userID, codeType, data, digitalAddr FROM confirmation_codes WHERE code=$1 AND digitalAddr=$2`

	rowsAny, err := tx.Query(query, code, digitalAddr)
	if err != nil {
		return nil, fmt.Errorf("[DATABASE ERROR][query execution] %s", err.Error())
	}

	rows, ok := rowsAny.(*sql.Rows)
	if !ok {
		return nil, errors.New("type should be *sql.Rows")
	}

	defer rows.Close()

	aux := &struct {
		code        string
		expireAt    time.Time
		codeType    string
		usrID       string
		digitalAddr string
		data        string
	}{
		code:        "",
		expireAt:    time.Time{},
		codeType:    "",
		usrID:       "",
		digitalAddr: "",
		data:        "",
	}

	for rows.Next() {
		err = rows.Scan(&aux.code, &aux.expireAt, &aux.usrID, &aux.codeType, &aux.data, &aux.digitalAddr)
		if err != nil {
			return nil, fmt.Errorf("[DATABASE ERROR][scan ConfirmationCode] %s", err.Error())
		}
		break
	}

	cc, err := models.NewConfirmationCode(aux.usrID, aux.digitalAddr, aux.codeType, aux.data)
	if err != nil {
		return nil, fmt.Errorf("[DATABASE ERROR][ConfirmationCode creation] %s", err.Error())
	}

	cc.SetCode(aux.code)
	cc.SetExpireAt(aux.expireAt)

	if !fullControl {
		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return nil, err
			}
		}
	}

	return cc, nil
}
