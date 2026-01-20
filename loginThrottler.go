package main

import (
	"errors"
	"sync"
	"time"
)

const (
	lockoutThreshold                  int    = 3
	observationWindowInSec            int    = 300
	ErrorUserExceededMaxNumOfAttempts string = "user locked because too many login attempts failed"
)

type LoginThrottler struct {
	loginAttempts map[string]loginAttempt
	mx            *sync.Mutex
}

type loginAttempt struct {
	n         int
	expiresAt time.Time
}

func NewLoginThrottler() *LoginThrottler {
	var mx sync.Mutex
	return &LoginThrottler{
		loginAttempts: make(map[string]loginAttempt),
		mx:            &mx,
	}
}

func (lt *LoginThrottler) HandleLoginFailure(usrID string, db *Database) error {
	lt.mx.Lock()
	usrAttemps := lt.loginAttempts[usrID]
	lt.mx.Unlock()

	if time.Now().After(usrAttemps.expiresAt) {
		usrAttemps.expiresAt = time.Now().Add(time.Second * time.Duration(observationWindowInSec))
		usrAttemps.n = 1
	} else {
		usrAttemps.n += 1
	}

	lt.mx.Lock()
	lt.loginAttempts[usrID] = usrAttemps
	lt.mx.Unlock()

	if usrAttemps.n >= lockoutThreshold {
		tx, err := db.con.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		if err = lockUser(tx, usrID); err != nil {
			return err
		}

		if err = tx.Commit(); err != nil {
			if err = tx.Commit(); err != nil {
				return err
			}
		}

		return errors.New(ErrorUserExceededMaxNumOfAttempts)
	}

	return nil
}
