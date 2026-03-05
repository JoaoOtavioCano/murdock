package application

import (
	"sync"
	"time"

	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/outbound"
)

const (
	lockoutThreshold                  int    = 3
	observationWindowInSec            int    = 300
	ErrorUserExceededMaxNumOfAttempts string = "user locked because too many login attempts failed"
)

type LoginThrottler struct {
	loginAttempts map[string]loginAttempt
	mx            *sync.Mutex
	db            outbound.Database
}

type loginAttempt struct {
	n         int
	expiresAt time.Time
}

func NewLoginThrottler(db outbound.Database) *LoginThrottler {
	var mx sync.Mutex
	return &LoginThrottler{
		loginAttempts: make(map[string]loginAttempt),
		mx:            &mx,
		db:            db,
	}
}

func (lt *LoginThrottler) HandleLoginFailure(usrID string) error {
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
		if err := lt.db.LockUser(usrID, nil); err != nil {
			return err
		}
		return customErr.UserExceededMaxNumOfAttemptsError{}
	}

	return nil
}
