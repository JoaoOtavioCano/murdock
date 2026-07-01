package models

import (
	"time"
)

const day = 24 * time.Hour

type Session struct {
	Usr      User      `json:"user"`
	ExpireAt time.Time `json:"expireAt"`
}

func NewSession(usr *User) *Session {
	return &Session{
		Usr:      *usr,
		ExpireAt: time.Now().Add(7 * day),
	}
}

func (s *Session) IsExpired() bool {
	return s.ExpireAt.Before(time.Now())
}
