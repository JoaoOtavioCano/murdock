package murdock

import (
	"bytes"
	"os"
	"testing"
)

func TestIsTheCorrectPassword(t *testing.T) {
	p1 := "1234"
	p2 := "1234"
	if !isTheCorrectPassword(p1, p2) {
		t.Errorf("Error: não acertou a comparação")
	}
}

func TestIsTheCorrectPasswordFail(t *testing.T) {
	p1 := "1234"
	p2 := "4321"
	if isTheCorrectPassword(p1, p2) {
		t.Errorf("Error: não acertou a comparação")
	}
}

func TestEncryptPassword(t *testing.T) {
	password := "1234"
	pepper := os.Getenv("PEPPER")
	salt := "0987654321"
	_, err := encryptPassword(password, salt, pepper)
	if err != nil {
		t.Errorf("Error: não acertou a comparação")
	}
}
func TestIssueJWT(t *testing.T) {
	user := User{
		Id:                "1234567890",
		Email:             "test@email.com",
		EncryptedPassword: "",
		Salt:              "",
	}
	jwt, err := issueJWT(user)
	if err != nil {
		t.Errorf("[Error] somethin went wrong issuing jwt")
	}
	if !bytes.Equal(jwt, []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJlbWFpbCI6InRlc3RAZW1haWwuY29tIiwiZW5jcnlwdGVkUGFzc3dvcmQiOiIiLCJzYWx0IjoiIn0.UbuPbH2mNjQUCFYY_l-ZlPkUT3L8VIWlspkTis4mFnc")) {
		t.Errorf("[Error] invalid jwt")
	}
}
