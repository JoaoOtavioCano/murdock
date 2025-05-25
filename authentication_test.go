package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/joho/godotenv"
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
	if err := godotenv.Load(".env"); err != nil {
		t.Errorf("[Error] get .env")
	}
	Pepper = os.Getenv("PEPPER")
	jwt_secret = os.Getenv("JWT_SECRET")
	e, err := encryptPassword("senha1234", "", Pepper)
	if err != nil {
		t.Errorf("[Error] encrypting password")
	}
	user := User{
		Id:                "123456789",
		Email:             "example@email.com",
		EncryptedPassword: e,
		Salt:              "",
	}
	jwt, err := issueJWT(user)
	if err != nil {
		t.Errorf("[Error] something went wrong issuing jwt")
	}

	if !bytes.Equal(jwt, []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OSIsImVtYWlsIjoiZXhhbXBsZUBlbWFpbC5jb20ifQ.Nfnw24aDs6FcO4YJ2-Mje8bj1RLjmsG1DCbxI-0DZkI")) {
		t.Errorf("[Error] invalid jwt")
	}
}

func Test10kWorstPasswordsComparison(t *testing.T) {
	found, err := isInThe10kWorstPasswords("monkey")
	if err != nil {
		t.Errorf("[Error] something went wrong")
	}

	if !found {
		t.Errorf("[Error] unable to find bad password in the file")
	}

	found, err = isInThe10kWorstPasswords("EssaEamelhorsenhadomund1234@#$%ˆ&")
	if err != nil {
		t.Errorf("[Error] something went wrong")
	}

	if found {
		t.Errorf("[Error] unable to find bad password in the file")
	}
}

func TestBase64UrlpDecode(t *testing.T) {
	encodedData := []byte("eyJpZCI6IjEyMzQ1Njc4OTAiLCJlbWFpbCI6InRlc3RAZW1haWwuY29tIiwiZW5jcnlwdGVkUGFzc3dvcmQiOiIiLCJzYWx0IjoiIn0")

	decodedData, err := base64UrlpDecode(encodedData)
	if err != nil {
		t.Errorf("[Error] unable to decode data")
	}
	decodedData = decodedData[:len(decodedData)-1]

	if !bytes.Equal(decodedData, []byte(`{"id":"1234567890","email":"test@email.com","encryptedPassword":"","salt":""}`)) {
		t.Errorf("[Error] data decoded incorrectly")
	}

}

func TestAuthenticate(t *testing.T) {
	jwt := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJlbWFpbCI6InRlc3RAZW1haWwuY29tIiwiZW5jcnlwdGVkUGFzc3dvcmQiOiIiLCJzYWx0IjoiIn0.UbuPbH2mNjQUCFYY_l-ZlPkUT3L8VIWlspkTis4mFnc")

	authenticated, err := authenticate(jwt)

	if err != nil {
		t.Errorf("[Error] something went wrong")
	}

	if !authenticated {
		t.Errorf("[Error] data not authenticated")
	}
}
