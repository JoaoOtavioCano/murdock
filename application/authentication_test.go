package application

import (
	"bytes"
	"os"
	"testing"

	"github.com/JoaoOtavioCano/murdock/application/models"
	"github.com/joho/godotenv"
)

func TestIsTheCorrectPassword(t *testing.T) {
	p1 := "1234"
	p2 := "1234"
	if !isTheCorrectPassword(p1, p2) {
		t.Fatalf("Error: não acertou a comparação")
	}
}

func TestIsTheCorrectPasswordFail(t *testing.T) {
	p1 := "1234"
	p2 := "4321"
	if isTheCorrectPassword(p1, p2) {
		t.Fatalf("Error: não acertou a comparação")
	}
}

func TestEncryptPassword(t *testing.T) {
	password := "password"
	pepper := os.Getenv("PEPPER")
	salt := "0987654321"
	_, err := EncryptPassword(password, salt, pepper)
	if err != nil {
		t.Fatalf("Error: não acertou a comparação")
	}
}

func TestIssueJWT(t *testing.T) {
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatalf("[Error] get .env")
	}
	pepper := os.Getenv("PEPPER")
	jwtSecret := os.Getenv("JWT_SECRET")
	e, err := EncryptPassword("senha1234", "", pepper)
	if err != nil {
		t.Fatalf("[Error] encrypting password")
	}
	user := models.User{
		Id:                "123456789",
		Email:             "example@email.com",
		EncryptedPassword: e,
		Salt:              "",
		Status:            "active",
	}
	jwt, err := issueJWT(user, jwtSecret)
	if err != nil {
		t.Fatalf("[Error] something went wrong issuing jwt")
	}

	t.Logf("jwt: %s", string(jwt))

	if !bytes.Equal(jwt, []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OSIsImVtYWlsIjoiZXhhbXBsZUBlbWFpbC5jb20iLCJzdGF0dXMiOiJhY3RpdmUifQ.4hysoYHwQA0Vl5itln1ahvMs1QA3vijwjdK2auUwGUM")) {
		t.Fatalf("[Error] invalid jwt")
	}
}

func TestPasswordsBlocklist(t *testing.T) {
	found, err := isInThePasswordsBlocklist("monkey")
	if err != nil {
		t.Fatalf("[Error] something went wrong: %v", err)
	}

	if !found {
		t.Fatalf("[Error] unable to find bad password in the file")
	}

	found, err = isInThePasswordsBlocklist("EssaEamelhorsenhadomund1234@#$%ˆ&")
	if err != nil {
		t.Fatalf("[Error] something went wrong")
	}

	if found {
		t.Fatalf("[Error] unable to find bad password in the file")
	}
}

func TestBase64UrlpDecode(t *testing.T) {
	encodedData := []byte("eyJpZCI6IjEyMzQ1Njc4OTAiLCJlbWFpbCI6InRlc3RAZW1haWwuY29tIiwiZW5jcnlwdGVkUGFzc3dvcmQiOiIiLCJzYWx0IjoiIn0")

	decodedData, err := base64UrlpDecode(encodedData)
	if err != nil {
		t.Fatalf("[Error] unable to decode data")
	}
	decodedData = decodedData[:len(decodedData)-1]

	if !bytes.Equal(decodedData, []byte(`{"id":"1234567890","email":"test@email.com","encryptedPassword":"","salt":""}`)) {
		t.Fatalf("[Error] data decoded incorrectly")
	}
}

// func TestAuthenticate(t *testing.T) {
// 	jwt := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJlbWFpbCI6InRlc3RAZW1haWwuY29tIiwiZW5jcnlwdGVkUGFzc3dvcmQiOiIiLCJzYWx0IjoiIn0.UbuPbH2mNjQUCFYY_l-ZlPkUT3L8VIWlspkTis4mFnc")
//
// 	authenticated, err := (jwt)
// 	if err != nil {
// 		t.Fatalf("[Error] something went wrong")
// 	}
//
// 	if !authenticated {
// 		t.Fatalf("[Error] data not authenticated")
// 	}
// }

// func BenchmarkInstance(b *testing.B) {
// 	for b.Loop() {
// 		password := "essa é minha senha. Ela tem um tamanho rasoavel"
// 		validator := newDefaultValidator()
// 		err := validator.validatePassword(&password)
// 		if err != nil {
// 			b.Errorf("[Error] something went wrong")
// 		}
// 	}
// }

// func BenchmarkInterface(b *testing.B) {
// 	for b.Loop() {
// 		password := "essa é minha senha. Ela tem um tamanho rasoavel"
// 		validator := newValidator01()
// 		err := validator.interfaceValidatePasswordAccordingToSingleFactorRequirementsNIST(&password)
// 		if err != nil {
// 			b.Errorf("[Error] something went wrong")
// 		}
// 	}
// }
