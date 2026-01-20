package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	Pepper    string
	jwtSecret string
)

type Service struct {
	server         *http.Server
	database       *Database
	loginThrottler *LoginThrottler
}

func (s *Service) start() {
	var err error
	if err = godotenv.Load(".env"); err != nil {
		log.Fatal(err)
	}

	Pepper = os.Getenv("PEPPER")
	jwtSecret = os.Getenv("JWT_SECRET")

	s.database, err = NewDatabase()
	if err != nil {
		log.Fatal(err)
	}

	s.loginThrottler = NewLoginThrottler()

	s.server = &http.Server{
		Addr:                         ":80",
		DisableGeneralOptionsHandler: false,
	}

	http.DefaultServeMux.HandleFunc("POST /api/signin", s.signinHandler)
	http.DefaultServeMux.HandleFunc("POST /api/auth", s.authHandler)
	http.DefaultServeMux.HandleFunc("POST /api/signup", s.signupHandler)

	log.Fatal(s.server.ListenAndServe())
}

func (s *Service) signinHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	authMethod := &EmailPasswordMethod{
		Email:     "",
		Password:  "",
		Validator: newDefaultValidator(),
	}

	if err = json.Unmarshal(body, authMethod); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	var jwt []byte
	if err = authMethod.validateCredentials(); err == nil {
		jwt, err = authMethod.login(s.database, s.loginThrottler)
	}

	if err != nil {
		switch err.Error() {
		case ErrorUserNotFound, ErrorWrongPassword:
			log.Println(err.Error())
			http.Error(w, "invalid email and/or password", http.StatusNotFound)
			return
		case ErrorEmptyPassword, ErrorEmptyEmail:
			http.Error(w, "missing values", http.StatusBadRequest)
			return
		case ErrorUserLocked:
			http.Error(w, ErrorUserLocked, http.StatusUnauthorized)
		case ErrorUserExceededMaxNumOfAttempts:
			http.Error(w, ErrorUserExceededMaxNumOfAttempts, http.StatusTooManyRequests)
		default:
			log.Println(err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
	}

	authCookie := &http.Cookie{
		Name:     "murdock_token",
		Value:    string(jwt),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Expires:  time.Now().AddDate(0, 0, 7),
	}
	http.SetCookie(w, authCookie)

	w.Header().Add("Authorization", string(jwt))
	w.WriteHeader(http.StatusOK)
}

func (s *Service) authHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}
	authRequestData := &struct {
		Token string `json:"token"`
	}{
		Token: "",
	}

	if err = json.Unmarshal(body, authRequestData); err != nil {
		log.Println(err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	if authRequestData.Token == "" {
		log.Println("token not found")
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	authenticated, err := authenticate([]byte(authRequestData.Token))
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	if !authenticated {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) signupHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	authMethod := &EmailPasswordMethod{
		Email:     "",
		Password:  "",
		Validator: newDefaultValidator(),
	}

	if err = json.Unmarshal(body, authMethod); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	idGenerator := &UUIDv7Generator{}

	if err := authMethod.createUser(idGenerator, *s.database); err != nil {
		log.Println(err)
		if strings.Contains(err.Error(), "[Validation Error]") {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		} else if strings.EqualFold(err.Error(), ErrorUserAlreadyExists) {
			http.Error(w, ErrorUserAlreadyExists, http.StatusUnprocessableEntity)
		} else {
			http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
}
