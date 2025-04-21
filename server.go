package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Service struct {
	server   *http.Server
	database *sql.DB
}

func (s *Service) start() {
	var err error
	if err = godotenv.Load(".env"); err != nil {
		log.Fatal(err)
	}

	dbConnStr := fmt.Sprintf("user=%s dbname=%s sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSL_MODE"))
	s.database, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatal(err)
	}

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
		Email:    "",
		Password: "",
	}

	if err = json.Unmarshal(body, authMethod); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	jwt, err := login(authMethod)
	if err != nil {
		switch err.Error() {
		case ErrorUserNotFound, ErrorWrongPassword:
			http.Error(w, "invalid email and/or password", http.StatusNotFound)
			return
		case ErrorEmptyPassword, ErrorEmptyEmail:
			http.Error(w, "missing values", http.StatusBadRequest)
			return
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

}
