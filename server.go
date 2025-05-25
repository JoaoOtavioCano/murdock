package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var Pepper string
var jwt_secret string
var service Service

type Service struct {
	server   *http.Server
	database *Database
}

func (s *Service) start() {
	var err error
	if err = godotenv.Load(".env"); err != nil {
		log.Fatal(err)
	}

	Pepper = os.Getenv("PEPPER")
	jwt_secret = os.Getenv("JWT_SECRET")

	s.database, err = NewDatabase() 
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

	jwt, err := s.login(authMethod)
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
