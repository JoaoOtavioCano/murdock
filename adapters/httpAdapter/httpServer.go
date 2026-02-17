package httpAdapter

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound"
	_ "github.com/lib/pq"
)

type HttpServer struct {
	server      *http.Server
	authService inbound.AuthPort
}

func NewHttpServer(port string, authService inbound.AuthPort) *HttpServer {
	return &HttpServer{
		server: &http.Server{
			Addr:                         port,
			DisableGeneralOptionsHandler: false,
		},
		authService: authService,
	}
}

func (s *HttpServer) Start() {
	http.DefaultServeMux.HandleFunc("POST /api/signin", s.signinHandler)
	http.DefaultServeMux.HandleFunc("POST /api/auth", s.checkHandler)
	http.DefaultServeMux.HandleFunc("POST /api/signup", s.signupHandler)

	log.Fatal(s.server.ListenAndServe())
}

func (s *HttpServer) signinHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	authReq := &inbound.AuthReq{}

	if err = json.Unmarshal(body, authReq); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	token, err := s.authService.Login(*authReq)
	if err != nil {
		var statusCode int
		switch err.Error() {
		case "invalid email and/or password":
			statusCode = http.StatusNotFound
		case "missing values":
			statusCode = http.StatusBadRequest
		case customErr.UserLockedError{}.Error():
			statusCode = http.StatusUnauthorized
		case customErr.UserExceededMaxNumOfAttemptsError{}.Error():
			statusCode = http.StatusTooManyRequests
		default:
			statusCode = http.StatusInternalServerError
		}
		log.Printf("[http resp] statusCode: %d - body: %s", statusCode, err.Error())
		http.Error(w, err.Error(), statusCode)
		return
	}

	authCookie := &http.Cookie{
		Name:     "murdock_token",
		Value:    string(token),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Expires:  time.Now().AddDate(0, 0, 7),
	}
	http.SetCookie(w, authCookie)

	w.Header().Add("Authorization", string(token))
	w.WriteHeader(http.StatusOK)
}

func (s *HttpServer) checkHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	authReq := &inbound.AuthReq{}

	if err = json.Unmarshal(body, authReq); err != nil {
		log.Println(err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	err = s.authService.Check(*authReq)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *HttpServer) signupHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	authReq := &inbound.AuthReq{}

	if err = json.Unmarshal(body, authReq); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	if err := s.authService.Signup(*authReq); err != nil {
		log.Println(err)
		var statusCode int
		switch err.(type) {
		case customErr.ValidationError, customErr.UserAlreadyExistsError:
			statusCode = http.StatusUnprocessableEntity
		default:
			statusCode = http.StatusInternalServerError

		}
		http.Error(w, err.Error(), statusCode)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
