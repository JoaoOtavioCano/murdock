// Package httpadapter implements a http server to act as a entrypoint
// for the authentication service.
package httpadapter

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	customErr "github.com/JoaoOtavioCano/murdock/ports/errors"
	"github.com/JoaoOtavioCano/murdock/ports/inbound"
	"github.com/JoaoOtavioCano/murdock/ports/inbound/commands"
	_ "github.com/lib/pq"
)

const (
	emailPasswordMethod string = "EmailPasswordMethod"
)

type HTTPServer struct {
	server      *http.Server
	authService inbound.AuthPort
}

type reqTemplate struct {
	Method string            `json:"method"`
	Data   map[string]string `json:"data"`
}

func NewHTTPServer(host, port string, authService inbound.AuthPort) *HTTPServer {
	return &HTTPServer{
		server: &http.Server{
			Addr:                         fmt.Sprintf("%s:%s", host, port),
			DisableGeneralOptionsHandler: false,
		},
		authService: authService,
	}
}

func (s *HTTPServer) Start() {
	http.DefaultServeMux.HandleFunc("POST /v1/sessions", s.signinHandler)
	http.DefaultServeMux.HandleFunc("POST /v1/sessions/status", s.checkHandler)
	http.DefaultServeMux.HandleFunc("POST /v1/users", s.signupHandler)
	http.DefaultServeMux.HandleFunc("POST /v1/verifications", s.confirmationCodeValidationHandler)
	http.DefaultServeMux.HandleFunc("POST /v1/password-resets", s.changePasswordHandler)
	http.DefaultServeMux.HandleFunc("DELETE /v1/users", s.deleteAccountHandler)

	log.Printf("startign http server in %s\n", s.server.Addr)
	log.Fatal(s.server.ListenAndServe())
}

func (s *HTTPServer) signinHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	req := &reqTemplate{}

	if err = json.Unmarshal(body, req); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	var cmd commands.LoginCmd
	switch req.Method {
	case emailPasswordMethod:
		cmd = commands.LoginCmdEmailPasswordMethod{
			Email:    req.Data["email"],
			Password: req.Data["password"],
		}
	}

	token, err := s.authService.Login(cmd)
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
		s.errorResponse(w, err.Error(), statusCode)
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
	s.successResponse(w, nil, http.StatusOK)
}

func (s *HTTPServer) checkHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	req := &reqTemplate{}

	if err = json.Unmarshal(body, req); err != nil {
		log.Println(err)
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	cmd := commands.NewCheckSessionStatusCmdEmailPasswordMethod(req.Data["token"])

	err = s.authService.CheckSessionStatus(cmd)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.successResponse(w, nil, http.StatusNoContent)
}

func (s *HTTPServer) signupHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	req := &reqTemplate{}

	if err = json.Unmarshal(body, req); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	var cmd commands.SignupCmd
	switch req.Method {
	case emailPasswordMethod:
		cmd = commands.SignupCmdEmailPasswordMethod{
			Email:    req.Data["email"],
			Password: req.Data["password"],
		}
	}

	if err := s.authService.Signup(cmd); err != nil {
		log.Println(err)
		var statusCode int
		switch err.(type) {
		case customErr.ValidationError, customErr.UserAlreadyExistsError:
			statusCode = http.StatusUnprocessableEntity
		default:
			statusCode = http.StatusInternalServerError

		}
		s.errorResponse(w, err.Error(), statusCode)
		return
	}

	s.successResponse(w, nil, http.StatusCreated)
}

func (s *HTTPServer) confirmationCodeValidationHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	validatioReq := &struct {
		DigitalAddr string `json:"digitalAddr"`
		Code        string `json:"code"`
	}{
		DigitalAddr: "",
		Code:        "",
	}

	if err = json.Unmarshal(body, validatioReq); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	if err := s.authService.ConfirmationCodeValidation(validatioReq.DigitalAddr, validatioReq.Code); err != nil {
		log.Println(err)
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.successResponse(w, nil, http.StatusOK)
}

func (s *HTTPServer) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		s.errorResponse(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}

	req := &struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	if err = json.Unmarshal(body, req); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	cmd := commands.ChangePasswordRequestCmdEmailPasswordMethod{
		Email:    req.Email,
		Password: req.Password,
	}

	if err := s.authService.ChangePasswordRequest(cmd); err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBody, err := json.Marshal(map[string]string{"message": "confirmation code sent to email address"})
	if err != nil {
		respBody = []byte{}
	}
	s.successResponse(w, respBody, http.StatusOK)
}

func (s *HTTPServer) deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("[Error reading request body]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	req := &reqTemplate{}

	if err = json.Unmarshal(body, req); err != nil {
		log.Println("[Error JSON unmarshal]" + err.Error())
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		return
	}

	var cmd commands.DeleteCmd
	switch req.Method {
	case emailPasswordMethod:
		cmd = commands.NewDeleteCmdEmailPasswordMethod(req.Data["token"])
	}

	if err = s.authService.Delete(cmd); err != nil {
		var statusCode int

		switch err.(type) {
		case customErr.InvalidTokeError:
			statusCode = http.StatusUnauthorized
		case customErr.NoTokenReceivedError, customErr.AuthMethodNotFoundError:
			statusCode = http.StatusBadRequest
		default:
			statusCode = http.StatusInternalServerError
		}
		s.errorResponse(w, err.Error(), statusCode)
		return
	}

	respBody, err := json.Marshal(map[string]string{"message": "account deleted"})
	if err != nil {
		respBody = []byte{}
	}
	s.successResponse(w, respBody, http.StatusOK)
}

func (s *HTTPServer) errorResponse(w http.ResponseWriter, msg string, statusCode int) {
	log.Printf("[http resp] statusCode: %d - msg: %s", statusCode, msg)
	resp, _ := json.Marshal(map[string]any{
		"error": map[string]string{
			"message": msg,
		},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(resp); err != nil {
		s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
	}
}

func (s *HTTPServer) successResponse(w http.ResponseWriter, body []byte, statusCode int) {
	log.Printf("[http resp] statusCode: %d - body: %s", statusCode, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if body != nil {
		if _, err := w.Write(body); err != nil {
			s.errorResponse(w, "something went wrong", http.StatusInternalServerError)
		}
	}
}
