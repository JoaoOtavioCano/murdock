package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
	"io"
)

func main() {
	s := &http.Server{
		Addr:                         ":80",
		DisableGeneralOptionsHandler: false,
	}

	http.DefaultServeMux.HandleFunc("POST /api/signin", signinHandler)
	http.DefaultServeMux.HandleFunc("POST /api/auth", authHandler)

	log.Fatal(s.ListenAndServe())
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	authMethod := &emailPasswordMethod{
		email:    r.FormValue("email"),
		password: r.FormValue("password"),
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

func authHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "somethig went wrong", http.StatusInternalServerError)
		return
	}
	authRequestData := &struct{
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