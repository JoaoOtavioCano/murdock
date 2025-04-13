package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	s := &http.Server{
		Addr: ":6969",
		DisableGeneralOptionsHandler: false,
	}

	http.DefaultServeMux.HandleFunc("POST /api/signin", signinHandler)

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
