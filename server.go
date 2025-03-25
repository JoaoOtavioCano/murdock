package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)


func main() {
	s := &http.Server{
		Addr: ":8080",
	}
	
	
	http.DefaultServeMux.HandleFunc("GET /page/{page}", pageHandler)
	http.DefaultServeMux.HandleFunc("GET /resources/{resource}", resourceHandler)
	http.DefaultServeMux.HandleFunc("POST /api/signin", signinHandler)
	
	log.Fatal(s.ListenAndServe())
}

func pageHandler(w http.ResponseWriter, r *http.Request) {
	page := r.PathValue("page")
	
	http.ServeFile(w, r, page)
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	
	authMethod := &emailPasswordMethod{
		email: r.FormValue("email"),
		password: r.FormValue("password"),
	}
	
	jwt, err := authMethod.login()
	if err != nil {
		if strings.Compare(err.Error(), ErrorUserNotFound) == 0  || strings.Compare(err.Error(), ErrorWrongPassword) == 0 {
			http.Error(w, fmt.Sprintf(`
				<span class="relative p-2 rounded w-fit m-auto visible border-2 border-red-600 bg-red-200 text-black" id="errorSpan" hx-swap-oob="true">
					invalid credentials
				</span>
				<div class="flex flex-col p-4" id="emailDiv" hx-swap-oob="true">
	                <label for="email" class="ml-1 rounded-t px-1 w-fit bg-red-600 text-white">email</label>
	                <input type="text" id="email" name="email" placeholder="example@email.com" value="%s"
	                    class="border-2 border-red-600 rounded text-zinc-600 bg-white p-1 ">
	            </div>
	            <div class="flex flex-col p-4" id="passwordDiv" hx-swap-oob="true">
	                <label for="password" class="ml-1 rounded-t px-1 w-fit bg-red-600 text-white">password</label>
	                <input type="password" id="password" name="password" placeholder="p@ssWord1234" value="%s"
	                    class="border-2 border-red-600 rounded bg-white text-zinc-600 p-1">
	            </div>
				`,authMethod.email, authMethod.password ), http.StatusNotFound)
		} else {
			http.Error(w, `
			<span class="relative p-2 rounded w-fit m-auto visible border-2 border-red-600 bg-red-200 text-black" id="errorSpan" hx-swap-oob="true">
				something went wrong
			</span>"
			`, http.StatusInternalServerError)
		}
	}
	
	authCookie := &http.Cookie{
		Name: "murdock_token",
		Value: string(jwt),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires: time.Now().AddDate(0, 0, 7),
	}
	http.SetCookie(w, authCookie)
	
	w.Header().Add("Authorization", string(jwt))
	w.WriteHeader(http.StatusOK)
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
	resource := r.PathValue("resource")
	
	http.ServeFile(w, r, "resources/" + resource)
}