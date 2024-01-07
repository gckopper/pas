package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"pas/auth"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Creating global cookie hashmap for the session cookies
var cookieList = make(map[string]http.Cookie)

// embedded filesystem to hold the login page related files
//go:embed static
var content embed.FS

func main() {
	port := flag.Int("p", 3000, "Port in which the updater will listen")
	flag.Parse()
	authHandler := http.HandlerFunc(authHandlerFunc)
	http.Handle("/auth", authHandler)                   // Set the authHandlerFunc to handle requests under /auth
	http.Handle("/", http.FileServer(http.FS(content))) // Set the / path to the static folder AKA login page
	// Listen on localhost as this service should not be public
	err := http.ListenAndServe(fmt.Sprint("localhost:", *port), nil)
	if err != nil {
		err = log.Output(0, fmt.Sprintln(err))
		if err != nil {
			log.Fatalln(err)
		}
	}
}
func authHandlerFunc(w http.ResponseWriter, r *http.Request) {
	userCookie, err := r.Cookie("SessionCookie")
	switch err {
	case nil:
		giveCookie(w, userCookie)
	case http.ErrNoCookie:
		checkCredentials(w, r, userCookie)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func giveCookie(w http.ResponseWriter, userCookie *http.Cookie) {
	cookie, exists := cookieList[userCookie.Value]
	if !exists || time.Now().Unix() > cookie.Expires.Unix() {
		// In case that the cookie expire we send it back with MaxAge = -1 to inform the browser
		newCookie := http.Cookie{
			Secure: true,
			Name:   "SessionCookie",
			Value:  userCookie.Value,
			MaxAge: -1,
		}
		delete(cookieList, userCookie.Value)
		http.SetCookie(w, &newCookie)
		w.Write([]byte("Cookie not found or expired"))
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkCredentials(w http.ResponseWriter, r *http.Request, userCookie *http.Cookie) {
	username := r.Header.Get("Username")
	password := r.Header.Get("Password")
	otpString := r.Header.Get("OTP")
	otp, err := strconv.Atoi(otpString)
	// Simultaneously check if password nor username are empty, if they are bigger than
	// 64 characters and if otp is a 6-digit number. Remember that r.Header.Get will
	if (password == "") || (err != nil) || (username == "") || (len(otpString) > 6) || (len(username) > 64) || (len(password) > 64) {
		log.Println(username, "is password invalid?", password == "" || len(password) > 64, err, otp, otpString)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !auth.GetCredentials(username, password, otp) {
		// Returns Unauthorized for users with no cookie and no credentials
		// Used by nginx to redirect the user to the login page
		w.WriteHeader(http.StatusForbidden)
		return
	}
	createCookie(w)
	w.WriteHeader(http.StatusOK)
}

func createCookie(w http.ResponseWriter) {
	id := uuid.New()
	newCookie := http.Cookie{
		Secure:   true,
		Name:     "SessionCookie",
		Value:    id.String(),
		MaxAge:   14400,
		Expires:  time.Now().Add(time.Hour * 4),
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &newCookie)
	cookieList[newCookie.Value] = newCookie
}
