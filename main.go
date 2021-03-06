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

// Creating global cookie list for the session cookies
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
	userCookie, err := r.Cookie("SessionCookie") // Try to grab the cookie named SessionCookie
	if err == nil {
		cookie, exists := cookieList[userCookie.Value]            // Will get the cookie from the cookieList
		if !exists || time.Now().Unix() > cookie.Expires.Unix() { // Making sure the cookie exists
			// In case that the cookie expire we send it back with MaxAge = -1 to inform the browser
			newCookie := http.Cookie{
				Secure: true,
				Name:   "SessionCookie",
				Value:  userCookie.Value,
				MaxAge: -1,
			}
			delete(cookieList, userCookie.Value) // Delete the cookie from the cookieList
			http.SetCookie(w, &newCookie)
			w.Write([]byte("Cookie not found or expired")) // If the cookie does not exist, write this to the response
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200) // If we have a valid unexpired cookie it's all good to go
		return
	}
	// Grab the authentication headers
	username := r.Header.Get("Username")
	password := r.Header.Get("Password")
	otpString := r.Header.Get("OTP")
	otp, err := strconv.Atoi(otpString) // Convert the otpString into an int
	// Simultaneously check if password nor username are empty, if they are bigger than
	// 64 characters and if otp is a 6-digit number. Remember that r.Header.Get will
	// return "" (empty string) if there is no header with such name
	if (password == "") || (err != nil) || (username == "") || (len(otpString) > 6) || (len(username) > 64) || (len(password) > 64) {
		log.Println(username, "is password invalid?", password == "" || len(password) > 64, err, otp, otpString)
		w.WriteHeader(403)
		return
	}
	// Confirm the received valid credentials
	if auth.GetCredentials(username, password, otp) {
		id := uuid.New() // Allocate 64 bytes of memory for the id
		newCookie := http.Cookie{
			Secure:   true,
			Name:     "SessionCookie",
			Value:    id.String(),
			MaxAge:   14400,
			Expires:  time.Now().Add(time.Hour * 4), // Give it 4 hours of life
			SameSite: http.SameSiteStrictMode,       // Set SameSite to strict as a way of mitigating attacks
		}
		http.SetCookie(w, &newCookie)
		// Add the new cookie to the front of the list as it is very likely to be used immediately
		// By the very nature of lists things at the end take more time to reach
		cookieList[newCookie.Value] = newCookie // Add the new cookie to the cookieList
		w.WriteHeader(200)
		return
	}
	// Returns Unauthorized for users with no cookie and no credentials
	// Used by nginx to redirect the user to the login page
	w.WriteHeader(401)
}
