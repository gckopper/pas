package main

import (
	"container/list"
	"crypto/rand"
	"embed"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"
	"pas/auth"
	"strconv"
	"time"
)

// Creating global cookie list for the session cookies
var cookieList = list.New()

// embedded filesystem to hold the login page related files
//go:embed static
var content embed.FS

func main() {
	cookieList.Init() // Initializing the list
	authHandler := http.HandlerFunc(authHandlerFunc)
	http.Handle("/auth", authHandler)                   // Set the authHandlerFunc to handle requests under /auth
	http.Handle("/", http.FileServer(http.FS(content))) // Set the / path to the static folder AKA login page
	// Listen on localhost as this service should not be public
	err := http.ListenAndServe("localhost:3000", nil)
	if err != nil {
		err = log.Output(0, fmt.Sprintln(err))
		if err != nil {
			log.Fatalln(err)
		}
	}
}
func authHandlerFunc(w http.ResponseWriter, r *http.Request) {
	userCookie, err := r.Cookie("SessionCookie") // Try to grab the cookie named SessionCookie
	if err == nil {                              // Will enter this if there is a cookie called SessionCookie
		if cookieList.Len() > 0 { // Making sure we even have a cookie to compare to
			for v := cookieList.Front(); v != nil; v = v.Next() { // Run through the cookie list
				if v.Value != nil { // Sanity check
					var cookie http.Cookie
					cookie = v.Value.(http.Cookie)        // Converts the interface into a http.Cookie type
					if cookie.Value == userCookie.Value { // Confirms that we got the right cookie
						if time.Now().Unix() > cookie.Expires.Unix() { // Making sure the cookie is still edible
							// In case that the cookie expire we send it back with MaxAge = -1 to inform the browser
							newCookie := http.Cookie{
								Secure: true,
								Name:   "SessionCookie",
								Value:  userCookie.Value,
								MaxAge: -1,
							}
							cookieList.Remove(v) // Remove the expired cookie from our list
							http.SetCookie(w, &newCookie)
						} else {
							w.WriteHeader(200) // If we have a valid unexpired cookie it's all good to go
							return
						}
					}
				}
			}
		}
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
		id := make([]byte, 64) // Allocate 64 bytes of memory for the id
		_, err = rand.Read(id) // Get Random values for the id
		if err != nil {
			log.Fatal(err)
		}
		newCookie := http.Cookie{
			Secure:   true,
			Name:     "SessionCookie",
			Value:    base32.StdEncoding.EncodeToString(id),
			MaxAge:   14400,
			Expires:  time.Now().Add(time.Hour * 4), // Give it 4 hours of life
			SameSite: http.SameSiteStrictMode,       // Set SameSite to strict as a way of mitigating attacks
		}
		http.SetCookie(w, &newCookie)
		// Add the new cookie to the front of the list as it is very likely to be used immediately
		// By the very nature of lists things at the end take more time to reach
		cookieList.PushFront(newCookie)
		w.WriteHeader(200)
		return
	} else {
		// Returns Unauthorized for users with no cookie and no credentials
		// Used by nginx to redirect the user to the login page
		w.WriteHeader(401)
		return
	}
}
