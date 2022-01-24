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

var cookieList = list.New()

//go:embed static
var content embed.FS

func main() {
	cookieList.Init()
	authHandler := http.HandlerFunc(authHandlerFunc)
	http.Handle("/auth", authHandler)
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.FS(content))))
	err := http.ListenAndServe("localhost:3000", nil)
	if err != nil {
		err := log.Output(0, fmt.Sprintln(err))
		if err != nil {
			log.Fatalln(err)
		}
	}
}
func authHandlerFunc(w http.ResponseWriter, r *http.Request) {
	userCookie, err := r.Cookie("SessionCookie")
	if err == nil {
		if cookieList.Len() > 0 {
			for v := cookieList.Front(); v != nil; v = v.Next() {
				if v.Value != nil {
					var cookie http.Cookie
					cookie = v.Value.(http.Cookie)
					if cookie.Value == userCookie.Value {
						if time.Now().Unix() > cookie.Expires.Unix() {

							newCookie := http.Cookie{
								Secure: true,
								Name:   "SessionCookie",
								Value:  userCookie.Value,
								MaxAge: -1,
							}
							cookieList.Remove(v)
							http.SetCookie(w, &newCookie)
						} else {
							w.WriteHeader(200)
							return
						}
					}
				}
			}
		}
	}
	username := r.Header.Get("Username")
	password := r.Header.Get("Password")
	otpstr := r.Header.Get("OTP")
	otp, err := strconv.Atoi(otpstr)
	if (password == "") || (err != nil) || (username == "") || (len(otpstr) != 6) || (len(username) > 64) || (len(password) > 64) {
		w.WriteHeader(403)
		return
	}
	if auth.GetCredentials(username, password, otp) {
		id := make([]byte, 64)
		_, err := rand.Read(id)
		if err != nil {
			log.Fatal(err)
		}
		newCookie := http.Cookie{
			Secure:   true,
			Name:     "SessionCookie",
			Value:    base32.StdEncoding.EncodeToString(id),
			MaxAge:   14400,
			Expires:  time.Now().Add(time.Hour * 4),
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, &newCookie)
		cookieList.PushFront(newCookie)
		w.WriteHeader(200)
		return
	} else {
		w.WriteHeader(401)
		return
	}
}
