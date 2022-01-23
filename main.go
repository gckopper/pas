package main

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var cookieList = list.New()

func main() {
	cookieList.Init()
	authHandler := http.HandlerFunc(authHandlerFunc)
	http.Handle("/auth", authHandler)
	firstHandler := http.HandlerFunc(firstHandlerFunc)
	http.Handle("/", firstHandler)
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
	if getCredentials(username, password, otp) {
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

func firstHandlerFunc(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./index.html")
	return
}

func getCredentials(username string, password string, otp int) bool {
	file, err := os.Open("users.csv")
	if err != nil {
		fmt.Println(err)
		return false
	}
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println(err)
		return false
	}
	for _, v := range records { // 0 = username 1 = password 2 = otp 3 = salt
		if v[0] == username {
			if hash(password, v[3]) == v[1] {
				if totp(v[2]) == otp {
					return true
				}
				return false
			}
		}
	}
	return false
}

func hash(password string, salt string) string {
	key, err := scrypt.Key([]byte(password), []byte(salt), 1<<16, 8, 1, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}

func totp(secretstr string) int {
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(secretstr))
	if err != nil {
		fmt.Println(err)
		return 0
	}
	buf := make([]byte, 8)
	hmacResult := hmac.New(sha1.New, secret)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/30))
	hmacResult.Write(buf)
	toTrunc := hmacResult.Sum(nil)
	offset := toTrunc[len(toTrunc)-1] & 0xf
	value := int64(((int(toTrunc[offset]) & 0x7f) << 24) |
		((int(toTrunc[offset+1] & 0xff)) << 16) |
		((int(toTrunc[offset+2] & 0xff)) << 8) |
		(int(toTrunc[offset+3]) & 0xff))
	return int(value % 1000000)
}
