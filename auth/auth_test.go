package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"testing"
)

func TestTOTP(t *testing.T) {
	fmt.Println(Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY="))
}

func TestRandTotpKey(t *testing.T) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	if err != nil {
		log.Fatal(err)
	}
	str := base32.StdEncoding.EncodeToString(secret)
	fmt.Println(str)
}

func TestPassword(t *testing.T) {
	fmt.Println(Hash("a", "x4d!nXZ%sxE#6&U%"))
}
