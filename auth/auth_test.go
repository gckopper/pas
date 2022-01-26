package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"math"
	"testing"
)

func TestTOTP(t *testing.T) {
	totp := Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=")
	// fmt.Println(totp)
	if math.Log10(float64(totp)) >= 6 {
		t.Fail()
	}
}

// Reference to generate a random secret
func _() {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	if err != nil {
		log.Fatal(err)
	}
	str := base32.StdEncoding.EncodeToString(secret)
	fmt.Println(str)
}

func TestPassword(t *testing.T) {
	if Hash("a", "x4d!nXZ%sxE#6&U%") != "2Cob0uliq6PAGqGXLf3nsR5Y5Bt5aUdqrSoSmonKv3Eh7NZcxbPOO2rjnoMyhugJkTIq/lzaVK2ir02XqDt66g==" {
		t.Fail()
	}
}
