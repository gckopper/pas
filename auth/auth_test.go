package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"math"
	"testing"
	"time"
)

var c = Credentials{
	SaltedHashedPassword: "2Cob0uliq6PAGqGXLf3nsR5Y5Bt5aUdqrSoSmonKv3Eh7NZcxbPOO2rjnoMyhugJkTIq/lzaVK2ir02XqDt66g==",
	OtpSecret:            "IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
	Salt:                 "x4d!nXZ%sxE#6&U%",
}

func TestTOTP(t *testing.T) {
	totp := c.Totp(uint64(time.Now().Unix() / 30))
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
	if c.Hash("a") != "2Cob0uliq6PAGqGXLf3nsR5Y5Bt5aUdqrSoSmonKv3Eh7NZcxbPOO2rjnoMyhugJkTIq/lzaVK2ir02XqDt66g==" {
		t.Fail()
	}
}
