package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"os"
	"strings"
	"time"
)

func GetCredentials(username string, password string, otp int) bool {
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
			if Hash(password, v[3]) == v[1] {
				if Totp(v[2]) == otp {
					return true
				}
				return false
			}
		}
	}
	return false
}

func Hash(password string, salt string) string {
	key, err := scrypt.Key([]byte(password), []byte(salt), 1<<16, 8, 1, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}

func Totp(secretstr string) int {
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
