package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

type Credentials struct {
	saltedHashedPassword string
	otpSecret            string
	salt                 string
}

var users = make(map[string]Credentials)

func init() {
	file, err := os.Open("users.csv") // Open the file in which the credentials are stored
	if err != nil {
		fmt.Println(err)
		return
	}
	reader := csv.NewReader(file) // Use the csv library to save some work
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println(err)
		return
	}
	/* The indexes are as follows:
	 * 0 = username
	 * 1 = salted and hashed password
	 * 2 = otp secret
	 * 3 = salt used in the password
	 */
	for _, v := range records {
		users[v[0]] = Credentials{
			saltedHashedPassword: v[1],
			otpSecret:            v[2],
			salt:                 v[3],
		}
	}
}

// GetCredentials function to verify the credentials passed to it
func GetCredentials(username string, password string, otp int) bool {
	credentials, exists := users[username]
	if !exists {
		return false
	}
	// Sends the password in plaintext with the salt to be hashed and compared with our record
	if Hash(password, credentials.salt) == credentials.saltedHashedPassword {
		presentTime := time.Now().Unix()
		margin := uint64(presentTime % 30)
		if Totp(credentials.otpSecret, uint64(presentTime/30)) == otp || (margin > 27 && Totp(credentials.otpSecret, uint64((presentTime+5)/30)) == otp) || (margin < 3 && Totp(credentials.otpSecret, uint64((presentTime-5)/30)) == otp) {
			return true
		}
		time.Sleep(1)
		return false
	} else { // Immediately return false if we got the wrong password for a valid username
		return false
	}
}

// Hash Receive a password in plaintext and a salt to hash
func Hash(password string, salt string) string {
	// The parameters N r p define the difficulty of calculating the hash and thus
	// should be modified if extra security is required, keep in mind that they affect
	// performance greatly
	key, err := scrypt.Key([]byte(password), []byte(salt), 1<<16, 8, 1, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(key) // Returns the hash as a base64 string
}

// Totp calculates the time-based one time password for a given secret
// spec definition https://datatracker.ietf.org/doc/html/rfc6238
func Totp(secretString string, timestamp uint64) int {
	// Convert the string to a byte array making sure it only has upper-case letters
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(secretString))
	if err != nil {
		fmt.Println(err)
		return 0
	}
	buf := make([]byte, 8)
	hmacResult := hmac.New(sha1.New, secret)   // Hash the secret as HMAC SHA-1
	binary.BigEndian.PutUint64(buf, timestamp) // Convert the time into bytes and saves it to buf
	hmacResult.Write(buf)                      // Adds more data to the running hash.
	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	// Used here to convert the hash to a byte array
	toTrunc := hmacResult.Sum(nil)
	// Calculate the offset and then truncates the value as specified in the spec
	offset := toTrunc[len(toTrunc)-1] & 0xf
	value := int64(((int(toTrunc[offset]) & 0x7f) << 24) |
		((int(toTrunc[offset+1] & 0xff)) << 16) |
		((int(toTrunc[offset+2] & 0xff)) << 8) |
		(int(toTrunc[offset+3]) & 0xff))
	return int(value % 1000000) // Return only the 6 least significant digits
}
