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
	SaltedHashedPassword string
	OtpSecret            string
	Salt                 string
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
			SaltedHashedPassword: v[1],
			OtpSecret:            v[2],
			Salt:                 v[3],
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
	if !(credentials.Hash(password) == credentials.SaltedHashedPassword) {
		return false
	}
	if !credentials.totpCheck(otp) {
		time.Sleep(time.Millisecond * 69)
		return false
	}
	return true
}

// Hash Receive a password in plaintext and a salt to hash
func (c Credentials) Hash(password string) string {
	// The parameters N r p define the difficulty of calculating the hash and thus
	// should be modified if extra security is required, keep in mind that they affect
	// performance greatly
	key, err := scrypt.Key([]byte(password), []byte(c.Salt), 1<<16, 8, 1, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(key) // Returns the hash as a base64 string
}

func (c Credentials) totpCheck(otp int) bool {
	margin := time.Now().Unix() % 30
	past, present, future := c.totpWithMargins()
	return (margin > 3 && past == otp) || (present == otp) || (margin > 27 && future == otp)
}

func (c Credentials) totpWithMargins() (past int, present int, future int) {
	presentTime := time.Now().Unix()
	pastChan := make(chan int)
	presentChan := make(chan int)
	futureChan := make(chan int)
	go c.asyncTopt(pastChan, uint64((presentTime-5)/30))
	go c.asyncTopt(presentChan, uint64(presentTime/30))
	go c.asyncTopt(futureChan, uint64((presentTime+5)/30))
	return <-pastChan, <-presentChan, <-futureChan
}

func (c Credentials) asyncTopt(result chan int, timestamp uint64) {
	result <- c.Totp(timestamp)
}

// Totp calculates the time-based one time password for a given secret
// spec definition https://datatracker.ietf.org/doc/html/rfc6238
func (c Credentials) Totp(timestamp uint64) int {
	// Convert the string to a byte array making sure it only has upper-case letters
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(c.OtpSecret))
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
