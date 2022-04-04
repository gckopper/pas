package main

import (
	"encoding/csv"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"pas/auth"
	"testing"
	"time"
)

// TestAuth tests if the GetCredentials function working using the example user
func TestAuth(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64(time.Now().Unix()/30)),
	) {
		t.Fail()
	}
}

// TestAuth tests if the GetCredentials function working using the example user
func TestAuthTOTPMarginsTOP(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64((time.Now().Unix()+1)/30)),
	) {
		t.Fail()
	}
}

// TestAuth tests if the GetCredentials function working using the example user
func TestAuthTOTPMarginsBASE(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64((time.Now().Unix()-1)/30)),
	) {
		t.Fail()
	}
}

// TestServer tests the authHandlerFunc directly with the provided example user
func TestServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authHandlerFunc)) // Uses a test server
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL, nil) // Creates a request to the test server
	if err != nil {
		t.Fatal(err)
	}
	request.Header = map[string][]string{ // Prepare an authentication header
		"Username": {"user"},
		"Password": {"a"},
		"OTP": {fmt.Sprint(auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64(time.Now().Unix()/30)))},
	}
	response, err := server.Client().Do(request) // Make the request
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 { // If the authentication fails then so does the test
		t.Fatal(response.StatusCode)
	}
}

// TestServer tests the authHandlerFunc directly with the provided example user
func TestServerCookie(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(authHandlerFunc)) // Uses a test server
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL, nil) // Creates a request to the test server
	if err != nil {
		t.Fatal(err)
	}
	request.Header = map[string][]string{ // Prepare an authentication header
		"Username": {"user"},
		"Password": {"a"},
		"OTP": {fmt.Sprint(auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64(time.Now().Unix()/30)))},
	}
	jar, err := cookiejar.New(nil)
	server.Client().Jar = jar
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request) // Make the request
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 { // If the authentication fails then so does the test
		t.Fatal(response.StatusCode)
	}
	response, err = server.Client().Get(server.URL) // Make the request
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 { // If the authentication fails then so does the test
		t.Fatal(response.StatusCode)
	}
}

func TestSampleServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authHandlerFunc)) // Uses a test server
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL, nil) // Creates a request to the test server
	if err != nil {
		t.Fatal(err)
	}
	request.Header = map[string][]string{ // Prepare an authentication header
		"Username": {"user"},
		"Password": {"a"},
		"OTP": {fmt.Sprint(auth.Totp(
			"IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
			uint64(time.Now().Unix()/30)))},
	}
	response, err := server.Client().Do(request) // Make the request
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 { // If the authentication fails then so does the test
		t.Fatal(response.StatusCode)
	}
}

// TestServer tests the authHandlerFunc directly with a TOTP that's not an int
func TestServerTOTPType(t *testing.T) {
	mockHandler := map[string][]string{ // Prepare an authentication header
		"Username": {"user"},
		"Password": {"a"},
		"OTP":      {"aaaaaa"},
	}
	server := httptest.NewServer(http.HandlerFunc(authHandlerFunc)) // Uses a test server
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL, nil) // Creates a request to the test server
	if err != nil {
		t.Fatal(err)
	}
	request.Header = mockHandler                 // Loads the authentication header
	response, err := server.Client().Do(request) // Make the request
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode == 200 { // If the authentication is successful the then test fails as the TOTP MUST be a number
		t.Fail()
	}
}

// TestServer tests the authHandlerFunc directly with a TOTP that's not an int
func TestServerTOTPSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authHandlerFunc)) // Uses a test server
	defer server.Close()
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 1000; i++ {
		request, err := http.NewRequest("GET", server.URL, nil) // Creates a request to the test server
		if err != nil {
			t.Fatal(err)
		}
		otp := fmt.Sprint(rand.Int() + 1000000)
		request.Header = map[string][]string{ // Prepare an authentication header
			"Username": {"user"},
			"Password": {"a"},
			"OTP":      {otp},
		} // Loads the authentication header
		response, err := server.Client().Do(request) // Make the request
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode == 200 { // If the authentication is successful the then test fails as the TOTP MUST be a number
			t.Fatal(otp)
		}
	}
}

func BenchmarkGetCred(b *testing.B) {
	auth.GetCredentials("user", "a", 232)
}

func BenchmarkGetCredGo(b *testing.B) {
	username := "user"
	password := "a"
	otp := 234234
	// A file that we open at runtime is used to allow modifications without the need to restart
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
	for _, v := range records { // Loop through the records
		if v[0] == username { // Check the username first as it requires no processing
			// Sends the password in plaintext with the salt to be hashed and compared with our record
			presentTime := time.Now().Unix()
			margin := uint64(presentTime % 30)
			passwordHash := make(chan string)
			TOTPCurrent := make(chan int)
			TOTPPlus := make(chan int)
			TOTPMinus := make(chan int)
			go chanHash(passwordHash, password, v[3])
			go chanTOTP(TOTPCurrent, v[2], uint64(presentTime/30))
			go chanTOTP(TOTPPlus, v[2], uint64((presentTime+5)/30))
			go chanTOTP(TOTPMinus, v[2], uint64((presentTime-5)/30))
			if <-passwordHash == v[1] {
				if <-TOTPCurrent == otp || (margin > 27 && (<-TOTPPlus == otp)) || (margin < 3 && (<-TOTPMinus == otp)) {
					return
				}
				return
			} else { // Immediately return false if we got the wrong password for a valid username
				return
			}
		}
	}
}

func chanTOTP(result chan int, secret string, timestamp uint64) {
	result <- auth.Totp(secret, timestamp)
}

func chanHash(result chan string, password string, salt string) {
	result <- auth.Hash(password, salt)
}
