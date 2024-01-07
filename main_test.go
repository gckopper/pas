package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"pas/auth"
	"testing"
	"time"
)

var c = auth.Credentials{
	SaltedHashedPassword: "2Cob0uliq6PAGqGXLf3nsR5Y5Bt5aUdqrSoSmonKv3Eh7NZcxbPOO2rjnoMyhugJkTIq/lzaVK2ir02XqDt66g==",
	OtpSecret:            "IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=",
	Salt:                 "x4d!nXZ%sxE#6&U%",
}

// TestAuth tests if the GetCredentials function working using the example user
func TestAuth(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		c.Totp(uint64(time.Now().Unix()/30)),
	) {
		t.Fail()
	}
}

// TestAuth tests if the GetCredentials function working using the example user
func TestAuthTOTPMarginsTOP(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		c.Totp(uint64((time.Now().Unix()+1)/30)),
	) {
		t.Fail()
	}
}

// TestAuth tests if the GetCredentials function working using the example user
func TestAuthTOTPMarginsBASE(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		c.Totp(uint64((time.Now().Unix()+1)/30)),
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
		"OTP": {fmt.Sprint(
			c.Totp(
				uint64(
					(time.Now().Unix() + 1) / 30)))},
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
		"OTP": {fmt.Sprint(
			c.Totp(
				uint64(
					(time.Now().Unix() + 1) / 30)))},
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
		"OTP": {fmt.Sprint(
			c.Totp(
				uint64(
					(time.Now().Unix() + 1) / 30)))},
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

func FuzzGetCred(f *testing.F) {
	f.Add("a", 232)
	f.Fuzz(func(t *testing.T, password string, otp int) {
		if auth.GetCredentials("user", password, otp) {
			t.Errorf("Broken with: %p and %o", &password, otp)
		}
	})
}
