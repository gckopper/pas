package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"pas/auth"
	"testing"
	"time"
)

// TestAuth tests if the GetCredentials function working using the example user
func TestAuth(t *testing.T) {
	if !auth.GetCredentials(
		"user",
		"a",
		auth.Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY="),
	) {
		t.Fail()
	}
}

// TestServer tests the authHandlerFunc directly with the provided example user
func TestServer(t *testing.T) {
	mockHandler := map[string][]string{ // Prepare an authentication header
		"Username": {"user"},
		"Password": {"a"},
		"OTP":      {fmt.Sprint(auth.Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY="))},
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
	if response.StatusCode != 200 { // If the authentication fails then so does the test
		t.Fail()
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
