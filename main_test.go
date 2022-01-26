package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"pas/auth"
	"testing"
)

func TestAuth(t *testing.T) {
	if !auth.GetCredentials("user", "a", auth.Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=")) {
		t.Fail()
	}
}

func TestServer(t *testing.T) {
	mockHandler := map[string][]string{"Username": {"user"}, "Password": {"a"}, "OTP": {fmt.Sprint(auth.Totp("IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY="))}}
	server := httptest.NewServer(http.HandlerFunc(authHandlerFunc))
	defer server.Close()
	request, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header = mockHandler
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(err, response, server.URL)
}
