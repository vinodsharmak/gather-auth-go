package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginSuccess(t *testing.T) {
	expectedEmail := "demo@gather.network"
	expectedStatusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data email
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if data.Email == expectedEmail {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": false}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"detail": "Invalid Email!"}`)
		}
	}))
	defer server.Close()

	response, err := Login("demo@gather.network", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode || response.Access != "some_access_value" || response.Refresh != "some_refresh_value" {
		t.Errorf("Unxpected response values: %v, %v, %v", response.StatusCode, response.Access, response.Refresh)
	}

}
func TestLoginFail(t *testing.T) {
	expectedInvalidEmail := "invalid@gather.network"
	expectedStatusCode := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data email
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if data.Email == expectedInvalidEmail {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"detail": "Invalid email id."}`)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	response, err := Login("invalid@gather.network", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode || response.ErrorDetail != "Invalid email id." {
		t.Errorf("Unxpected response values: %v, %v", response.StatusCode, response.ErrorDetail)
	}

}

func TestLoginOTPSuccess(t *testing.T) {
	expectedEmail := "demo@gather.network"
	expectedCode := "abc123"
	expectedStatusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data emailAndCode
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if data.Email == expectedEmail && data.Code == expectedCode {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": true}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"detail": "Invalid Credentials!"}`)
		}
	}))
	defer server.Close()

	response, err := LoginOTP("demo@gather.network", "abc123", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode || response.Access != "some_access_value" || response.Refresh != "some_refresh_value" {
		t.Errorf("Unxpected response values: %v, %v, %v", response.StatusCode, response.Access, response.Refresh)
	}

}

func TestLoginOTPFail(t *testing.T) {
	expectedEmail := "demo@gather.network"
	expectedInvalidCode := "invalidCode"
	expectedStatusCode := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data emailAndCode
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if data.Email == expectedEmail && data.Code == expectedInvalidCode {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"detail": "Invalid Credentials!"}`)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	response, err := LoginOTP("demo@gather.network", "invalidCode", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode || response.ErrorDetail != "Invalid Credentials!" {
		t.Errorf("Unxpected response values: %v, %v", response.StatusCode, response.ErrorDetail)
	}

}
func TestVerifyAccessTokenSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		err := json.NewDecoder(r.Body).Decode(&response)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if response.Access == "some_access" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	resp := &Response{
		Refresh: "some_refresh",
		Access:  "some_access",
	}

	response, err := resp.VerifyAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if !response {
		t.Errorf("Expected true on request, but got %v", response)
	}
}
func TestVerifyAccessTokenFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var accessToken verifyAccessToken
		err := json.NewDecoder(r.Body).Decode(&accessToken)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if accessToken.Token == "expired_access" {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	resp := &Response{Access: "expired_access"}

	response, err := resp.VerifyAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response {
		t.Errorf("Expected false on request, but got %v", response)
	}
}

func TestRefreshAccessTokenSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var refreshToken refreshAccessToken
		err := json.NewDecoder(r.Body).Decode(&refreshToken)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if refreshToken.Refresh == "valid_refresh" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"access":"new_access_token","refresh":"new_refresh_token"}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	resp := &Response{Refresh: "valid_refresh"}
	response, err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != http.StatusOK || response.Access != "new_access_token" || response.Refresh != "new_refresh_token" {
		t.Errorf("Unxpected response values: %v, %v, %v", response.StatusCode, response.Access, response.Refresh)
	}
}

func TestRefreshAccessTokenFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var refreshToken refreshAccessToken
		err := json.NewDecoder(r.Body).Decode(&refreshToken)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if refreshToken.Refresh == "invalid_refresh" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"detail":"Token_is_Invalid"}`)
		}
	}))
	defer server.Close()

	resp := &Response{Refresh: "invalid_refresh"}
	response, err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != http.StatusNotFound || response.ErrorDetail != "Token_is_Invalid" {
		t.Errorf("Unxpected response values: %v, %v", response.StatusCode, response.ErrorDetail)
	}
}
