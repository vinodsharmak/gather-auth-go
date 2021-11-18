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
	expectedStatusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data email
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": false}`)

	}))
	defer server.Close()

	response, err := Login("demo@gather.network", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected response! Expected StatusCode: values: %v, but got StatusCode: %v", expectedStatusCode, response.StatusCode)
	}
	if response.Access != "some_access_value" {
		t.Errorf("Unexpected response! Expeced access:some_access_value but got access:%v", response.Access)
	}
	if response.Refresh != "some_refresh_value" {
		t.Errorf("Unexpected response! Expeced refresh:some_refresh_value but got refresh:%v", response.Refresh)
	}

}
func TestLoginFail(t *testing.T) {
	expectedStatusCode := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data email
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}

		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"detail": "Invalid email id."}`)
	}))
	defer server.Close()

	response, err := Login("invalid@gather.network", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected StatusCode, Expected: %v, but got: %v", expectedStatusCode, response.StatusCode)
	}
	if response.ErrorDetail != "Invalid email id." {
		t.Errorf("Unexpected ErrorMessage. Expected ErrorDetail: Invalid email id., but got %v", response.ErrorDetail)
	}

}

func TestLoginOTPSuccess(t *testing.T) {
	expectedStatusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data emailAndCode
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": true}`)
	}))
	defer server.Close()

	response, err := LoginOTP("demo@gather.network", "abc123", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected response! Expected StatusCode: values: %v, but got StatusCode: %v", expectedStatusCode, response.StatusCode)
	}
	if response.Access != "some_access_value" {
		t.Errorf("Unexpected response! Expeced access:some_access_value but got access:%v", response.Access)
	}
	if response.Refresh != "some_refresh_value" {
		t.Errorf("Unexpected response! Expeced refresh:some_refresh_value but got refresh:%v", response.Refresh)
	}

}

func TestLoginOTPFail(t *testing.T) {
	expectedStatusCode := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data emailAndCode
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"detail": "Invalid Credentials!"}`)

	}))
	defer server.Close()

	response, err := LoginOTP("demo@gather.network", "invalidCode", server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected StatusCode, Expected: %v, but got: %v", expectedStatusCode, response.StatusCode)
	}
	if response.ErrorDetail != "Invalid Credentials!" {
		t.Errorf("Unexpected ErrorMessage. Expected ErrorDetail: Invalid Credentials!, but got %v", response.ErrorDetail)
	}

}
func TestVerifyAccessTokenSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		err := json.NewDecoder(r.Body).Decode(&response)
		if err != nil {
			log.Fatalf(err.Error())
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
		w.WriteHeader(http.StatusNotFound)
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
	expectedStatusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var refreshToken refreshAccessToken
		err := json.NewDecoder(r.Body).Decode(&refreshToken)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"access":"new_access_token","refresh":"new_refresh_token"}`)
	}))
	defer server.Close()

	resp := &Response{Refresh: "valid_refresh"}
	response, err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected response! Expected StatusCode: values: %v, but got StatusCode: %v", expectedStatusCode, response.StatusCode)
	}
	if response.Access != "new_access_token" {
		t.Errorf("Unexpected response! Expeced access:new_access_token but got access:%v", response.Access)
	}
	if response.Refresh != "new_refresh_token" {
		t.Errorf("Unexpected response! Expeced refresh:new_refresh_token but got refresh:%v", response.Refresh)
	}
}

func TestRefreshAccessTokenFail(t *testing.T) {
	expectedStatusCode := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var refreshToken refreshAccessToken
		err := json.NewDecoder(r.Body).Decode(&refreshToken)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(expectedStatusCode)
		io.WriteString(w, `{"detail":"Token_is_Invalid"}`)
	}))
	defer server.Close()

	resp := &Response{Refresh: "invalid_refresh"}
	response, err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected StatusCode, Expected: %v, but got: %v", expectedStatusCode, response.StatusCode)
	}
	if response.ErrorDetail != "Token_is_Invalid" {
		t.Errorf("Unexpected ErrorMessage. Expected ErrorDetail: Token_is_Invalid, but got %v", response.ErrorDetail)
	}
}

func TestVerifyJWTToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		err := json.NewDecoder(r.Body).Decode(&response)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}))
	defer server.Close()

	resp := &Response{
		Refresh:    "some_refresh",
		Access:     "some_access",
		StatusCode: http.StatusOK,
	}
	_, response, err := resp.VerifyJWTToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("Unexpected StatusCode: %v", response.StatusCode)
	}
}
