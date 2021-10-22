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
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unexpected StatusCode on request, expected: %v, got: %v", expectedStatusCode, response.StatusCode)
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
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unexpected StatusCode on request, expected: %v, got: %v", expectedStatusCode, response.StatusCode)
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
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unexpected StatusCode on request, expected: %v, got: %v", expectedStatusCode, response.StatusCode)
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
	if response.StatusCode != expectedStatusCode {
		t.Errorf("Unexpected StatusCode on request, expected: %v, got: %v", expectedStatusCode, response.StatusCode)
	}

}
func TestVerifyAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	cluster := &Response{
		Refresh: "some_refresh",
		Access:  "some_access",
	}

	_, err := cluster.VerifyAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access":"some_access_token","refresh":"some_refresh_token"}`)
	}))
	defer server.Close()

	cluster := &Response{
		Refresh: "some_refresh",
		Access:  "some_access",
	}
	response, err := cluster.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if response.Access != "some_access_token" {
		t.Errorf("Expected access token: some_access_token, but got access token: %s", response.Access)
	}
}
