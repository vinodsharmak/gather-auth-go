package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogin(t *testing.T) {
	x := email{"check123@gmail.com"}
	requestByte, _ := json.Marshal(x)
	requestReader := bytes.NewReader(requestByte)
	req, err := http.NewRequest("POST", "/api/v1/token/", requestReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": false}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestLoginOTP(t *testing.T) {
	x := emailAndCode{"otp123@gmail.com", "otp123"}
	requestByte, _ := json.Marshal(x)
	requestReader := bytes.NewReader(requestByte)
	req, err := http.NewRequest("POST", "/api/v1/token/code/", requestReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginOTPHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := `{"refresh": "some_refresh_value",
		"access": "some_access_value",
		"department": "some_department_name",
		"smtp_enabled": true}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf(err.Error())
	}
	var req map[string]interface{}
	err = json.Unmarshal([]byte(bodyBytes), &req)
	if err != nil {
		log.Fatalf(err.Error())
	}
	if req["email"] == "check123@gmail.com" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": false}`)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"detail": "No active account found with the given credentials"}`)
	}

	w.Header().Set("Content-Type", "application/json")
}

func loginOTPHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf(err.Error())
	}
	var req map[string]interface{}
	err = json.Unmarshal([]byte(bodyBytes), &req)
	if err != nil {
		log.Fatalf(err.Error())
	}
	if req["email"] == "otp123@gmail.com" && req["code"] == "otp123" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"refresh": "some_refresh_value",
		"access": "some_access_value",
		"department": "some_department_name",
		"smtp_enabled": true}`)
	} else {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"detail": "Not found."}`)
	}

	w.Header().Set("Content-Type", "application/json")
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
