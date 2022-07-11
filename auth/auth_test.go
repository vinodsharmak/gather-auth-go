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
		_, err = io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": false}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
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
		_, err = io.WriteString(w, `{"detail": "Invalid email id."}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
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
		_, err = io.WriteString(w, `{"refresh": "some_refresh_value", "access": "some_access_value", "department": "some_department_name", "smtp_enabled": true}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
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
		_, err = io.WriteString(w, `{"detail": "Invalid Credentials!"}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
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
		var request Response
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Fatalf(err.Error())
		}
		response := `{"is_worker_node": true}`
		_, err = w.Write([]byte(response))
		if err != nil {
			log.Fatal(err.Error())
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
		_, err = io.WriteString(w, `{"access":"new_access_token","refresh":"new_refresh_token"}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}))
	defer server.Close()

	resp := &Response{Refresh: "valid_refresh"}
	err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if resp.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected response! Expected StatusCode: values: %v, but got StatusCode: %v", expectedStatusCode, resp.StatusCode)
	}
	if resp.Access != "new_access_token" {
		t.Errorf("Unexpected response! Expeced access:new_access_token but got access:%v", resp.Access)
	}
	if resp.Refresh != "new_refresh_token" {
		t.Errorf("Unexpected response! Expeced refresh:new_refresh_token but got refresh:%v", resp.Refresh)
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
		_, err = io.WriteString(w, `{"detail":"Token_is_Invalid"}`)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}))
	defer server.Close()

	resp := &Response{Refresh: "invalid_refresh"}
	err := resp.RefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if resp.StatusCode != expectedStatusCode {
		t.Errorf("Unxpected StatusCode, Expected: %v, but got: %v", expectedStatusCode, resp.StatusCode)
	}
	if resp.ErrorDetail != "Token_is_Invalid" {
		t.Errorf("Unexpected ErrorMessage. Expected ErrorDetail: Token_is_Invalid, but got %v", resp.ErrorDetail)
	}
}

func TestVerifyAndRefreshAccessTokenStatusOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request Response
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Fatalf(err.Error())
		}
		response := `{"is_worker_node": true}`
		_, err = w.Write([]byte(response))
		if err != nil {
			log.Fatal(err.Error())
		}
	}))
	defer server.Close()

	resp := &Response{
		Refresh:    "valid_refresh",
		Access:     "valid_access",
		StatusCode: http.StatusOK,
	}
	err := resp.VerifyAndRefreshAccessToken(server.URL)
	if err != nil {
		t.Errorf("Unexpected error on request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected StatusCode: %v", resp.StatusCode)
	}
	if resp.Access != "valid_access" {
		t.Errorf("Unexpected response: %v", resp.Access)
	}
	if resp.Refresh != "valid_refresh" {
		t.Errorf("Unexpected response: %v", resp.Refresh)
	}
}

func TestVerifyAndRefreshAccessTokenStatusUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		err := json.NewDecoder(r.Body).Decode(&response)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	resp := &Response{
		Refresh:    "expired_refresh",
		Access:     "expired_access",
		StatusCode: http.StatusOK,
	}
	err := resp.VerifyAndRefreshAccessToken(server.URL)
	if err == nil {
		t.Errorf("Expected error on request.")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Unexpected StatusCode: %v", resp.StatusCode)
	}
	if resp.Access != "expired_access" {
		t.Errorf("Unexpected response: %v", resp.Access)
	}
	if resp.Refresh != "expired_refresh" {
		t.Errorf("Unexpected response: %v", resp.Refresh)
	}
}

func TestVerifyAndRefreshAccessTokenError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		err := json.NewDecoder(r.Body).Decode(&response)
		if err != nil {
			log.Fatalf(err.Error())
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	resp := &Response{
		Refresh:    "expired_refresh",
		Access:     "expired_access",
		StatusCode: http.StatusOK,
	}
	err := resp.VerifyAndRefreshAccessToken(server.URL)
	if err == nil {
		t.Errorf("Expected error on request.")
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("Unexpected StatusCode: %v", resp.StatusCode)
	}
	if resp.Access != "expired_access" {
		t.Errorf("Unexpected response: %v", resp.Access)
	}
	if resp.Refresh != "expired_refresh" {
		t.Errorf("Unexpected response: %v", resp.Refresh)
	}
}

func TestAskOtp(t *testing.T) {
	askOtpTrueResponse := true
	askOtpFalseResponse := false

	tests := []struct {
		name string
		resp Response
		want bool
	}{
		{name: "AskOtpTrue", resp: Response{SMTPEnabled: true, IsOtpEnabled: true}, want: askOtpTrueResponse},
		{name: "AskOtpFalse1", resp: Response{SMTPEnabled: false, IsOtpEnabled: true}, want: askOtpFalseResponse},
		{name: "AskOtpFalse2", resp: Response{SMTPEnabled: true, IsOtpEnabled: false}, want: askOtpFalseResponse},
		{name: "AskOtpFalse3", resp: Response{SMTPEnabled: false, IsOtpEnabled: false}, want: askOtpFalseResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.AskOtp()
			if result != tt.want {
				t.Errorf("Unexpected response. Expected: %v but got: %v ", tt.want, result)
			}
		})
	}
}
