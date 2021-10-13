package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

/* Login takes email and controller url as parameters.
It sends login request to the controller and returns response from controller or error.
*/
func Login(anEmail string, url string) (authResponse, error) {
	jsonReq, err := json.Marshal(email{anEmail})
	if err != nil {
		return newResponse(nil, 0), err
	}
	resp, err := http.Post(url+"/api/v1/token/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return newResponse(nil, resp.StatusCode), err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return newResponse(nil, resp.StatusCode), err
	}

	var data map[string]interface{}
	err = json.Unmarshal([]byte(bodyBytes), &data)
	if err != nil {
		return newResponse(data, resp.StatusCode), err
	}

	return newResponse(data, resp.StatusCode), nil
}

/* LoginOTP takes email, code/OTP and controller url as parameters.
LoginOTP should be used in the case if smtp is enabled.
*/
func LoginOTP(email string, code string, url string) (authResponse, error) {
	jsonReq, err := json.Marshal(emailAndCode{email, code})
	if err != nil {
		return newResponse(nil, 0), err
	}

	resp, err := http.Post(url+"/api/v1/token/code/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return newResponse(nil, resp.StatusCode), err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return newResponse(nil, resp.StatusCode), err
	}

	var data map[string]interface{}
	err = json.Unmarshal([]byte(bodyBytes), &data)
	if err != nil {
		return newResponse(data, resp.StatusCode), err
	}
	return newResponse(data, resp.StatusCode), nil
}
