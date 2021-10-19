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
func Login(anEmail string, url string) (Response, error) {
	jsonReq, err := json.Marshal(email{anEmail})
	if err != nil {
		return Response{}, err
	}
	resp, err := http.Post(url+"/api/v1/token/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return Response{Status_code: resp.StatusCode}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{Status_code: resp.StatusCode}, err
	}
	var data Response
	err = json.Unmarshal([]byte(bodyBytes), &data)
	data.Status_code = resp.StatusCode
	if err != nil {
		return data, err
	}
	return data, nil
}

/* LoginOTP takes email, code/OTP and controller url as parameters.
LoginOTP should be used in the case if smtp is enabled.
*/
func LoginOTP(email string, code string, url string) (Response, error) {
	jsonReq, err := json.Marshal(emailAndCode{email, code})
	if err != nil {
		return Response{}, err
	}

	resp, err := http.Post(url+"/api/v1/token/code/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return Response{Status_code: resp.StatusCode}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{Status_code: resp.StatusCode}, err
	}

	var data Response
	err = json.Unmarshal([]byte(bodyBytes), &data)
	data.Status_code = resp.StatusCode
	if err != nil {
		return data, err
	}
	return data, nil
}

/* VerifyAccessToken takes controller url as parameter and can only be called as a Response function
It verfies the if the access token is still valid and returns false if expired or true if still valid.
*/
func (r *Response) VerifyAccessToken(url string) (bool, error) {
	jsonReq, err := json.Marshal(verifyAccessToken{r.Access})
	if err != nil {
		return false, err
	}

	resp, err := http.Post(url+"/api/v1/token/verify/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else {
		return false, nil
	}

}

/* RefreshAccessToken takes controller url as a prameter and can be called as a response function.
It refresh the access token using the existing refresh token
*/
func (r *Response) RefreshAccessToken(url string) (*Response, error) {
	jsonReq, err := json.Marshal(refreshAccessToken{r.Refresh})
	if err != nil {
		return r, err
	}

	resp, err := http.Post(url+"/api/v1/token/refresh/", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}
	r.Status_code = resp.StatusCode
	err = json.Unmarshal([]byte(bodyBytes), &r)
	if err != nil {
		return r, err
	}
	return r, nil

}
