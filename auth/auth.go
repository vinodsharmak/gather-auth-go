package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const contentType = "application/json; charset=utf-8"

var client = &http.Client{}

/* Login takes email and controller url as parameters.
It sends login request to the controller and returns response from controller or error.
*/
func Login(anEmail string, url string) (Response, error) {
	jsonReq, err := json.Marshal(email{anEmail})
	if err != nil {
		return Response{}, err
	}
	resp, err := http.Post(url+"/api/v1/token/", contentType, bytes.NewBuffer(jsonReq))
	if err != nil {
		return Response{StatusCode: resp.StatusCode}, err
	}
	defer resp.Body.Close()

	var data Response
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return data, err
	}

	if data.IsOtpEnabled && data.SmtpEnabled {
		data.AskOtp = true
	}

	data.StatusCode = resp.StatusCode

	return data, nil
}

/* LoginOTP takes email, code/OTP and controller url as parameters.
LoginOTP should be used in the case if AskOtp is true.
*/
func LoginOTP(email string, code string, url string) (Response, error) {
	jsonReq, err := json.Marshal(emailAndCode{email, code})
	if err != nil {
		return Response{}, err
	}

	resp, err := http.Post(url+"/api/v1/token/code/", contentType, bytes.NewBuffer(jsonReq))
	if err != nil {
		return Response{StatusCode: resp.StatusCode}, err
	}
	defer resp.Body.Close()

	var data Response
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return data, err
	}

	data.StatusCode = resp.StatusCode

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

	urlPath := fmt.Sprintf("%s/api/v1/token/verify/", url)
	req, err := http.NewRequest("POST", urlPath, bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", r.Access))
	req.Header.Add("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	return true, nil

}

/* RefreshAccessToken takes controller url as a prameter and can be called as a response function.
It refresh the access token using the existing refresh token
*/
func (r *Response) RefreshAccessToken(url string) error {
	jsonReq, err := json.Marshal(refreshAccessToken{r.Refresh})
	if err != nil {
		return err
	}

	urlPath := fmt.Sprintf("%s/api/v1/token/refresh/", url)
	req, err := http.NewRequest("POST", urlPath, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", r.Access))
	req.Header.Add("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	r.StatusCode = resp.StatusCode

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return err
	}

	return nil
}

/* VerifyAndRefreshJWTToken takes controller url as a prameter and can be called as a response function.
It uses VerifyAccessToken and RefreshAccessToken functions to verify if the existing access token is expired.
And tries to refresh it using the refresh token. It throws error in case token is expired and cannot be refreshed.
*/
func (r *Response) VerifyAndRefreshAccessToken(url string) error {
	isValid, err := r.VerifyAccessToken(url)
	if err != nil {
		return err
	}

	if !isValid {
		err := r.RefreshAccessToken(url)
		if err != nil {
			return err
		}

		if r.StatusCode != http.StatusOK {
			if r.StatusCode == http.StatusUnauthorized {
				return errors.New("invalid/expired token")
			}
			return errors.New("unexpected error")
		}
	}

	return nil
}
