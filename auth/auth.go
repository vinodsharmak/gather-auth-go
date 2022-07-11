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

/*Login takes email and controller url as parameters.
It sends login request to the controller and returns response from controller or error.
*/
func Login(anEmail string, url string, args ...interface{}) (Response, error) {
	requestByte, err := json.Marshal(email{anEmail})
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequest(http.MethodPost, url+"/api/v1/token/", bytes.NewReader(requestByte))
	if err != nil {
		return Response{}, err
	}

	req.Header.Add("Content-Type", contentType)
	if len(args) > 0 {
		req.Header.Add("Request-Source", fmt.Sprintf("%s", args[0]))
	}

	resp, err := client.Do(req)
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

/*AskOtp checks if otp is required using values is_otp_enabled and smtp_enabled.
It return boolean value, true if otp required and false if not required.
*/
func (r *Response) AskOtp() bool {
	return r.IsOtpEnabled && r.SMTPEnabled
}

/*LoginOTP takes email, code/OTP and controller url as parameters.
It should be used in the case if AskOtp() returns true.
*/
func LoginOTP(email string, code string, url string, args ...interface{}) (Response, error) {
	jsonReq, err := json.Marshal(emailAndCode{email, code})
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequest(http.MethodPost, url+"/api/v1/token/code/", bytes.NewReader(jsonReq))
	if err != nil {
		return Response{}, err
	}

	req.Header.Add("Content-Type", contentType)
	if len(args) > 0 {
		req.Header.Add("Request-Source", fmt.Sprintf("%s", args[0]))
	}

	resp, err := client.Do(req)
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

/*VerifyAccessToken takes controller url as parameter and can only be called as a Response function
It verfies the if the access token is still valid and returns false if expired or true if still valid.
*/
func (r *Response) VerifyAccessToken(url string) (bool, error) {
	jsonReq, err := json.Marshal(verifyAccessToken{r.Access})
	if err != nil {
		return false, err
	}

	urlPath := fmt.Sprintf("%s/api/v1/token/verify/", url)
	req, err := http.NewRequest(http.MethodPost, urlPath, bytes.NewBuffer(jsonReq))
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

	if resp.StatusCode == http.StatusOK {
		var data VerifyResponse
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return false, err
		}
		if !data.IsWorkerNode {
			return false, errors.New("access is restricted")
		}
		return true, nil
	}

	return false, nil
}

/*RefreshAccessToken takes controller url as a prameter and can be called as a response function.
It refresh the access token using the existing refresh token.
*/
func (r *Response) RefreshAccessToken(url string) error {
	jsonReq, err := json.Marshal(refreshAccessToken{r.Refresh})
	if err != nil {
		return err
	}

	urlPath := fmt.Sprintf("%s/api/v1/token/refresh/", url)
	req, err := http.NewRequest(http.MethodPost, urlPath, bytes.NewBuffer(jsonReq))
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

/*VerifyAndRefreshAccessToken takes controller url as a prameter and can be called as a response function.
It uses VerifyAccessToken and RefreshAccessToken functions to verify if the existing access token is expired.
and tries to refresh it using the refresh token. It throws error in case token is expired and cannot be refreshed.
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
