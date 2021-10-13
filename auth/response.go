package auth

import (
	"strconv"
)

type response struct {
	data       map[string]interface{}
	statusCode int
}
type baseResponse interface {
	Data() map[string]interface{}
	StatusCode() int
}
type authResponse interface {
	baseResponse
	AuthToken() string
	SMTPEnabled() bool
}

func newResponse(data map[string]interface{}, statusCode int) *response {
	return &response{data: data, statusCode: statusCode}
}

//AuthToken() returns access token from the controller response body
func (r *response) AuthToken() string {
	var result string

	switch v := r.data["access"].(type) {
	case string:
		result = v
	}

	return result
}

//SMTPEnabled() checks if the smtp is enabled from the response body of Login()
func (r *response) SMTPEnabled() bool {
	var result bool

	switch v := r.data["smtp_enabled"].(type) {
	case bool:
		result = v
	case string:
		r, err := strconv.ParseBool(v)
		if err == nil {
			result = r
		}
	}

	return result
}

//Data() returns the data from the controller response body
func (r *response) Data() map[string]interface{} {
	return r.data
}

//StatusCode() returns the statuscode of the controller response
func (r *response) StatusCode() int {
	return r.statusCode
}
