package auth

import (
	"strconv"
)

type response struct {
	data       map[string]interface{}
	statusCode int
}
type authResponse interface {
	baseResponse
	AuthToken() string
	SMTPEnabled() bool
}

type baseResponse interface {
	Data() map[string]interface{}
	StatusCode() int
}

func newResponse(data map[string]interface{}, statusCode int) *response {
	return &response{data: data, statusCode: statusCode}
}

func (r *response) AuthToken() string {
	var result string

	switch v := r.data["access"].(type) {
	case string:
		result = v
	}

	return result
}

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

func (r *response) Data() map[string]interface{} {
	return r.data
}

func (r *response) StatusCode() int {
	return r.statusCode
}
