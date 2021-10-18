package auth

import (
	"fmt"
	"net/http"
)

//response is the used to store the response values from the controller
type Response struct {
	Refresh      string
	Access       string
	Department   string
	Smtp_enabled bool
	ErrorDetail  string
	Status_code  int
}

//newResponse takes the response from controller in map format and stores it into the 'response' Struct
func newResponse(data map[string]interface{}, statusCode int) *Response {
	if statusCode == http.StatusOK {
		return &Response{Refresh: fmt.Sprintf("%v", data["refresh"]),
			Access:       fmt.Sprintf("%v", data["access"]),
			Department:   fmt.Sprintf("%v", data["department"]),
			Smtp_enabled: data["smtp_enabled"].(bool),
			ErrorDetail:  "No error!",
			Status_code:  statusCode}
	} else {
		return &Response{ErrorDetail: fmt.Sprintf("%v", data), Status_code: statusCode}
	}

}

//AuthToken() returns access token from the controller response body
func (r *Response) AuthToken() string {
	result := r.Access
	return result
}

//SMTPEnabled() checks if the smtp is enabled from the response body of Login()
func (r *Response) SMTPEnabled() bool {
	result := r.Smtp_enabled
	return result
}

//Data() returns the data from the controller response body
func (r *Response) Data() Response {
	return Response{r.Refresh, r.Access, r.Department, r.Smtp_enabled, r.ErrorDetail, r.Status_code}
}

//StatusCode() returns the statuscode of the controller response
func (r *Response) StatusCode() int {
	return r.Status_code
}
