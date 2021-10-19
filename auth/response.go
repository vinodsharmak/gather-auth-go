package auth

//response is the used to store the response values from the controller
type Response struct {
	Refresh      string `json:"refresh"`
	Access       string `json:"access"`
	Department   string `json:"department"`
	Smtp_enabled bool   `json:"smtp_enabled"`
	Error_detail string `json:"detail"`
	Status_code  int
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
	return Response{r.Refresh, r.Access, r.Department, r.Smtp_enabled, r.Error_detail, r.Status_code}
}

//StatusCode() returns the statuscode of the controller response
func (r *Response) StatusCode() int {
	return r.Status_code
}
