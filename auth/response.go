package auth

//Response is the used to store the response values from the controller
type Response struct {
	Refresh     string `json:"refresh"`
	Access      string `json:"access"`
	Department  string `json:"department"`
	SmtpEnabled bool   `json:"smtp_enabled"`
	ErrorDetail string `json:"detail"`
	StatusCode  int
}
