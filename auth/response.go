package auth

// Response is the used to store the response values from the controller.
type Response struct {
	Refresh      string `json:"refresh"`
	Access       string `json:"access"`
	Department   string `json:"department"`
	SMTPEnabled  bool   `json:"smtp_enabled"`
	IsOtpEnabled bool   `json:"is_otp_enabled"`
	ErrorDetail  string `json:"detail"`
	StatusCode   int
}

type VerifyResponse struct {
	IsWorkerNode bool `json:"is_worker_node"`
}
