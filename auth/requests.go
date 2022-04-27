package auth

// Request body struct for Login function.
type email struct {
	Email string `json:"email"`
}

// Request body struct for LoginOTP function.
type emailAndCode struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// Request body struct for VerifyAccessToken function.
type verifyAccessToken struct {
	Token string `json:"token"`
}

// Request body struct for GenerateAccessToken function.
type refreshAccessToken struct {
	Refresh string `json:"refresh"`
}
