package auth

//Request body struct for Login function
type email struct {
	Email string `json:"email"`
}

//Request body struct for LoginOTP function
type emailAndCode struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
