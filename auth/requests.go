package auth

type email struct {
	Email string `json:"email"`
}

type emailAndCode struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
