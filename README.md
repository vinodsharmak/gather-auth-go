# Gather-Auth-Go

Authentication package for golang repositories which sends authentication requests to the gather controller.

## Auth package

1. **auth.go** *(Exported functions)*

   - `Login( email string, url string ) (Response, error)`
     - *Login takes email and controller url as parameters. It sends login request to the controller and returns response from controller or error.*
     - *If AskOtp() returns false, OTP is not required. Directly login the user in case of correct email.*
     - *If AskOtp() returns true, OTP is required. User will receive an email with OTP, ask the user to fill in received OTP to login.*

   - `LoginOTP( email string, code string, url string ) (Response, error)`
     - *LoginOTP takes email, code/OTP and controller url as parameters.*
     - *LoginOTP should be used in the case if AskOtp() returns true.*

  -  `(r *Response) AskOtp()`
     - *Return value of AskOtp() is calculated using values of is_otp_enabled and smtp_enabled. To check if OTP is required to login, use AskOtp().*
     - *If AskOtp() returns false, OTP is not required. Directly login the user in case of correct email.*
     - *If AskOtp() returns true, OTP is required. User will receive an email with OTP, ask the user to fill in received OTP to login.*

   - `(r *Response) VerifyAccessToken(url string) (bool, error)`
     - *VerifyAccessToken is a function of Response struct which take contoller url as a parameter.*
     - *VerifyAccessToken verifies if the current access_token is expired or not, it returns bool and error.*
     - *If return value is true, then the access_token is still valid and not expired. If return value is false, then the access token is expired.*

   - `(r *Response) RefreshAccessToken(url string) (*Response, error)`
     - *RefreshAccessToken is a function of Response struct which take contoller url as a parameter.*
     - *RefreshAccessToken refresh the access_token using the current refresh_token if the current refresh_token is not expired.*
     - *RefreshAccessToken updates the access token in the same Response struct and returns a pointer. It also returns an error message if there is any.*
