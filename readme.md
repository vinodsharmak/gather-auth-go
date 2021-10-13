# Gather-Auth-Go

Authentication package for golang repositories which sends authentication requests to the gather controller.

## Auth package

1. **auth.go** *(Exported functions)*

   - `Login( email string, url string ) (authResponse, error)`
     - *Login takes email and controller url as parameters. It sends login request to the controller and returns response from controller or error.*

     - *If smtp is disabled it will directly login the user in case of correct email.*

     - *If smtp is enabled it will send an OTP to the user's email and ask the user to fill in the OTP  to login.*

   - `LoginOTP( email string, code string, url string ) (authResponse, error)`
     - *LoginOTP takes email, code/OTP and controller url as parameters.*
     - *LoginOTP should be used in the case if smtp is enabled.*

2. **response.go** *(Exported Functions)*

   - `AuthToken() string`
     - *Takes **access** token  from the controller response body and returns it* as a **string**.
   - `SMTPEnabled() bool`
     - *Checks if the **smtp** is enabled from the response body of Login() and returns a **boolean** value*.
   - `Data() map[string]interface{}`
     - *Returns the **data** from the controller response body as a `map[string]interface{}`.*
   - `StatusCode() int`
     - *Returns the **StatusCode** of the response as an **integer**.*
     - *Returns the **StatusCode** of the response as an **integer**.*
