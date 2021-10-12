package main

import (
	"check.com/gather-auth-go/auth"
)

func main() {
	auth.LoginOTP("nehal@gather.network", "zUqTbbZd", "https://dev-controller.gather.network")
}
