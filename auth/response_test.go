package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseAuthToken(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		response       Response
		expectedResult string
		msg            string
	}{
		{
			msg:            "without access",
			response:       Response{},
			expectedResult: "",
		},
		{
			msg:            "access exits",
			response:       Response{Access: "access token"},
			expectedResult: "access token",
		},
		{
			msg:            "access is not a string",
			response:       Response{},
			expectedResult: "",
		},
	}

	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			r := Response{Access: c.response.Access}
			assert.Equal(c.expectedResult, r.Access)
		})
	}
}

func TestResponseSMTPEnabled(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		response       Response
		expectedResult bool
		msg            string
	}{
		{
			msg:            "smtp_enabled is false",
			response:       Response{SmtpEnabled: false},
			expectedResult: false,
		},
		{
			msg:            "smtp_enabled is true",
			response:       Response{SmtpEnabled: true},
			expectedResult: true,
		},
	}

	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			r := Response{SmtpEnabled: c.response.SmtpEnabled}
			assert.Equal(c.expectedResult, r.SmtpEnabled)
		})
	}
}
