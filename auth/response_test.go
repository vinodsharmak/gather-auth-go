package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseAuthToken(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		data           map[string]interface{}
		expectedResult string
		msg            string
	}{
		{
			msg:            "without access",
			data:           map[string]interface{}{},
			expectedResult: "",
		},
		{
			msg:            "access exits",
			data:           map[string]interface{}{"access": "access token"},
			expectedResult: "access token",
		},
		{
			msg:            "access is not a string",
			data:           map[string]interface{}{"access": 3.14},
			expectedResult: "",
		},
	}

	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			r := response{data: c.data}
			assert.Equal(c.expectedResult, r.AuthToken())
		})
	}
}

func TestResponseSMTPEnabled(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		data           map[string]interface{}
		expectedResult bool
		msg            string
	}{
		{
			msg:            "without smtp_enabled",
			data:           map[string]interface{}{},
			expectedResult: false,
		},
		{
			msg:            "smtp_enabled is 'true'",
			data:           map[string]interface{}{"smtp_enabled": "true"},
			expectedResult: true,
		},
		{
			msg:            "smtp_enabled is 'false'",
			data:           map[string]interface{}{"smtp_enabled": "false"},
			expectedResult: false,
		},
		{
			msg:            "smtp_enabled is true",
			data:           map[string]interface{}{"smtp_enabled": true},
			expectedResult: true,
		},
		{
			msg:            "smtp_enabled is false",
			data:           map[string]interface{}{"smtp_enabled": false},
			expectedResult: false,
		},
		{
			msg:            "smtp_enabled is not a bool",
			data:           map[string]interface{}{"smtp_enabled": "string"},
			expectedResult: false,
		},
	}

	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			r := response{data: c.data}
			assert.Equal(c.expectedResult, r.SMTPEnabled())
		})
	}
}
