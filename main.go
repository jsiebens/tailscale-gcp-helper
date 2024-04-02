package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"tailscale.com/client/tailscale"
)

func main() {
	aud := flag.String("aud", "", "")
	flag.Parse()

	if aud == nil || len(*aud) == 0 {
		logFatal("400", "Missing -aud flag", fmt.Errorf("missing -aud flag"))
	}

	var tsclient tailscale.LocalClient

	token, err := tsclient.IDToken(context.Background(), *aud)
	if err != nil {
		logFatal("401", "Caller not authorized.", err)
	}
	claims := jwt.MapClaims{}

	parser := jwt.NewParser()
	withClaims, _, err := parser.ParseUnverified(token.IDToken, claims)
	if err != nil {
		logFatal("500", "", err)
	}

	exp, err := withClaims.Claims.GetExpirationTime()
	if err != nil {
		logFatal("500", "", err)
	}

	c := &credentials{
		Version:        1,
		Success:        true,
		TokenType:      "urn:ietf:params:oauth:token-type:id_token",
		IDToken:        token.IDToken,
		ExpirationTime: exp,
	}

	marshal, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(marshal))
}

func logFatal(code string, msg string, err error) {
	c := &credentials{
		Version: 1,
		Success: false,
		Code:    code,
		Message: msg,
	}

	if msg == "" {
		c.Message = err.Error()
	}

	marshal, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(marshal))

	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

type credentials struct {
	Version        int              `json:"version,omitempty"`
	Success        bool             `json:"success,omitempty"`
	TokenType      string           `json:"token_type,omitempty"`
	IDToken        string           `json:"id_token,omitempty"`
	ExpirationTime *jwt.NumericDate `json:"expiration_time,omitempty"`

	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
