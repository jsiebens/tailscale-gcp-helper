package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	stdoauth2 "golang.org/x/oauth2"
	"net/http"
	"tailscale.com/client/tailscale"
	"time"
)

type accessTokenRequest struct {
	GrantType          string `json:"grantType,omitempty"`
	Audience           string `json:"audience,omitempty"`
	Scope              string `json:"scope,omitempty"`
	RequestedTokenType string `json:"requestedTokenType,omitempty"`
	SubjectToken       string `json:"subjectToken,omitempty"`
	SubjectTokenType   string `json:"subjectTokenType,omitempty"`
	Options            string `json:"options,omitempty"`
}

type accessTokenResponse struct {
	AccessToken     string `json:"access_token,omitempty"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	TokenType       string `json:"token_type,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

type serviceAccountTokenResponse struct {
	AccessToken string `json:"accessToken,omitempty"`
	ExpireTime  string `json:"expireTime,omitempty"`
}

type Config struct {
	Audience       string
	ServiceAccount string
	Scope          string
}

type tailscaleTokenSource struct {
	audience       string
	scope          string
	serviceAccount string
}

func DefaultAudience(projectNumber, poolId, providerId string) string {
	return fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, poolId, providerId)
}

func DefaultConfig(serviceAccount string, audience string) *Config {
	return &Config{
		Scope:          "https://www.googleapis.com/auth/cloud-platform",
		Audience:       audience,
		ServiceAccount: serviceAccount,
	}
}

func TailscaleTokenSource(config *Config) stdoauth2.TokenSource {
	return stdoauth2.ReuseTokenSource(nil, &tailscaleTokenSource{
		audience:       config.Audience,
		scope:          config.Scope,
		serviceAccount: config.ServiceAccount,
	})
}

func (sts *tailscaleTokenSource) Token() (*stdoauth2.Token, error) {
	tsIDToken, err := sts.getTailscaleIDToken()
	if err != nil {
		return nil, err
	}

	token := accessTokenResponse{}
	if err = sts.getWorkloadIdentityFederationToken(tsIDToken, &token); err != nil {
		return nil, err
	}

	saToken := serviceAccountTokenResponse{}
	if err = sts.impersonateIamServiceAccount(token.AccessToken, &saToken); err != nil {
		return nil, err
	}

	layout := "2006-01-02T15:04:05Z"
	t, err := time.Parse(layout, saToken.ExpireTime)
	if err != nil {
		return nil, err
	}

	return &stdoauth2.Token{
		AccessToken: saToken.AccessToken,
		Expiry:      t,
		TokenType:   "Bearer",
	}, nil
}

func (sts *tailscaleTokenSource) getTailscaleIDToken() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token, err := tailscale.IDToken(ctx, sts.audience)
	if err != nil {
		return "", err
	}
	return token.IDToken, nil
}

func (sts *tailscaleTokenSource) getWorkloadIdentityFederationToken(tsIDToken string, token *accessTokenResponse) error {
	tokenRequest := accessTokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Audience:           sts.audience,
		Scope:              sts.scope,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectToken:       tsIDToken,
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
	}

	body, err := json.Marshal(tokenRequest)
	if err != nil {
		return err
	}

	resp, err := http.Post("https://sts.googleapis.com/v1/token", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		return fmt.Errorf("failed retrieving token: %d - %s", resp.StatusCode, resp.Status)
	} else {
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(token)
		if err != nil {
			return err
		}
		return nil
	}
}

func (sts *tailscaleTokenSource) impersonateIamServiceAccount(wifToken string, token *serviceAccountTokenResponse) error {
	body := []byte(fmt.Sprintf(`{
        "scope": [ "%s" ]
    }`, sts.scope))

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", sts.serviceAccount),
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", wifToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		return fmt.Errorf("failed retrieving token: %d - %s", resp.StatusCode, resp.Status)
	} else {
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(token)
		if err != nil {
			return err
		}
		return nil
	}
}
