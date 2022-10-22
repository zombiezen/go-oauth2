// Package googleauth provides a client for [Google API authorization].
//
// [Google API authorization]: https://developers.google.com/identity/authorization
package googleauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zombiezen.com/go/oauth2"
	"zombiezen.com/go/oauth2/accesstoken"
)

// Client is a Google OAuth 2.0 client.
// It implements the [oauth2.Refresher] interface.
type Client struct {
	client       *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
}

// Exchange exchanges an authorization code
// (obtained from the second leg of three-legged OAuth 2.0)
// for an access token and possibly a refresh token.
func (r *Client) Exchange(ctx context.Context, code string, redirectURI string) (oauth2.AccessToken, oauth2.RefreshToken, error) {
	return r.do(ctx, &accesstoken.Request{
		ClientID:     r.clientID,
		ClientSecret: r.clientSecret,
		AuthCode:     code,
		RedirectURL:  redirectURI,
	})
}

// Refresh obtains an access token from a provided refresh token.
// See the [oauth2.Refresher] interface for more details.
func (r *Client) Refresh(ctx context.Context, rt oauth2.RefreshToken) (oauth2.AccessToken, oauth2.RefreshToken, error) {
	return r.do(ctx, &accesstoken.Request{
		ClientID:     r.clientID,
		ClientSecret: r.clientSecret,
		RefreshToken: rt,
	})
}

func (r *Client) do(ctx context.Context, req *accesstoken.Request) (oauth2.AccessToken, oauth2.RefreshToken, error) {
	hreq, err := accesstoken.HTTPRequest(r.tokenURL, accesstoken.RequestBodyAuth, req)
	if err != nil {
		return oauth2.AccessToken{}, "", err
	}
	hres, err := r.client.Do(hreq.WithContext(ctx))
	if err != nil {
		return oauth2.AccessToken{}, "", err
	}
	defer hres.Body.Close()

	if hres.StatusCode != http.StatusOK {
		return oauth2.AccessToken{}, "", err
	}
	body, err := io.ReadAll(io.LimitReader(hres.Body, 1<<20)) // limit to 1MiB
	if err != nil {
		return oauth2.AccessToken{}, "", err
	}
	res, err := accesstoken.ParseJSON(body, time.Now())
	if err != nil {
		return oauth2.AccessToken{}, "", err
	}
	return res.AccessToken, res.RefreshToken, nil
}

// ClientCredentials holds the parsed values of a Google OAuth 2.0 client secret JSON file.
type ClientCredentials struct {
	// Type is one of "web" or "installed".
	Type string

	ClientID     string
	ClientSecret string
	RedirectURIs []string
	AuthURI      string
	TokenURI     string
}

func (creds *ClientCredentials) UnmarshalJSON(data []byte) error {
	type cred struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
		AuthURI      string   `json:"auth_uri"`
		TokenURI     string   `json:"token_uri"`
	}
	var j struct {
		Web       *cred `json:"web"`
		Installed *cred `json:"installed"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var c *cred
	switch {
	case j.Web != nil:
		creds.Type = "web"
		c = j.Web
	case j.Installed != nil:
		creds.Type = "installed"
		c = j.Installed
	default:
		return fmt.Errorf("oauth2/google: no credentials found")
	}
	creds.ClientID = c.ClientID
	creds.ClientSecret = c.ClientSecret
	creds.RedirectURIs = c.RedirectURIs
	creds.AuthURI = c.AuthURI
	creds.TokenURI = c.TokenURI
	return nil
}

// Client returns an [Client] that communicates using the given HTTP client.
func (creds *ClientCredentials) Client(client *http.Client) *Client {
	return &Client{
		client:       client,
		tokenURL:     creds.TokenURI,
		clientID:     creds.ClientID,
		clientSecret: creds.ClientSecret,
	}
}

// AuthCodeURL holds the parameters to build an [authorization URL].
//
// [authorization URL]: https://developers.google.com/identity/protocols/oauth2/native-app#step-2:-send-a-request-to-googles-oauth-2.0-server
type AuthCodeURL struct {
	AccessType  string
	Scopes      []string
	State       string
	ClientID    string
	RedirectURI string
}

// String formats the URL as a string.
func (u *AuthCodeURL) String() string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {u.ClientID},
		"redirect_uri":  {u.RedirectURI},
		"state":         {u.State},
		"scope":         {strings.Join(u.Scopes, " ")},
	}
	if u.AccessType != "" {
		q.Set("access_type", u.AccessType)
	}
	return (&url.URL{
		Scheme:   "https",
		Host:     "accounts.google.com",
		Path:     "/o/oauth2/v2/auth",
		RawQuery: q.Encode(),
	}).String()
}
