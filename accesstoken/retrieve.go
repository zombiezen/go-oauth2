// Package accesstoken provides a client to retrieve OAuth 2.0 access tokens
// from an HTTP endpoint according to [RFC 6749].
//
// [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
package accesstoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"zombiezen.com/go/oauth2"
)

// Request describes an access token request as described in
// [section 4 of RFC 6749].
//
// [section 4 of RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749#section-4
type Request struct {
	ClientID     string
	ClientSecret string
	Scopes       []string   // for password, client credentials, or refresh token grants
	Form         url.Values // extra POST form data

	// The following fields are grouped by which grant type they are
	// associated with. Only one group can have their fields set
	// to non-zero values.

	// refresh_token
	RefreshToken oauth2.RefreshToken

	// password
	Username string
	Password string

	// authorization_code
	AuthCode    string
	RedirectURL string

	// client_credentials
	ClientCredentials bool
}

// GrantType returns the value of the grant_type query parameter
// based on the set fields
// or the empty string if the request has an incorrect combination of fields set.
func (tr *Request) GrantType() string {
	refreshToken := tr.RefreshToken != "" && tr.RedirectURL == ""
	password := tr.Username != "" || tr.Password != "" && tr.RedirectURL == ""
	authCode := tr.AuthCode != ""
	clientCreds := tr.ClientCredentials && tr.RedirectURL == ""
	switch {
	case refreshToken && !password && !authCode && !clientCreds:
		return "refresh_token"
	case !refreshToken && password && !authCode && !clientCreds:
		return "password"
	case !refreshToken && !password && authCode && !clientCreds:
		return "authorization_code"
	case !refreshToken && !password && !authCode && clientCreds:
		return "client_credentials"
	default:
		return ""
	}
}

// AuthMethod specifies how to send client authentication information
// to the server. See [section 2.3 of RFC 6749].
//
// [section 2.3 of RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
type AuthMethod int

// Client authentication methods.
const (
	// AuthorizationHeader places the client credentials in the Authorization header.
	AuthorizationHeader AuthMethod = iota

	// RequestBodyAuth places the client credentials as parameters in the request body.
	RequestBodyAuth
)

// HTTPRequest builds an HTTP request for a provided token request.
func HTTPRequest(requestURL string, am AuthMethod, tr *Request) (*http.Request, error) {
	v := make(url.Values)
	for k, fv := range tr.Form {
		if isReservedRequestField(k) {
			return nil, fmt.Errorf("oauth2: token request: cannot overwrite parameter %q", k)
		}
		v[k] = fv // v does not escape or mutate; no need to copy.
	}
	grant := tr.GrantType()
	v.Set("grant_type", grant)
	switch grant {
	case "refresh_token":
		v.Set("refresh_token", string(tr.RefreshToken))
		// TODO(someday): The spec does allow scope here,
		// but we don't have a need for it now.
		// TokenRequest.GrantType would also need to be changed to support it.
	case "password":
		v.Set("username", tr.Username)
		v.Set("password", tr.Password)
		if len(tr.Scopes) > 0 {
			v.Set("scope", strings.Join(tr.Scopes, " "))
		}
	case "authorization_code":
		v.Set("code", tr.AuthCode)
		v.Set("redirect_uri", tr.RedirectURL)
	case "client_credentials":
		if len(tr.Scopes) > 0 {
			v.Set("scope", strings.Join(tr.Scopes, " "))
		}
	case "":
		return nil, errors.New("oauth2: token request: invalid token request")
	default:
		return nil, fmt.Errorf("oauth2: token request: unknown request type %s", grant)
	}
	if am == RequestBodyAuth {
		if tr.ClientID != "" {
			v.Set("client_id", tr.ClientID)
		}
		if tr.ClientSecret != "" {
			v.Set("client_secret", tr.ClientSecret)
		}
	}
	r, err := http.NewRequest("POST", requestURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: token request: %v", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if am == AuthorizationHeader && (tr.ClientID != "" || tr.ClientSecret != "") {
		r.SetBasicAuth(url.QueryEscape(tr.ClientID), url.QueryEscape(tr.ClientSecret))
	}
	return r, nil
}

func isReservedRequestField(key string) bool {
	return key == "code" ||
		key == "grant_type" ||
		key == "password" ||
		key == "redirect_uri" ||
		key == "refresh_token" ||
		key == "scope" ||
		key == "username"
}

// Response is an access token response, as described in
// [section 5.1 of RFC 6749].
//
// [section 5.1 of RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749#section-5.1
type Response struct {
	AccessToken  oauth2.AccessToken
	RefreshToken oauth2.RefreshToken
	Scopes       []string

	// Unknown contains any unrecognized fields in the response.
	Unknown map[string]json.RawMessage
}

// ParseJSON parses a JSON access token response.
// The expiry time will be evaluated relative to the time given.
func ParseJSON(b []byte, now time.Time) (*Response, error) {
	var j struct {
		AccessToken  string         `json:"access_token"`
		TokenType    string         `json:"token_type"`
		RefreshToken string         `json:"refresh_token"`
		ExpiresIn    expirationTime `json:"expires_in"` // spec says number, but PayPal (others?) return string
		Scope        string         `json:"scope"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("oauth2: parse token response: %v", err)
	}
	if j.AccessToken == "" {
		return nil, errors.New("oauth2: parse token response: missing access token")
	}
	if j.TokenType == "" {
		return nil, errors.New("oauth2: parse token response: missing token type")
	}
	var expiry time.Time
	if j.ExpiresIn != 0 {
		expiry = now.Round(0).Add(j.ExpiresIn.duration())
	}
	var scopes []string
	if j.Scope != "" {
		scopes = strings.Split(j.Scope, " ")
	}
	var unknown map[string]json.RawMessage
	if err := json.Unmarshal(b, &unknown); err != nil {
		unknown = nil
	} else {
		for f := range knownResponseFields {
			delete(unknown, f)
		}
		if len(unknown) == 0 {
			// No point in keeping around garbage.
			unknown = nil
		}
	}
	return &Response{
		AccessToken: oauth2.AccessToken{
			Type:   j.TokenType,
			Value:  j.AccessToken,
			Expiry: expiry,
		},
		RefreshToken: oauth2.RefreshToken(j.RefreshToken),
		Scopes:       scopes,
		Unknown:      unknown,
	}, nil
}

// expirationTime is an integer number of seconds.
// On the wire, this can be either a JSON number or a string (non-compliant).
type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	*e = expirationTime(i)
	return nil
}

func (e expirationTime) duration() time.Duration {
	return time.Duration(e) * time.Second
}

// ParseForm parses a URL-encoded (RFC 1866, section 8.2.1) access token
// response. The expiry time will be evaluated relative to the time
// passed in. This is not a compliant OAuth 2.0 response.
func ParseForm(b []byte, now time.Time) (*Response, error) {
	vals, err := url.ParseQuery(string(b))
	if err != nil {
		return nil, fmt.Errorf("oauth2: parse token form response: %v", err)
	}
	if vals.Get("access_token") == "" {
		return nil, errors.New("oauth2: parse token form response: missing access token")
	}
	if vals.Get("token_type") == "" {
		return nil, errors.New("oauth2: parse token form response: missing token type")
	}
	var scopes []string
	if s := vals.Get("scope"); s != "" {
		scopes = strings.Split(s, " ")
	}
	var expiry time.Time
	if vals.Get("expires_in") != "" {
		e, err := strconv.Atoi(vals.Get("expires_in"))
		if err != nil {
			return nil, fmt.Errorf("oauth2: parse token form response: invalid expiry (got %q)", vals.Get("expires_in"))
		}
		expiry = now.Round(0).Add(time.Duration(e) * time.Second)
	}
	unknown := make(map[string]json.RawMessage)
	for k, v := range vals {
		switch {
		case len(v) == 0 || isKnownResponseField(k):
			// Skip.
		case len(v) > 1:
			if b, err := json.Marshal(v); err == nil {
				unknown[k] = json.RawMessage(b)
			}
		default:
			if b, err := json.Marshal(v[0]); err == nil {
				unknown[k] = json.RawMessage(b)
			}
		}
	}
	if len(unknown) == 0 {
		unknown = nil
	}
	return &Response{
		AccessToken: oauth2.AccessToken{
			Type:   vals.Get("token_type"),
			Value:  vals.Get("access_token"),
			Expiry: expiry,
		},
		RefreshToken: oauth2.RefreshToken(vals.Get("refresh_token")),
		Scopes:       scopes,
		Unknown:      unknown,
	}, nil
}

// knownResponseFields is a set of fields this package knows to parse.
var knownResponseFields = map[string]struct{}{
	"access_token":  {},
	"token_type":    {},
	"refresh_token": {},
	"expires_in":    {},
	"scope":         {},
}

func isKnownResponseField(k string) bool {
	_, ok := knownResponseFields[k]
	return ok
}
