package accesstoken_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"zombiezen.com/go/oauth2/accesstoken"
)

// Authorization codes obtained from the "3-legged" authorization flow
// can be exchanged for access tokens.
func Example_exchange() {
	// tokenURL is the OAuth 2.0 provider token endpoint URL.
	const tokenURL = "https://www.example.com/oauth2/token"

	// Send request
	req := &accesstoken.Request{
		ClientID:     "CLIENT_ID",     // obtained from provider website
		ClientSecret: "CLIENT_SECRET", // obtained from provider website

		AuthCode:    "code", // obtained from "code" request parameter in redirect request
		RedirectURL: "https://mysite.example.com/redirect",
	}
	hreq, err := accesstoken.HTTPRequest(tokenURL, accesstoken.AuthorizationHeader, req)
	if err != nil {
		// handle error
	}
	hres, err := http.DefaultClient.Do(hreq)
	if err != nil {
		// handle error
	}
	defer hres.Body.Close()

	// Parse response
	if hres.StatusCode != http.StatusOK {
		// handle error
	}
	body, err := ioutil.ReadAll(io.LimitReader(hres.Body, 1<<20)) // limit to 1MiB
	if err != nil {
		// handle error
	}
	res, err := accesstoken.ParseJSON(body, time.Now())
	if err != nil {
		// handle error
	}

	// Use token from response
	fmt.Println("Got token:", res.AccessToken.Type, res.AccessToken.Value)
}

// Long-lived refresh tokens can be used to produce short-lived access
// tokens.
func Example_refreshToken() {
	// tokenURL is the OAuth 2.0 provider token endpoint URL.
	const tokenURL = "https://www.example.com/oauth2/token"

	// Send request
	req := &accesstoken.Request{
		ClientID:     "CLIENT_ID",     // obtained from provider website
		ClientSecret: "CLIENT_SECRET", // obtained from provider website

		RefreshToken: "REFRESH_TOKEN", // obtained from a previous request
	}
	hreq, err := accesstoken.HTTPRequest(tokenURL, accesstoken.AuthorizationHeader, req)
	if err != nil {
		// handle error
	}
	hres, err := http.DefaultClient.Do(hreq)
	if err != nil {
		// handle error
	}
	defer hres.Body.Close()

	// Parse response
	if hres.StatusCode != http.StatusOK {
		// handle error
	}
	body, err := ioutil.ReadAll(io.LimitReader(hres.Body, 1<<20)) // limit to 1MiB
	if err != nil {
		// handle error
	}
	res, err := accesstoken.ParseJSON(body, time.Now())
	if err != nil {
		// handle error
	}

	// Use token from response
	fmt.Println("Got token:", res.AccessToken.Type, res.AccessToken.Value)
}

// A user name and password can be used to produce short-lived access
// tokens.
//
// This is not a common way to acquire access tokens. From RFC 6749,
// this should only be used "when there is a high degree of trust
// between the resource owner and the client (e.g., the client is part
// of the device operating system or a highly privileged application),
// and when other authorization grant types are not available."
func Example_passwordCredentials() {
	// tokenURL is the OAuth 2.0 provider token endpoint URL.
	const tokenURL = "https://www.example.com/oauth2/token"

	// Send request
	req := &accesstoken.Request{
		ClientID:     "CLIENT_ID",     // obtained from provider website
		ClientSecret: "CLIENT_SECRET", // obtained from provider website

		Username: "username", // obtain from user
		Password: "xyzzy",    // obtain from user
	}
	hreq, err := accesstoken.HTTPRequest(tokenURL, accesstoken.AuthorizationHeader, req)
	if err != nil {
		// handle error
	}
	hres, err := http.DefaultClient.Do(hreq)
	if err != nil {
		// handle error
	}
	defer hres.Body.Close()

	// Parse response
	if hres.StatusCode != http.StatusOK {
		// handle error
	}
	body, err := ioutil.ReadAll(io.LimitReader(hres.Body, 1<<20)) // limit to 1MiB
	if err != nil {
		// handle error
	}
	res, err := accesstoken.ParseJSON(body, time.Now())
	if err != nil {
		// handle error
	}

	// Use token from response
	fmt.Println("Got token:", res.AccessToken.Type, res.AccessToken.Value)
}
