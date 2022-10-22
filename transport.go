package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// A TokenSource produces OAuth 2.0 access tokens.
// AccessToken must be safe to call concurrently.
type TokenSource interface {
	AccessToken(context.Context) (AccessToken, error)
}

// Transport is an [http.RoundTripper] that adds an Authorization header
// containing OAuth 2.0 access tokens to requests
// before sending them to another [http.RoundTripper].
// A Transport is safe to use from multiple goroutines.
type Transport struct {
	src TokenSource
	rt  http.RoundTripper
}

// NewTransport returns a new [Transport] that sends requests
// authorized by access tokens from src to rt.
func NewTransport(src TokenSource, rt http.RoundTripper) *Transport {
	return &Transport{src, rt}
}

// RoundTrip obtains an access token from its source, adds it to req,
// then sends req to its underlying [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	tok, err := t.src.AccessToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("oauth2 transport: %v", err)
	}
	auth := tok.Authorization()
	if auth == "" {
		if tok.Type == "" {
			return nil, errors.New("oauth2 transport: empty access token type")
		}
		return nil, fmt.Errorf("oauth2 transport: unknown access token type %s", tok.Type)
	}
	// RoundTripper must not modify its argument, so send a copy.
	r2 := new(http.Request)
	*r2 = *req
	r2.Header = make(http.Header, len(req.Header)+1)
	for k, s := range req.Header {
		r2.Header[k] = s
	}
	r2.Header.Set("Authorization", auth)

	res, err := t.rt.RoundTrip(r2)
	// req.Body is assumed to have been closed by the base RoundTripper.
	reqBodyClosed = true
	return res, err
}
