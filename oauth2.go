// Package oauth2 provides a client for making HTTP requests authorized
// with OAuth 2.0 tokens as specified in [RFC 6749].
//
// [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// An AccessToken is a short-lived authentication and authorization token
// for accessing protected resources.
type AccessToken struct {
	// Type is the type of token. If empty, then "Bearer" is assumed.
	Type string

	// Value is the access token.
	Value string

	// Expiry is the token's expiration time
	// or zero if the token does not expire.
	Expiry time.Time
}

// Authorization returns the access token
// in the form of an HTTP Authorization header
// or "" if an unknown token type is encountered.
func (t AccessToken) Authorization() string {
	switch {
	case t.Type == "" || strings.EqualFold(t.Type, "bearer"):
		return "Bearer " + t.Value
	case strings.EqualFold(t.Type, "mac"):
		return "MAC " + t.Value
	case strings.EqualFold(t.Type, "basic"):
		return "Basic " + t.Value
	default:
		return ""
	}
}

// A RefreshToken is a long-lived token that is used to obtain access tokens.
// Refresh tokens are not used for accessing resources.
type RefreshToken string

// Credentials is a [TokenSource]
// that can optionally refresh its access tokens.
// Credentials is safe for concurrent use by multiple goroutines.
type Credentials struct {
	refresher Refresher

	mu         sync.Mutex
	refreshing chan struct{} // non-nil if a refresh request is ongoing, closed when finished.
	curr       AccessToken
	refresh    RefreshToken
}

// NewCredentials creates new [Credentials].
// If the refresh token is empty or refresher is nil,
// then the credentials will return errors once the initial token expires.
// If the initial access token is invalid,
// then a new token will be obtained based on the refresh token
// on the first call to [Credentials.Token].
func NewCredentials(initial AccessToken, refresh RefreshToken, refresher Refresher) *Credentials {
	return &Credentials{
		refresher: refresher,
		curr:      initial,
		refresh:   refresh,
	}
}

// AccessToken returns the last valid token or obtains a new token
// from the configured [Refresher].
func (creds *Credentials) AccessToken(ctx context.Context) (AccessToken, error) {
	// Wait for any ongoing refresh to finish.
	creds.mu.Lock()
	for creds.refreshing != nil {
		r := creds.refreshing
		creds.mu.Unlock()
		select {
		case <-r:
		case <-ctx.Done():
			return AccessToken{}, ctx.Err()
		}
		creds.mu.Lock()
	}

	// Typical case: we have a valid access token.
	hasRefresh := creds.refresh != "" && creds.refresher != nil
	if creds.curr.Value != "" && !expired(creds.curr, hasRefresh) {
		t := creds.curr
		creds.mu.Unlock()
		return t, nil
	}

	// No token available, must refresh.
	if !hasRefresh {
		creds.mu.Unlock()
		return AccessToken{}, errors.New("oauth2: invalid token and no refresh token available")
	}
	creds.refreshing = make(chan struct{})
	creds.mu.Unlock()
	next, nextRefresh, err := creds.refresher.Refresh(ctx, creds.refresh)
	creds.mu.Lock()
	defer creds.mu.Unlock()
	close(creds.refreshing)
	creds.refreshing = nil

	if err != nil {
		return AccessToken{}, fmt.Errorf("oauth2: refresh token: %v", err)
	}
	if next.Value == "" {
		return AccessToken{}, errors.New("oauth2: refresh token: empty acess token")
	}
	if expired(next, false) {
		return AccessToken{}, errors.New("oauth2: refresh token: received stale token")
	}
	creds.curr = next
	if nextRefresh != "" {
		creds.refresh = nextRefresh
	}
	return next, nil
}

func expired(t AccessToken, hasRefresh bool) bool {
	if t.Expiry.IsZero() {
		return false
	}
	if hasRefresh {
		// Report expired slightly before actual time
		// to avoid late expirations due to client-server time mismatches.
		return time.Now().After(t.Expiry.Round(0).Add(-10 * time.Second))
	}
	return !time.Now().Before(t.Expiry)
}

// RefreshToken returns the latest refresh token.
// This can be used to persist credentials across runs of a program.
func (creds *Credentials) RefreshToken() RefreshToken {
	creds.mu.Lock()
	rt := creds.refresh
	creds.mu.Unlock()
	return rt
}

// Refresher is the interface that contains the Refresh method.
//
// Refresh requests a new access token given a non-empty refresh token.
// If Refresh returns a non-empty refresh token,
// then it should be used for subsequent calls to Refresh.
type Refresher interface {
	Refresh(ctx context.Context, rt RefreshToken) (AccessToken, RefreshToken, error)
}
