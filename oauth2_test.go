package oauth2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type refresherFunc func(rt RefreshToken) (AccessToken, RefreshToken, error)

func (rf refresherFunc) Refresh(_ context.Context, rt RefreshToken) (AccessToken, RefreshToken, error) {
	return rf(rt)
}

func TestCredentials(t *testing.T) {
	alwaysValidToken := AccessToken{
		Type:  "Bearer",
		Value: "ACCESS_TOKEN",
	}
	staleToken := AccessToken{
		Type:   "Bearer",
		Value:  "ACCESS_TOKEN",
		Expiry: time.Now().Add(-1 * time.Hour),
	}
	tests := []struct {
		name      string
		refresher Refresher
		initial   AccessToken
		refresh   RefreshToken

		wantToken   AccessToken
		wantError   bool
		wantRefresh RefreshToken
	}{
		{
			name:      "valid initial with empty refresh and no refresher",
			initial:   alwaysValidToken,
			wantToken: alwaysValidToken,
		},
		{
			name:        "valid initial with valid refresh and no refresher",
			initial:     alwaysValidToken,
			refresh:     "REFRESH_TOKEN",
			wantToken:   alwaysValidToken,
			wantRefresh: "REFRESH_TOKEN",
		},
		{
			name:      "invalid initial and nil refresher",
			initial:   AccessToken{},
			wantError: true,
		},
		{
			name: "invalid initial and failing refresher",
			refresher: refresherFunc(func(RefreshToken) (AccessToken, RefreshToken, error) {
				return AccessToken{}, "", errors.New("no token")
			}),
			initial:   AccessToken{},
			wantError: true,
		},
		{
			name: "refresh preservation",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				if rt != "REFRESH_TOKEN" {
					return AccessToken{}, "", errors.New("invalid refresh token: " + string(rt))
				}
				return alwaysValidToken, "REFRESH_TOKEN", nil
			}),
			refresh:     "REFRESH_TOKEN",
			wantToken:   alwaysValidToken,
			wantRefresh: "REFRESH_TOKEN",
		},
		{
			name: "refresh replacement",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				if rt != "OLD_REFRESH_TOKEN" {
					return AccessToken{}, "", errors.New("invalid refresh token: " + string(rt))
				}
				return alwaysValidToken, "NEW_REFRESH_TOKEN", nil
			}),
			refresh:     "OLD_REFRESH_TOKEN",
			wantToken:   alwaysValidToken,
			wantRefresh: "NEW_REFRESH_TOKEN",
		},
		{
			name: "refresh preservation on omission",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				if rt != "REFRESH_TOKEN" {
					return AccessToken{}, "", errors.New("invalid refresh token: " + string(rt))
				}
				return alwaysValidToken, "", nil
			}),
			refresh:     "REFRESH_TOKEN",
			wantToken:   alwaysValidToken,
			wantRefresh: "REFRESH_TOKEN",
		},
		{
			name: "refresher returns empty token",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				return AccessToken{}, "REFRESH_TOKEN", nil
			}),
			refresh:     "REFRESH_TOKEN",
			wantError:   true,
			wantRefresh: "REFRESH_TOKEN",
		},
		{
			name: "refresher returns stale token",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				return staleToken, "", nil
			}),
			refresh:     "REFRESH_TOKEN",
			wantError:   true,
			wantRefresh: "REFRESH_TOKEN",
		},
		{
			name: "refresher returns error",
			refresher: refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
				return AccessToken{}, "", errors.New("token revoked")
			}),
			refresh:     "REFRESH_TOKEN",
			wantError:   true,
			wantRefresh: "REFRESH_TOKEN",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tr := NewCredentials(test.initial, test.refresh, test.refresher)
			tk, err := tr.AccessToken(context.Background())
			refresh := tr.RefreshToken()
			switch {
			case err == nil && test.wantError:
				t.Errorf("tr.AccessToken(ctx) = _, <nil>; want error")
			case err != nil && !test.wantError:
				t.Errorf("tr.AccessToken(ctx) = _, %v; want no error", err)
			case err == nil:
				if diff := cmp.Diff(test.wantToken, tk); diff != "" {
					t.Errorf("tr.AccessToken(ctx) (-want +got):\n%s", diff)
				}
			}
			if refresh != test.wantRefresh {
				t.Errorf("tr.RefreshToken() = %q; want %q", refresh, test.wantRefresh)
			}
		})
	}
}

func TestCredentialsCache(t *testing.T) {
	n := 0
	tk := AccessToken{Type: "Bearer", Value: "ACCESS_TOKEN"}
	refresher := refresherFunc(func(rt RefreshToken) (AccessToken, RefreshToken, error) {
		n++
		if rt != "REFRESH_TOKEN" {
			return AccessToken{}, "", errors.New("invalid refresh token: " + string(rt))
		}
		return tk, "", nil
	})
	creds := NewCredentials(AccessToken{}, "REFRESH_TOKEN", refresher)
	tk1, err := creds.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("tr.AccessToken(ctx): %v", err)
	}
	if diff := cmp.Diff(tk, tk1); diff != "" {
		t.Errorf("tr.AccessToken(ctx) (-want +got):\n%s", diff)
	}
	tk2, err := creds.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("tr.AccessToken(ctx): %v", err)
	}
	if diff := cmp.Diff(tk, tk2); diff != "" {
		t.Errorf("tr.AccessToken(ctx) (-want +got):\n%s", diff)
	}
	if n > 1 {
		t.Errorf("TokenRefresher retrieved token %d times", n)
	}
}
