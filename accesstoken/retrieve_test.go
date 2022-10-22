package accesstoken

import (
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"zombiezen.com/go/oauth2"
)

func TestHTTPRequest(t *testing.T) {
	tests := []struct {
		name              string
		authMethod        AuthMethod
		request           Request
		wantAuthorization string
		wantFormValues    map[string]string
	}{
		{
			name: "Exchange",
			request: Request{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				AuthCode:     "exchange-code",
				RedirectURL:  "http://www.example.com/",
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
			wantFormValues: map[string]string{
				"grant_type":   "authorization_code",
				"code":         "exchange-code",
				"redirect_uri": "http://www.example.com/",
			},
		},
		{
			name: "Password",
			request: Request{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				Username:     "user1",
				Password:     "password1",
				Scopes:       []string{"scope1", "scope2"},
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
			wantFormValues: map[string]string{
				"grant_type": "password",
				"username":   "user1",
				"password":   "password1",
				"scope":      "scope1 scope2",
			},
		},
		{
			name: "Refresh",
			request: Request{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RefreshToken: "REFRESH_TOKEN",
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
			wantFormValues: map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": "REFRESH_TOKEN",
			},
		},
		{
			name: "ClientCredentials",
			request: Request{
				ClientID:          "CLIENT_ID",
				ClientSecret:      "CLIENT_SECRET",
				Scopes:            []string{"scope1", "scope2"},
				ClientCredentials: true,
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
			wantFormValues: map[string]string{
				"grant_type": "client_credentials",
				"scope":      "scope1 scope2",
			},
		},
		{
			name:       "RequestBodyAuth",
			authMethod: RequestBodyAuth,
			request: Request{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				AuthCode:     "exchange-code",
				RedirectURL:  "http://www.example.com/",
			},
			wantFormValues: map[string]string{
				"client_id":     "CLIENT_ID",
				"client_secret": "CLIENT_SECRET",
				"grant_type":    "authorization_code",
				"code":          "exchange-code",
				"redirect_uri":  "http://www.example.com/",
			},
		},
		{
			name: "ExtraFormValues",
			request: Request{
				ClientID:          "CLIENT_ID",
				ClientSecret:      "CLIENT_SECRET",
				Scopes:            []string{"scope1", "scope2"},
				ClientCredentials: true,
				Form: url.Values{
					"audience": []string{"audience1"},
				},
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
			wantFormValues: map[string]string{
				"grant_type": "client_credentials",
				"scope":      "scope1 scope2",
				"audience":   "audience1",
			},
		},
		{
			name:       "URLUnsafeAuth",
			authMethod: AuthorizationHeader,
			request: Request{
				ClientID:     "CLIENT_ID??",
				ClientSecret: "CLIENT_SECRET??",
				AuthCode:     "exchange-code",
			},
			wantAuthorization: "Basic Q0xJRU5UX0lEJTNGJTNGOkNMSUVOVF9TRUNSRVQlM0YlM0Y=",
			wantFormValues: map[string]string{
				"grant_type": "authorization_code",
				"code":       "exchange-code",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := HTTPRequest("https://www.example.com/token", test.authMethod, &test.request)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := r.URL.String(), "https://www.example.com/token"; got != want {
				t.Errorf("r.URL = %s; want %s", got, want)
			}
			if got := r.Header.Get("Authorization"); got != test.wantAuthorization {
				t.Errorf("r.Header.Get(\"Authorization\") = %q; want %q", got, test.wantAuthorization)
			}
			if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
				t.Errorf("r.Header.Get(\"Content-Type\") = %q; want %q", got, want)
			}
			if body, err := io.ReadAll(r.Body); err != nil {
				t.Errorf("io.ReadAll(r.Body): %v", err)
			} else if q, err := url.ParseQuery(string(body)); err != nil {
				t.Errorf("url.ParseQuery(%q): %v", body, err)
			} else {
				for k, want := range test.wantFormValues {
					if got := q.Get(k); got != want {
						t.Errorf("Body has %s=%s; want %s=%s", k, got, k, want)
					}
				}
			}
		})
	}
}

func TestParse(t *testing.T) {
	refTime := time.Date(2017, time.May, 22, 20, 35, 0, 0, time.UTC)
	tests := []struct {
		name      string
		json      string
		form      string
		want      *Response
		wantError bool
	}{
		{
			name: "Minimal",
			json: `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`,
			form: "access_token=ACCESS_TOKEN&token_type=bearer",
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:  "bearer",
					Value: "ACCESS_TOKEN",
				},
			},
		},
		{
			name: "AllFields",
			json: `{"access_token": "ACCESS_TOKEN", "scope": "scope1 scope2", "token_type": "bearer", "expires_in": 86400, "refresh_token": "REFRESH_TOKEN"}`,
			form: "access_token=ACCESS_TOKEN&scope=scope1+scope2&token_type=bearer&expires_in=86400&refresh_token=REFRESH_TOKEN",
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:   "bearer",
					Value:  "ACCESS_TOKEN",
					Expiry: refTime.Add(86400 * time.Second),
				},
				RefreshToken: "REFRESH_TOKEN",
				Scopes:       []string{"scope1", "scope2"},
			},
		},
		{
			name: "ExpiryPayPal",
			json: `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "expires_in": "86400"}`,
			form: "access_token=ACCESS_TOKEN&token_type=bearer&expires_in=86400",
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:   "bearer",
					Value:  "ACCESS_TOKEN",
					Expiry: refTime.Add(86400 * time.Second),
				},
			},
		},
		{
			name: "ExpiryFacebook",
			json: `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "expires": 86400}`,
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:  "bearer",
					Value: "ACCESS_TOKEN",
				},
				Unknown: map[string]json.RawMessage{
					"expires": json.RawMessage("86400"),
				},
			},
		},
		{
			name: "ExpiresInAndExpires",
			json: `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "expires_in": 86400, "expires": 42}`,
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:   "bearer",
					Value:  "ACCESS_TOKEN",
					Expiry: refTime.Add(86400 * time.Second),
				},
				Unknown: map[string]json.RawMessage{
					"expires": json.RawMessage("42"),
				},
			},
		},
		{
			name:      "ExpiryBool",
			json:      `{"access_token": "ACCESS_TOKEN", "scope": "user", "token_type": "bearer", "expires_in": false}`,
			form:      "access_token=ACCESS_TOKEN&scope=user&token_type=bearer&expires_in=false",
			wantError: true,
		},
		{
			name:      "ExpiryObject",
			json:      `{"access_token": "ACCESS_TOKEN", "scope": "user", "token_type": "bearer", "expires_in": {}}`,
			wantError: true,
		},
		{
			name:      "ExpiryNonNumeric",
			json:      `{"access_token": "ACCESS_TOKEN", "scope": "user", "token_type": "bearer", "expires_in": "abc"}`,
			form:      "access_token=ACCESS_TOKEN&scope=user&token_type=bearer&expires_in=abc",
			wantError: true,
		},
		{
			name:      "MissingAccessToken",
			json:      `{"scope": "user", "token_type": "bearer"}`,
			form:      "scope=user&token_type=bearer",
			wantError: true,
		},
		{
			name:      "WrongAccessTokenType",
			json:      `{"access_token": 123, "scope": "user", "token_type": "bearer"}`,
			wantError: true,
		},
		{
			name: "UnknownFields",
			json: `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "foo": "bar", "baz": "qux"}`,
			form: "access_token=ACCESS_TOKEN&token_type=bearer&foo=bar&baz=qux",
			want: &Response{
				AccessToken: oauth2.AccessToken{
					Type:  "bearer",
					Value: "ACCESS_TOKEN",
				},
				Unknown: map[string]json.RawMessage{
					"foo": json.RawMessage(`"bar"`),
					"baz": json.RawMessage(`"qux"`),
				},
			},
		},
	}

	t.Run("JSON", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				resp, err := ParseJSON([]byte(test.json), refTime)
				if test.wantError {
					if err == nil {
						t.Error("ParseJSON did not return an error")
					}
					if resp != nil {
						t.Error("ParseJSON returned non-nil on error")
					}
					return
				}
				if err != nil {
					t.Fatalf("ParseJSON: %v", err)
				}
				if diff := cmp.Diff(test.want, resp, responseOptions()); diff != "" {
					t.Errorf("-want +got:\n%s", diff)
				}
			})
		}
	})

	t.Run("Form", func(t *testing.T) {
		for _, test := range tests {
			if test.form == "" {
				continue
			}
			t.Run(test.name, func(t *testing.T) {
				resp, err := ParseForm([]byte(test.form), refTime)
				if test.wantError {
					if err == nil {
						t.Error("ParseForm did not return an error")
					}
					if resp != nil {
						t.Error("ParseForm returned non-nil on error")
					}
					return
				}
				if err != nil {
					t.Fatalf("ParseForm: %v", err)
				}
				if diff := cmp.Diff(test.want, resp, responseOptions()); diff != "" {
					t.Errorf("-want +got:\n%s", diff)
				}
			})
		}
	})
}

func TestTokenRequestGrantType(t *testing.T) {
	tests := []struct {
		req       Request
		grantType string
	}{
		{
			Request{},
			"",
		},
		{
			Request{Scopes: []string{"foo", "bar"}},
			"",
		},
		{
			Request{RedirectURL: "http://example.com/"},
			"",
		},
		{
			Request{RefreshToken: "xyzzy"},
			"refresh_token",
		},
		{
			Request{RefreshToken: "xyzzy", Scopes: []string{"foo", "bar"}},
			"refresh_token",
		},
		{
			Request{Username: "abc@example.com"},
			"password",
		},
		{
			Request{Username: "abc@example.com", Scopes: []string{"foo", "bar"}},
			"password",
		},
		{
			Request{Password: "12345"},
			"password",
		},
		{
			Request{Password: "12345", Scopes: []string{"foo", "bar"}},
			"password",
		},
		{
			Request{Username: "abc@example.com", Password: "12345"},
			"password",
		},
		{
			Request{Username: "abc@example.com", Password: "12345", Scopes: []string{"foo", "bar"}},
			"password",
		},
		{
			Request{AuthCode: "123deadbeef"},
			"authorization_code",
		},
		{
			Request{AuthCode: "123deadbeef", RedirectURL: "http://example.com/"},
			"authorization_code",
		},
		{
			Request{ClientID: "me", AuthCode: "123deadbeef", RedirectURL: "http://example.com/"},
			"authorization_code",
		},
		{
			Request{ClientCredentials: true},
			"client_credentials",
		},
		{
			Request{ClientCredentials: true, Scopes: []string{"foo", "bar"}},
			"client_credentials",
		},
	}
	for _, test := range tests {
		if gt := test.req.GrantType(); gt != test.grantType {
			t.Errorf("%+v.GrantType() = %q; want %q", test.req, gt, test.grantType)
		}
	}
}

func responseOptions() cmp.Options {
	responseType := reflect.TypeOf(Response{})
	sortScopes := cmp.FilterPath(
		func(path cmp.Path) bool {
			if path.Index(-2).Type() != responseType {
				return false
			}
			field, ok := path.Last().(cmp.StructField)
			return ok && field.Name() == "Scopes"
		},
		cmpopts.SortSlices(func(s1, s2 string) bool { return s1 < s2 }),
	)
	equateEmpty := cmp.FilterPath(
		func(path cmp.Path) bool {
			for _, step := range path {
				if step.Type() == responseType {
					return true
				}
			}
			return false
		},
		cmpopts.EquateEmpty(),
	)
	return cmp.Options{sortScopes, equateEmpty}
}
