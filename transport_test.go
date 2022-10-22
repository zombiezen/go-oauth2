package oauth2

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestTransport(t *testing.T) {
	ts := NewCredentials(AccessToken{
		Type:  "Bearer",
		Value: "xyzzy",
	}, "", nil)
	rt := &fakeRoundTripper{response: &http.Response{
		Status:     "204 No Content",
		StatusCode: http.StatusNoContent,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       ioutil.NopCloser(bytes.NewReader(nil)),
	}}

	req, err := http.NewRequest("GET", "http://www.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTransport(ts, rt).RoundTrip(req); err != nil {
		t.Fatal("RoundTrip error:", err)
	}
	if rt.request == req {
		t.Error("RoundTrip used same *http.Request")
	}
	if got, want := rt.request.Header.Get("Authorization"), "Bearer xyzzy"; got != want {
		t.Errorf("rt.request.Header.Get(\"Authorization\") = %q; want %q", got, want)
	}
}

type fakeRoundTripper struct {
	request  *http.Request
	response *http.Response
}

func (rt *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.request = req
	rt.response.Request = req
	return rt.response, nil
}
