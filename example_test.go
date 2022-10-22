package oauth2_test

import (
	"log"
	"net/http"

	"zombiezen.com/go/oauth2"
)

func ExampleTransport() {
	// In a real application, you would obtain your token using a provider package.
	tokenSource := oauth2.NewCredentials(oauth2.AccessToken{
		Type:  "Bearer",
		Value: "magic",
	}, "", nil)

	// Create an HTTP client that uses the token source.
	client := &http.Client{
		Transport: oauth2.NewTransport(tokenSource, http.DefaultTransport),
	}

	// Make an authorized request.
	resp, err := client.Get("https://www.example.com/myapi")
	if err != nil {
		log.Print(err)
		return
	}
	defer resp.Body.Close()
}
