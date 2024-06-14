package client

import (
	"fmt"
	"net/http"
	"net/url"
)

type AuthRoundTripper struct {
	publicKey interface{}
	id        *url.URL
	base      http.RoundTripper
	a         Authority
}

// RoundTrip implements the http.RoundTripper interface.
func (a AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	wlToken, err := a.a.IssueJWTSvid(a.id, a.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to issue JWT SVID: %w", err)
	}

	req.Header.Set("Workload-Identity-Token", wlToken)

	return a.base.RoundTrip(req)
}
