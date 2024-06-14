package client

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

const popLifetime = 10 * time.Second

type PopTokenRoundTripper struct {
	privateKey interface{}
	id         *url.URL
	base       http.RoundTripper
	a          Authority
}

// RoundTrip implements the http.RoundTripper interface.
func (a PopTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	popToken, err := a.buildPopToken(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build PoP token: %w", err)
	}

	req.Header.Set("PoP-Token", popToken)

	return a.base.RoundTrip(req)
}

func (a PopTokenRoundTripper) buildPopToken(signingKey interface{}) (string, error) {
	method := jwt.SigningMethodES384
	t := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "wimse-id+pop",
			"alg": method.Alg(),
		},
		Claims: jwt.MapClaims{
			"iss": a.id.String(),
			"sub": a.id.String(),
			"exp": time.Now().Unix() + int64(popLifetime),
			"jti": uuid.New().String(),
		},
		Method: method,
	}

	return t.SignedString(signingKey)
}
