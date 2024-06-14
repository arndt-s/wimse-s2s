package middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/context"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/golang-jwt/jwt"
)

type wlPopTokenMiddleware struct {
	a Authority
}

func NewWlPopTokenMiddleware(a Authority) *wlPopTokenMiddleware {
	return &wlPopTokenMiddleware{
		a: a,
	}
}

func (m *wlPopTokenMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authData := context.Get(r, WorkloadTokenContextKey)
		if authData == nil {
			http.Error(w, "missing workload identity token", http.StatusUnauthorized)
			return
		}

		popTokenEnc := r.Header.Get(PoPTokenHeader)
		if popTokenEnc == "" {
			http.Error(w, "missing PoP token", http.StatusUnauthorized)
			return
		}

		wlToken, ok := authData.(*jwt.Token)
		if !ok {
			http.Error(w, "invalid workload identity token", http.StatusUnauthorized)
			return
		}

		key, err := extractCnfFromToken(wlToken)
		if err != nil {
			fmt.Printf("failed to extract PoP key: %v\n", err)
			http.Error(w, "failed to extract PoP key", http.StatusUnauthorized)
			return
		}

		popToken, err := jwt.Parse(popTokenEnc, func(t *jwt.Token) (interface{}, error) {
			// Note: What about signature check?

			var raw interface{}
			err := key.Raw(&raw)
			if err != nil {
				return nil, fmt.Errorf("failed to get raw key: %w", err)
			}

			return raw, nil
		})
		if err != nil {
			fmt.Printf("failed to parse PoP token: %v\n", err)
			http.Error(w, "failed to parse PoP token", http.StatusUnauthorized)
			return
		}

		if !popToken.Valid {
			http.Error(w, "invalid PoP token", http.StatusUnauthorized)
			return
		}

		fmt.Print("PoP token:\n")
		printToken(popToken)

		next.ServeHTTP(w, r)
	})
}

func extractCnfFromToken(token *jwt.Token) (jwk.Key, error) {
	c, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract cnf claim")
	}

	cnf, ok := c["cnf"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf claim is missing")
	}

	raw, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jwk claim is missing")
	}

	// jwk library only allows JSON as an input unfortunately
	jwkClaim, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwk: %w", err)
	}

	key, err := jwk.ParseKey(jwkClaim)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}

	return key, nil
}
