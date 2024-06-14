package middlewares

import (
	"fmt"
	"net/http"

	"github.com/gorilla/context"

	"github.com/golang-jwt/jwt"
)

type wlAuthMiddleware struct {
	a Authority
}

func NewWorkloadAuthMiddleware(a Authority) *wlAuthMiddleware {
	return &wlAuthMiddleware{
		a: a,
	}
}

func (m *wlAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wlTokenEnc := r.Header.Get(WorkloadTokenHeader)
		if wlTokenEnc == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		wlToken, err := jwt.Parse(wlTokenEnc, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			return m.a.GetJWTPublicKey(), nil
		})
		if err != nil {
			http.Error(w, "failed to parse token", http.StatusUnauthorized)
			return
		}

		if !wlToken.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		fmt.Print("WL token:\n")
		printToken(wlToken)

		context.Set(r, WorkloadTokenContextKey, wlToken)

		next.ServeHTTP(w, r)
	})
}
