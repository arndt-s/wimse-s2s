package middlewares

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/yaronf/httpsign"
)

func GetVerifierFunc(a Authority) func(r *http.Request) (sigName string, verifier *httpsign.Verifier) {
	publicKey := a.GetJWTPublicKey()
	return func(r *http.Request) (string, *httpsign.Verifier) {
		header := r.Header.Get(WorkloadTokenHeader)
		if header == "" {
			fmt.Println("missing workload identity token")
			return "", nil
		}

		token, err := jwt.Parse(header, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			return publicKey, nil
		})
		if err != nil {
			fmt.Printf("failed to parse token: %v\n", err)
			return "", nil
		}

		if !token.Valid {
			fmt.Printf("invalid token\n")
			return "", nil
		}

		key, err := extractCnfFromToken(token)
		if err != nil {
			fmt.Printf("failed to extract PoP key: %v\n", err)
			return "", nil
		}

		var rawKey ecdsa.PublicKey
		if err := key.Raw(&rawKey); err != nil {
			fmt.Printf("failed to get raw key: %v\n", err)
			return "", nil
		}

		verifier, err := httpsign.NewP384Verifier(rawKey, httpsign.NewVerifyConfig().SetKeyID("key"), httpsign.Headers("@request-target"))
		if err != nil {
			fmt.Printf("failed to create verifier: %v\n", err)
			return "", nil
		}

		sigName := "sig1"
		return sigName, verifier
	}
}
