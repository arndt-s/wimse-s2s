package middlewares

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt"
)

func printToken(token *jwt.Token) {
	c, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("failed to get claims")
		return
	}

	header, err := json.MarshalIndent(token.Header, "", "  ")
	if err != nil {
		fmt.Println("failed to marshal header")
		return
	}

	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		fmt.Println("failed to marshal claims")
		return
	}

	fmt.Printf("%s.\n%s.[signature]\n", header, body)
}
