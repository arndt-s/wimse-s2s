package server

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/yaronf/httpsign"
	"ietf.org/wimse/s2s/pkg/server/middlewares"
)

type ProofOfPossession int

const (
	None           ProofOfPossession = 0
	PoPToken       ProofOfPossession = 1
	HttpSignatures ProofOfPossession = 2
)

type Authority interface {
	GetJWTPublicKey() *ecdsa.PublicKey
}

type Config struct {
	PopMode ProofOfPossession
	Address string
}

type Server struct {
	authority Authority
	c         Config
	*http.Server
}

func New(a Authority, c Config) *Server {
	handler := buildHandler(c, a)
	hs := http.Server{
		Addr:    c.Address,
		Handler: handler,
	}

	s := &Server{
		authority: a,
		c:         c,
		Server:    &hs,
	}

	return s
}

func buildHandler(c Config, a Authority) http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/invoke", handleInvoke)

	authMiddleware := middlewares.NewWorkloadAuthMiddleware(a)
	r.Use(authMiddleware.Middleware)

	if c.PopMode == HttpSignatures {
		sigConfig := httpsign.NewHandlerConfig()
		sigConfig.SetFetchVerifier(middlewares.GetVerifierFunc(a))
		return httpsign.WrapHandler(r, *sigConfig)
	} else if c.PopMode == PoPToken {
		wlPopTokenMiddleware := middlewares.NewWlPopTokenMiddleware(a)
		r.Use(wlPopTokenMiddleware.Middleware)
		return r
	} else {
		return r
	}
}

func handleInvoke(w http.ResponseWriter, r *http.Request) {
	fmt.Print("Headers:\n")
	for k, v := range r.Header {
		fmt.Printf("%s: %s\n", k, v)
	}

	w.WriteHeader(http.StatusOK)
}
