package main

import (
	"context"
	"net/url"

	"ietf.org/wimse/s2s/pkg/authority"
	"ietf.org/wimse/s2s/pkg/client"
	"ietf.org/wimse/s2s/pkg/server"
)

func main() {
	clientMode := client.HttpSignatures
	serverMode := server.HttpSignatures

	domain := url.URL{Scheme: "wimse", Host: "example.org"}
	authority, err := authority.NewAuthority(domain)
	if err != nil {
		panic(err)
	}

	address := url.URL{Scheme: "http", Host: "localhost:8080"}
	server := server.New(authority, server.Config{
		PopMode: serverMode,
		Address: address.Host,
	})

	clientID := url.URL{Scheme: domain.Scheme, Host: domain.Host, Path: "/client"}
	client, err := client.New(authority, client.Config{
		SpiffeID: &clientID,
		PoPMode:  clientMode,
	})
	if err != nil {
		panic(err)
	}

	go func() {
		server.ListenAndServe()
	}()
	defer server.Shutdown(context.TODO())

	err = client.InvokeServer(address)
	if err != nil {
		panic(err)
	}
}
