package client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/yaronf/httpsign"
)

type ProofOfPossession int

const (
	None           ProofOfPossession = 0
	PoPToken       ProofOfPossession = 1
	HttpSignatures ProofOfPossession = 2
)

type Authority interface {
	IssueJWTSvid(id *url.URL, publicKey interface{}) (string, error)
	IssueX509Svid(id *url.URL) (*x509.Certificate, *ecdsa.PrivateKey, error)
}

type Config struct {
	SpiffeID *url.URL
	PoPMode  ProofOfPossession
}

type Client struct {
	authority Authority
	x509Svid  *x509.Certificate
	c         Config
	cl        HttpClient
}

// httpsig.Client does not implement http.Client, so we need to define our own interface
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func New(a Authority, c Config) (*Client, error) {
	var client HttpClient

	_, key, err := a.IssueX509Svid(c.SpiffeID)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	authTransport := &AuthRoundTripper{
		id:        c.SpiffeID,
		a:         a,
		base:      http.DefaultTransport,
		publicKey: key.Public(),
	}

	if c.PoPMode == HttpSignatures {

		signer, err := getHttpSigner(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer: %w", err)
		}

		httpClient := *&http.Client{
			Transport: authTransport,
		}
		config := httpsign.NewClientConfig().SetSignatureName("sig1").SetSigner(signer)
		client = httpsign.NewClient(httpClient, config)
	} else if c.PoPMode == PoPToken {
		client = &http.Client{
			Transport: &PopTokenRoundTripper{
				id:         c.SpiffeID,
				a:          a,
				privateKey: key,
				base:       authTransport,
			},
		}
	} else {
		client = &http.Client{
			Transport: authTransport,
		}
	}

	return &Client{
		authority: a,
		c:         c,
		cl:        client,
	}, nil
}

func (c *Client) InvokeServer(addr url.URL) error {
	req, err := http.NewRequest("GET", addr.String()+"/invoke", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.cl.Do(req)
	if err != nil {
		return fmt.Errorf("failed to invoke server: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	fmt.Printf("Server response: %d: %s\n", resp.StatusCode, body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return nil
}

func getHttpSigner(key *ecdsa.PrivateKey) (*httpsign.Signer, error) {
	signer, err := httpsign.NewP384Signer(*key, httpsign.NewSignConfig().SetKeyID("key"), httpsign.Headers("@request-target"))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
}
