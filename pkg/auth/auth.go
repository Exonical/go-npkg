package auth

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/Exonical/go-npkg/pkg/types"
)

// Authenticator handles authentication for registry requests
type Authenticator interface {
	Authenticate(req *http.Request) error
	Type() types.AuthType
}

// NoAuth provides no authentication
type NoAuth struct{}

func (n *NoAuth) Authenticate(req *http.Request) error {
	return nil
}

func (n *NoAuth) Type() types.AuthType {
	return types.AuthTypeNone
}

// BasicAuth provides HTTP Basic authentication
type BasicAuth struct {
	Username string
	Password string
}

func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		Username: username,
		Password: password,
	}
}

func (b *BasicAuth) Authenticate(req *http.Request) error {
	if b.Username == "" {
		return fmt.Errorf("username is required for basic auth")
	}

	credentials := base64.StdEncoding.EncodeToString(
		[]byte(b.Username + ":" + b.Password),
	)
	req.Header.Set("Authorization", "Basic "+credentials)
	return nil
}

func (b *BasicAuth) Type() types.AuthType {
	return types.AuthTypeBasic
}

// TokenAuth provides Bearer token authentication
type TokenAuth struct {
	Token string
}

func NewTokenAuth(token string) *TokenAuth {
	return &TokenAuth{Token: token}
}

func (t *TokenAuth) Authenticate(req *http.Request) error {
	if t.Token == "" {
		return fmt.Errorf("token is required for token auth")
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	return nil
}

func (t *TokenAuth) Type() types.AuthType {
	return types.AuthTypeToken
}

// CertAuth provides certificate-based authentication
type CertAuth struct {
	CertFile string
	KeyFile  string
	cert     *tls.Certificate
}

func NewCertAuth(certFile, keyFile string) (*CertAuth, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return &CertAuth{
		CertFile: certFile,
		KeyFile:  keyFile,
		cert:     &cert,
	}, nil
}

func (c *CertAuth) Authenticate(req *http.Request) error {
	// Certificate auth is handled at the transport level
	return nil
}

func (c *CertAuth) Type() types.AuthType {
	return types.AuthTypeCert
}

func (c *CertAuth) GetCertificate() *tls.Certificate {
	return c.cert
}

// NewAuthenticator creates an authenticator from config
func NewAuthenticator(config types.AuthConfig) (Authenticator, error) {
	switch config.Type {
	case types.AuthTypeNone, "":
		return &NoAuth{}, nil
	case types.AuthTypeBasic:
		return NewBasicAuth(config.Username, config.Password), nil
	case types.AuthTypeToken:
		return NewTokenAuth(config.Token), nil
	case types.AuthTypeCert:
		return NewCertAuth(config.Certificate, config.Key)
	default:
		return nil, fmt.Errorf("unknown auth type: %s", config.Type)
	}
}
