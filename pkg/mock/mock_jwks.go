package mock

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"time"
)

// JWKey an RSA JWKS struct
type JWKey struct {
	// N RSA public key modulus, Base64urlUInt-encoded
	N string `json:"n"`
	// E RSA public key exponent, Base64urlUInt-encoded
	E string `json:"e"`
	// KID the key ID known to the OIDC server
	KID string `json:"kid"`
	// X5c RawStdEncoding Base64 DER of RSA signing cert chain. Supersedes N and E.
	X5c []string `json:"x5c"`
	// Use should be "sig"
	Use string `json:"use"`
	// Alg signature algorithm (RS256)
	Alg string `json:"alg"`
	// Kty key type (RSA)
	Kty string `json:"kty"`
}

// JWKeys the response from a call to a well-known JWKS endpoint that returns a list of the OIDC's signing certs
type JWKeys struct {
	Keys []JWKey `json:"keys"`
}

// JWKService an instance of a mock JWK service to respond with well-known keys
type JWKService struct {
	// Server a mock JWK server
	Server *httptest.Server
	// FetchCounter number of times it has hit the JWK service for keys
	FetchCounter int
	// KeyResponse the key to respond with in the JWK Set
	KeyResponse JWKey
}

// URL returns URL of the httptest server
func (mjwk *JWKService) URL() string {
	return mjwk.Server.URL
}

// Close closes the httptest server
func (mjwk *JWKService) Close() {
	mjwk.Server.Close()
}

// WriteResponse write the KeyResponse data as a JWK Set in JSON
func (mjwk *JWKService) WriteResponse(w http.ResponseWriter, r *http.Request) {
	mjwk.FetchCounter++
	keys := JWKeys{Keys: []JWKey{mjwk.KeyResponse}}
	data, err := json.Marshal(&keys)
	if err != nil {
		log.Printf("%s; unable to marshal JWK keys in JWKService.WriteResponse", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "application/jwk-set+json")
	w.Header().Set("Expires", time.Now().Add(10*time.Second).Format(http.TimeFormat))
	_, _ = w.Write(data)
}

// NewJWKService creates a new HTTP test server to respond with JWKS well-known keys.
// Remember to call the Close() method on the returned server.
func (m *JWT) NewJWKService() *JWKService {
	mjwk := &JWKService{
		// set default response key(s)
		KeyResponse: JWKey{
			N:   m.n,
			E:   m.e,
			KID: "1",
			X5c: nil,
			Use: "sig",
			Alg: "RS256",
			Kty: "RSA",
		},
	}
	mjwk.Server = httptest.NewServer(http.HandlerFunc(mjwk.WriteResponse))

	return mjwk
}
