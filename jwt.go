// Package jwtv provides convenience routines to extract and validate a JWT and add middleware to various web server frameworks.
package jwtv

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/golang-jwt/jwt"
)

const (
	// OIDCWellKnownURI is the OIDC standard URI to discover configuration. To use in Keycloak, prepend the Keycloak HREF `https://{keycloak-addr}/auth/realms/{realm}/protocol`
	OIDCWellKnownURI = "/.well-known/openid-configuration"
	// JWKSWellKnowCertURI default JWKS URI of JWT issuer to get signing public keys. Only use if this is for the IdentityServer4 issuer.
	JWKSWellKnowCertURI = OIDCWellKnownURI + "/jwks"
)

// JWTValidator the instance of the JWT validator
type JWTValidator struct {
	// JwksURI endpoint of JWT issuer to get signing public keys.
	// This may represent:
	//   * a full HREF to the OIDC's well-known endpoint
	//   * or an endpoint URI used in combination with the JWT's `iss` claim HREF
	// When empty at validation time, it will use 'iss' claim to lookup a predefined endpoint.
	JwksURI string
	// PublicKey specifies the public key to be used to verify all JWTs. This being defined supersedes the need to lookup the key from JwksURI.
	PublicKey interface{}
	// OnlineValidation if true, the OIDC server will be asked to validate the token. Otherwise, offline validation is done by checking the token signature against the OIDC server's public key.
	// WARN: if true, this always causes an extra connection to the OIDC server to validate the token.
	OnlineValidation bool
	// OIDCEndpoints if doing discovery against the OIDC server, this will be a map of idpURL to it's discovered endpoints
	OIDCEndpoints map[string]*JWTEndpoints

	ctx context.Context
	// keyFetcher fetch and cache keys from JWKS. Automatically created by default or shared by OptionSetJWKSFetcher.
	keyFetcher *jwk.AutoRefresh
}

const (
	TokenTypeNone = iota
	TokenTypeBearer
	TokenTypeBasicAuth
)
const (
	TokenLocHeader = iota
	TokenLocQuery
	TokenLocCookie
)

// TokenInfo defines how the JWT was found in an HTTP request
type TokenInfo struct {
	// typ one of TokenType...
	typ int
	// loc one of TokenLoc...
	loc int
	// val the value of the token
	val string
}

// parseAccessToken locates the Authorization header or access_token cookie from the request and returns the info
func parseAccessToken(r *http.Request) (typ TokenInfo, err error) {
	queryToken, ok := r.URL.Query()["access_token"]
	if ok && len(queryToken[0]) > 0 {
		return TokenInfo{TokenTypeBearer, TokenLocQuery, queryToken[0]}, nil
	}

	c, err := r.Cookie("access_token")
	if err == nil && len(c.Value) > 0 {
		return TokenInfo{TokenTypeBearer, TokenLocCookie, c.Value}, nil
	}

	authHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authHeader) != 2 {
		if len(authHeader) == 1 && len(authHeader[0]) > 0 {
			// missing authorization header in request
			return TokenInfo{}, errors.New("invalid auth token format")
		}
		return TokenInfo{}, nil
	}

	typ = TokenInfo{loc: TokenLocHeader, val: authHeader[1]}
	switch authHeader[0] {
	case "Bearer":
		typ.typ = TokenTypeBearer
	case "Basic":
		typ.typ = TokenTypeBasicAuth
	}
	return typ, nil
}

// discoverIfNeeded determine JWKS by proxy or call OIDC configuration server to get endpoints
func (jv *JWTValidator) discoverIfNeeded(token *jwt.Token) error {
	/* if opt.introspect (e.g. verify JWT with issuer) - get introspection and JWKS endpoints from discovery.

	 */
	iss, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
	if !ok {
		return errors.New("no issuer present in JWT claims header")
	}

	if err := jv.DiscoverEndpoints(iss); err != nil {
		return err
	}

	return nil
}

// lookupKeyFromIssuer downloads keys from JwksURI for the token claims 'iss' and 'kid'.
//
// WARN: this only supports JWTs issued by a single OIDC server when jv.PublicKey is specified.
func (jv *JWTValidator) lookupKeyFromIssuer(token *jwt.Token) (interface{}, error) {
	if jv.PublicKey != nil {
		return jv.PublicKey, nil
	}

	// look it up from the OIDC issuer via JWKS

	jwksURL := jv.JwksURI

	// if jv.JwksURI is NOT a full URL, then get the issuer HREF from the claims header
	if !strings.HasPrefix(jwksURL, "http") {
		iss, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
		if !ok {
			return nil, errors.New("no issuer present in JWT claims header")
		}
		href, err := matchWellKnownEndpointByIssuer(iss)
		if err != nil {
			jwksURL = iss + jv.JwksURI
		} else {
			jwksURL = href
		}
		jv.JwksURI = href // we don't need to look it up again
	}

	if !jv.keyFetcher.IsRegistered(jwksURL) {
		jv.keyFetcher.Configure(jwksURL)
	}
	set, err := jv.keyFetcher.Fetch(jv.ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w; unable to fetch JWK set from %q", err, jwksURL)
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("no kid present in JWT claims header")
	}

	key, ok := set.LookupKeyID(keyID)
	if !ok {
		return nil, fmt.Errorf("key %q not found from JWKS", keyID)
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, err
	}
	return rawKey, nil
}

// ValidateToken validates a JWT token and returns claims.
//
// See also Validate() to validate a token from an HTTP request.
func (jv *JWTValidator) ValidateToken(token string) (*Claims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, jv.lookupKeyFromIssuer)
	if err != nil {
		return nil, err
	}
	// TODO if jv.OnlineValidationService != nil && jv.OnlineValidationService.
	return NewMapClaims(claims), nil
}

// Validate validates an HTTP request's JWT token.
// The token may come from a cookie named 'access_token', a query param named 'access-token', or from the 'Authorization' header.
// If one exists and can be validated, this returns the claims from the token. If validation fails, this returns an error.
// If no JWT is present in the request, this returns nil for the claims and a nil error.
//
// See also ValidateToken().
func (jv *JWTValidator) Validate(r *http.Request) (*Claims, error) {
	ti, err := parseAccessToken(r)
	if err != nil {
		return nil, err
	}
	if ti.typ != TokenTypeBearer {
		return nil, nil
	}

	return jv.ValidateToken(ti.val)
}

// ParseTokenWithoutValidation parse the JWT token and return the claims. Does not validate the token signature.
//
// See also ParseWithoutValidation() for the same functionality but taking the token from an HTTP request.
func (jv *JWTValidator) ParseTokenWithoutValidation(token string) (*Claims, error) {
	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		return nil, err
	}
	return NewMapClaims(claims), nil
}

// ParseWithoutValidation parses the JWT token from an HTTP request and return the claims. Useful only if upstream has already validated the token.
//
// WARNING: THIS DOES NOT VALIDATE THE TOKEN!
//
// See also ParseTokenWithoutValidation().
func (jv *JWTValidator) ParseWithoutValidation(r *http.Request) (*Claims, error) {
	ti, err := parseAccessToken(r)
	if err != nil {
		return nil, err
	}
	if ti.typ != TokenTypeBearer {
		return nil, nil
	}

	return jv.ParseTokenWithoutValidation(ti.val)
}

// ParseIfAPIGWValidated Use this method to get the claims from the JWT if the request could have been routed through the APIGW. If it did come through APIGW, then don't verify the JWT signature (saving a network call) because APIGW already did that. Otherwise, it validates the JWT signature against the issuing OIDC server (cached).
//
// WARNING: Only use this method if access to your service is locked behind APIGW.
func (jv *JWTValidator) ParseIfAPIGWValidated(r *http.Request) (*Claims, error) {
	apigwValidated := r.Header.Get("X-Auth-Claims_validated")

	if apigwValidated != "" {
		return jv.ParseWithoutValidation(r)
	} else {
		return jv.Validate(r)
	}
}

// ValidatorOption signature for an option to NewJWTValidator
type ValidatorOption func(validator *JWTValidator) error

// TODO this subsumed by discover.go
// OIDCConfiguration from response to IDP's /.well-known/openid-configuration
type OIDCConfiguration struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// OptionDiscoverJWKSCertsURI is a NewJWTValidator Functional Option to call any IDP's OIDC discovery endpoint to look up the JWKS URI.
func OptionDiscoverJWKSCertsURI(idpHREF string) ValidatorOption {
	return func(validator *JWTValidator) error {
		resp, err := http.DefaultClient.Get(idpHREF + OIDCWellKnownURI)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		oBody := resp.Body
		brdr := oBody

		oidcConf := OIDCConfiguration{}
		if err = json.NewDecoder(brdr).Decode(&oidcConf); err != nil {
			return fmt.Errorf("%w; error decoding OIDCConfiguration response", err)
		}

		if oidcConf.JWKSURL == "" {
			return errors.New("could not get JWKS URI from OIDCConfiguration")
		}
		validator.JwksURI = oidcConf.JWKSURL
		return nil
	}
}

// OptionSetJWKSWellKnownURI is a NewJWTValidator Functional Option to set the endpoint URI of the JWT's issuer so that public keys can be acquired to validate a JWT.
// This may specify a full HREF to the OIDC's endpoint. Otherwise, it is expected that this is a URI and will be appended to the JWT claims `iss` (issuer) HREF to form the full URL to acquire JWKS keys from an OIDC server.
//
// The default is JWKSWellKnowCertURI.
//
// Use OptionDiscoverJWKSCertsURI() for the preferred method.
func OptionSetJWKSWellKnownURI(uri string) ValidatorOption {
	return func(validator *JWTValidator) error {
		validator.JwksURI = uri
		return nil
	}
}

// OptionSetJWKSFetcher is a NewJWTValidator Functional Option that sets the shared JWK key fetcher which may be used by other validators. The 'fetcher'
// argument can be acquired from a call to NewSharedFetcher().
//
// The use case for this option began with APIGW whose config could possibly declare the same IDP for different proxy services. Thus, we'd like to share the JWK cache globally.
func OptionSetJWKSFetcher(fetcher *jwk.AutoRefresh) ValidatorOption {
	return func(validator *JWTValidator) error {
		validator.keyFetcher = fetcher
		return nil
	}
}

// OptionSetPublicKey is a NewJWTValidator Functional Option to specify the RSA public key to use to validate JWTs and is only useful when you know the JWT signer uses only one public key.
// The pemOrFile argument may be PEM data or a path to a PEM public key or certificate file.
//
// This supersedes OptionSetJWKSWellKnownURI().
func OptionSetPublicKey(pemOrFile string) ValidatorOption {
	return func(validator *JWTValidator) error {
		var pemData []byte
		if _, err := os.Stat(pemOrFile); err == nil {
			fp, err := os.Open(pemOrFile)
			if err != nil {
				return err
			}
			defer fp.Close()
			pemData, err = io.ReadAll(fp)
			if err != nil {
				return err
			}
		} else {
			pemData = []byte(pemOrFile)
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			return errors.New("unable to decode PEM data for public key")
		}
		switch {
		case strings.Contains(strings.ToUpper(block.Type), "CERTIFICATE"):
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			validator.PublicKey = cert.PublicKey
		default:
			pa, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("%w; expected PUBLIC KEY and got %q", err, block.Type)
			}
			validator.PublicKey = pa
		}

		return nil
	}
}

// OptionEnableOnlineValidation use the issuing OIDC server to validate each token. The only value in setting this is when you cannot tolerate a token that has not yet expired but has been revoked by some other service.
// For instance, on session logout, the token may be revoked by the OIDC server.
//
// With short validity periods on tokens, the risk that a user logs off and someone gains access to their token to use afterwards to call an API service.
func OptionEnableOnlineValidation() ValidatorOption {
	return func(validator *JWTValidator) error {
		validator.OnlineValidation = true
		return nil
	}
}

// NewJWTValidator create an instance of the validator for JWTs from a single issuer (e.g. OIDC).
//
// The reason for the single issuer restriction is that the validator needs to know the JWKS
// endpoint to download keys. The 'iss' claim cannot be relied upon as there is no standard. JWT issuers
// may specify only the base URL of the IDP and not include the JWKS endpoint. Furthermore, there
// is no standard for the path to the JWKS endpoint.
//
// With respect to the above, a JWKS fetcher can be shared by multiple validators when specifying
// OptionSetJWKSFetcher for `opts`.
//
// Other options include OptionSetJWKSFetcher, OptionSetPublicKey
func NewJWTValidator(opts ...ValidatorOption) (*JWTValidator, error) {
	ctx := context.Background()
	jv := JWTValidator{
		//JwksURI: JWKSWellKnowCertURI,
		ctx: ctx,
	}
	// handle any Functional Options
	for _, o := range opts {
		if err := o(&jv); err != nil {
			return nil, err
		}
	}

	if jv.keyFetcher == nil {
		jv.keyFetcher = jwk.NewAutoRefresh(ctx)
	}

	return &jv, nil
}

// NewSharedFetcher a convenience to return a jwk.AutoRefresh key fetcher and can be used with OptionSetJWKSFetcher().
func NewSharedFetcher(ctx context.Context) *jwk.AutoRefresh {
	return jwk.NewAutoRefresh(ctx)
}
