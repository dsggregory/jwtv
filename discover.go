package jwtv

import (
	"encoding/json"
	"net/http"
	"time"
)

type Discoverer struct {
	// data map of idpURL to it's discovered endpoints
	data map[string]*JWTEndpoints
}

type JWTEndpoints struct {
	Issuer                string
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"` // https://datatracker.ietf.org/doc/html/rfc7662
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"` // https://datatracker.ietf.org/doc/html/rfc7009
}

// DiscoverOidcEndpoints calls the OIDC server's endpoint to discover all other endpoints provided by the server
func DiscoverOidcEndpoints(hclient *http.Client, oidcBaseURL string) (*JWTEndpoints, error) {
	resp, err := hclient.Get(oidcBaseURL + OIDCWellKnownURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	eps := JWTEndpoints{}
	err = json.NewDecoder(resp.Body).Decode(&eps)
	if err != nil {
		return nil, err
	}
	return &eps, nil
}

func (jv *JWTValidator) DiscoverEndpoints(oidcBaseURL string) error {
	if jv.OIDCEndpoints == nil {
		jv.OIDCEndpoints = make(map[string]*JWTEndpoints)
	} else if _, ok := jv.OIDCEndpoints[oidcBaseURL]; ok {
		return nil
	}
	eps, err := DiscoverOidcEndpoints(&http.Client{Timeout: 10 * time.Second}, oidcBaseURL)
	if err != nil {
		return err
	}
	jv.OIDCEndpoints[oidcBaseURL] = eps

	return nil
}
