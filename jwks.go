package jwtv

import (
	"fmt"
	"regexp"
)

// WellKnownIssuers struct to define well-known issuers JWKS certs URIs used to form JWKS certs endpoint
type WellKnownIssuer struct {
	// IssRE a regex to match a potential JWT 'iss' claim
	IssRE *regexp.Regexp
	// CertURI the URI to be appended to the JWT 'iss' claim to form the well-known cert endpoint
	CertURI string
}

// wellKnownIssuers well-known issuers JWKS certs URIs used to form JWKS certs endpoint
var wellKnownIssuers = []WellKnownIssuer{
	// order matters WRT the regex
	{
		// KeyCloak
		regexp.MustCompile("/realms/[^/]+"),
		"/protocol/openid-connect/certs",
	},
	{
		// IdentityServer4 issuer contains no good identifiers, thus ".*" and should be last in the list
		regexp.MustCompile(".*"),
		"/.well-known/openid-configuration/jwks",
	},
}

// matchWellKnownEndpointByIssuer using the JWT claims 'iss', attempt to match to wellKnownIssuers and return the full well-known cert HREF
func matchWellKnownEndpointByIssuer(iss string) (string, error) {
	biss := []byte(iss)
	for i := range wellKnownIssuers {
		if wellKnownIssuers[i].IssRE.Match(biss) {
			wkuri := wellKnownIssuers[i].CertURI
			if wkuri[0] != '/' {
				wkuri = "/" + wellKnownIssuers[i].CertURI
			}
			return iss + wkuri, nil
		}
	}
	return "", fmt.Errorf("unable to match %q to a well-known issuer", iss)
}
