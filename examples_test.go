package jwtv

import (
	"net/http"

	"github.com/golang-jwt/jwt"
)

func ExampleNewJWTValidator() {
	var jv *JWTValidator

	// validator will reference the JWT's 'iss' claim to determine the well-known JWKS endpoint to verify signing
	jv, _ = NewJWTValidator()

	// force the JWKS endpoint to claims["iss"] + "/well-known/jwks"
	jv, _ = NewJWTValidator(
		OptionSetJWKSWellKnownURI("/well-known/jwks"),
	)

	// force the JWKS endpoint to the one specified
	jv, _ = NewJWTValidator(
		OptionSetJWKSWellKnownURI("https://login.local/well-known/jwks"),
	)

	_ = jv
}

// ExampleJWTValidator_Middleware provides an example where all routes automatically validate the request's JWT
func ExampleJWTValidator_Middleware() {
	jv, _ := NewJWTValidator()

	mux := http.NewServeMux()

	// wrap this endpoint with a JWT validator middleware
	mux.Handle("/getClients", jv.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// the middleware has successfully verified the JWT's integrity, thus all we do is validate the claims
			claims := jv.GetClaims(r)

			// you must verify the claims
			if !claims.VerifyScope("foo", true) {
				// the claim does not have permission to perform this function
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("scope foo required"))
				return
			}

			if !claims.VerifyAudience("audience-1", true) {
				// the claim is not a member of audience-1 so cannot perform this function
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("aud audience-1 required"))
				return
			}
		},
	)))

	// start the server, do the rest ...
}

// Example_unwrapped provides an example where the HTTP request's JWT is validated inside select routes
func Example_unwrapped() {
	jv, _ := NewJWTValidator()

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// validate the JWT is signed, not expired, et.al.
		claims, err := jv.Validate(r)
		if err != nil {
			// JWT failed verification
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims == nil {
			// no JWT was sent on request
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// you must verify the claims
		if !claims.VerifyScope("foo", true) {
			// the claim does not have permission to perform this function
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("scope foo required"))
			return
		}

		if !claims.VerifyAudience("audience-1", true) {
			// the claim is not a member of audience-1 so cannot perform this function
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("aud audience-1 required"))
			return
		}
	}))

	// start the server, do the rest ...
}

// ExampleClaims_VerifyScope demonstrate that Claims.VerifyScope() can handle differing formats from various JWT issuers.
func ExampleClaims_VerifyScope() {
	// OIDC returns standard claims that include a scope
	claimsScopeSpaceSep := Claims{
		MapClaims: jwt.MapClaims{
			"scope": "one two three",
		},
	}

	if !claimsScopeSpaceSep.VerifyScope("one", true) {
		return
	}

	// OIDC returns a different format
	claimsScopeArray := Claims{
		MapClaims: jwt.MapClaims{
			"scope": []string{"one", "two", "three"},
		},
	}

	// VerifyScope is able to handle the different format of scope
	if !claimsScopeArray.VerifyScope("one", true) {
		return
	}
}
