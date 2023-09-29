# JWT Validation Convenience Library
Convenience routines to extract and validate a JWT and add middleware to various web server frameworks.

> go get github.com/dsggregory/jwtv

For reference, JWT validation flow is:
* parse the JWT token from the request's Authorization header, cookie, or query param
* download and cache the signing key from the issuer of the JWT using a JWKS service provided by the OIDC
* verify the JWT signature, expiration, etc.
* present the custom Claims from the JWT to the caller for app-specific validation (is this the correct role, etc.)

## Mocks For Testing
Provides a convenient mock of JWT token and JWKS response to use in your tests. The mock does not require a private key and will create one if necessary. See [mock_jwt.go](./pkg/mock/mock_jwt.go) and example use in [jwt_test.go](./jwt_test.go).

## Usage
To validate a JWT, the following steps are taken:
* create a JWTValidator object with options
* wrap your auth-required endpoints with the validator middleware or,
* call the validator directly in any auth-required endpoints

Furthermore, your code should validate the JWT claims as required by the application.

### Create a JWTValidator
The following _Functional Options_ may be used to tailor the validator:

#### OptionDiscoverJWKSCertsURI
Calls any IDP's OIDC discovery endpoint to look up the JWKS URI. The argument passed to this func is the canonical base for the IDP (e.g. what gets set in the `iss` claim of a JWT). For instance, with Keycloak, one may specify `https://keycloak.local/auth/realms/{realm}` as the argument.
#### OptionSetJWKSWellKnownURI
The recommendation is to instead use `OptionDiscoverJWKSCertsURI()`. This option only needs to be used when the default does not work for the OIDC that issues the JWT, or when a connection is undesirable to discover the JWKS endpoint.

> The default is to infer the issuer from a known list. It will reference the JWT's 'iss' claim to determine the proper JWKS endpoint, and currently handles JWTs issued from IdentityServer4 and KeyCloak.

The argument to this option will either:
* set a URI to use in combination with a JWT claim's `iss` (issuer) claim
* or specify the full URL to the OIDC's JWKS endpoint

```go
// uses this to append to the JWT claims 'iss'
jv, err := NewJWTValidator(OptionSetJWKSWellKnownURI("/well-known/jwks"))
// or, specify the full JWKS certs endpoint
jv, err := NewJWTValidator(OptionSetJWKSWellKnownURI("https://myoidc.local/well-known/jwks"))
```
#### OptionSetJWKSFetcher
Use this option if you will have multiple validators and want to share a global cache of JWKS keys. This option would be rarely used unless you have the situation where for some reason you require multiple validators for the same JWT issuer.

```go
fetcher := NewSharedFetcher()
jv1, err := NewJWTValidator(
    OptionSetJWKSFetcher(fetcher),
    OptionSetJWKSWellKnownURI("/well-known/jwks")
)
jv2, err := NewJWTValidator(
    OptionSetJWKSFetcher(fetcher),
    OptionDiscoverJWKSCertsURI("https://myoidc.local")
)
```
#### OptionSetPublicKey
Use this option when you have access to the public key used in signing JWTs. This keeps the system from having to call out to the OIDC's JWKS URL to acquire the key. It is only valid when you know that the OIDC signs every JWT with only one RSA key and that a key rotation event can be supported existentially.
```go
jv, err := NewJWTValidator(OptionSetPublicKey("./path/to/RSAPublicKey.pem"))
```

When using the PhishLabs APIGW with configuration that resigns the original JWT, you can load the public key in k8s by specifying the following environment variable in your deployment manifest:
```yaml
   spec.template.spec.containers[0].env:
     - name: "CLAIMS_SIGNING_PUBKEY"
     value: "vault:secrets/data/apigw/claims-sign#APIGW_SIGNING_PUBKEY"
```

### Parsing a Token From the Request
Normally, `Validate()` method is used to read the token from the HTTP request, verify its integrity, and provide the claims for your further validation. See the examples below for details.

If you require the claims and __know the token has been validated upstream__, use `ParseWithoutValidation()` to get the claims.

### Working With Claims
Some extra functionality was needed to allow clients to work with JWT claims in light of different OIDC vendor implementations. One glaring example is that of the `scope` claim. IdentityServer4 delivers scope claims as StrOrArray while the RFC states space-separated string which is what Keycloak does. Another is that of the `aud` claim; Not because of vendor differences but due to ambiguity allowed by the relevant RFCs.

The `Validate()` (and GetClaims()) method returns a `Claims` type. This type responds to all methods provided by jwt.MapClaims and includes some helpful methods and fields on its own:
* VerifyScope() - tests that a given scope is referenced in the claim and supports the various format types we expect
* Get() - returns a claim value as an interface{}
* GetString() - returns a claim value if it exists and is a string
* MapClaims - accessor of the jwt.MapClaims representation so you may index on it yourself
* VerifyAudience() - as per jwt.MapClaims.VerifyAudience()

## Examples
### Standard net/http Mux Example
This example uses the provided middleware functions to wrap routes that require auth.
```go
package main

import (
	"log"
	"net/http"
	"github.com/dsggregory/jwtv"
)

// we share this so we only fetch the JWK keys as needed
var jv *jwtv.JWTValidator

func ShowAdminDashboard(w http.ResponseWriter, r *http.Request) {
	// get the claims that are present in the JWT
	claims := jv.GetClaims(r)
	if claims == nil {
		log.Print("expected JWT on request but didn't get one")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	
	if !claims.VerifyScope("dashboard", true) {
		log.Print("dashboard scope not included in token")
		w.WriteHeader(http.StatusForbidden)
		return
    }
	// We have claims that need validating
	user := claims.GetString("user")
	if user == "" {
		log.Print("expected user claim to exist")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// validate user ...
}

func main() {
	// create an instance of the JWT validator
	jv, _ = jwtv.NewJWTValidator()
	
	r := http.NewServeMux()

	// add JWT middleware to wrap our handler that needs auth
	r.Handle("/admin", jv.Middleware(http.HandlerFunc(ShowAdminDashboard)))
	// we don't want auth for this route
	r.HandleFunc("/", ShowIndex)
	// ...    
}

```

### Use Without the Included Middleware
You may use the validator without going through HTTP mux middleware.
```go
package main

import (
	"log"
	"net/http"
	"github.com/dsggregory/jwtv"
)

// we share this so we only fetch the JWK keys as needed
var jv *jwtv.JWTValidator

func someHandler(w http.ResponseWriter, r *http.Request) {
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
		// the claim does not have permission to do this function
		w.WriteHeader(http.StatusForbidden)
		return
	}
	
	// request is fully validated and safe to continue processing. ...
}

func main() {
	// create an instance of the JWT validator
	jv, _ = jwtv.NewJWTValidator()
	
	// rest of your code to setup a web server ...
}
```

### Use Before ALL Routes
Some web frameworks allow you to have a function that is run on the request before any other handlers. Following is an example using the `echo` framework. This approach (as opposed to individually wrapping each handler) means you are required to manually exclude those matching routes that do not require auth. 

```go
package main

import (
	"log"
	"net/http"
	"github.com/dsggregory/jwtv"
	"github.com/labstack/echo/v4"
)

// we share this so we only fetch the JWK keys as needed
var jv *jwtv.JWTValidator

func AuthenticationMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		path := c.Request().URL.Path
		// manually ignore routes not requiring auth
		if strings.HasPrefix(path, "/health") {
			return next(c)
		}

		// validate a JWT on the request if present:
		//   * err indicates an invalid JWT
		//   * claims not nil are claims from the JWT
		//   * nil claims and nil error means no JWT was present in the request
		claims, err := jv.Validate(c.Request())
		
		// remainder is the same procedure as the "Without Middleware" example ...
	}
}
func main() {
	// create an instance of the JWT validator
	jv, _ = jwtv.NewJWTValidator()
	
	e := echo.New()
	// Use AuthenticationMiddleware function
	e.Pre(AuthenticationMiddleware)
	
	// create other routes and start the server ...
}
```

## References
* [JSON Web Token RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)
* [OAuth2 Token Exchange RFC8639](https://datatracker.ietf.org/doc/html/rfc8693)
