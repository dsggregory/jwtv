package jwtv

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type ValidatorContextKey string

const ClaimsContextKey = "claims"

// GetClaims returns the claims from a validated JWT of an HTTP request which is set during the Middleware handler.
//
// One would call this from handlers that require authorization. For those handlers, if nil is returned from this call, you should respond with a 401 because a JWT was not present in the request. In the case when a JWT is present but does not validate, the Middleware handler would have already responded 401 and your handler would not be called.
//
// When non-nil is returned, it is the responsibility of the caller to inspect and validate the individual claims.
func (jv *JWTValidator) GetClaims(r *http.Request) *Claims {
	claims, ok := r.Context().Value(ValidatorContextKey(ClaimsContextKey)).(*Claims)
	if ok {
		return claims
	}
	return nil
}

// Middleware wraps the HTTP handler 'next' to validate a JWT on the request.
// It validates a JWT from the header and responds with 401 if not valid.
// Otherwise, the claims from the JWT are added to the request context for later handlers to access via GetClaims().
//
// WARN: This DOES NOT validate individual claims as that is the responsibility of the caller after getting results from GetClaims().
func (jv *JWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := jv.Validate(r)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"httpRemoteAddr": r.RemoteAddr,
				"httpMethod":     r.Method,
				"httpURL":        r.URL.String(),
			}).Error("JWT is invalid")
			w.WriteHeader(http.StatusUnauthorized)
		}
		// add the claims to the context so further handlers can access using jv.GetClaims()
		ctx := context.WithValue(r.Context(), ValidatorContextKey(ClaimsContextKey), claims)

		// call the wrapped handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
