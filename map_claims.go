package jwtv

import (
	"crypto/subtle"
	"strings"

	"github.com/golang-jwt/jwt"
)

// Claims embedded jwt.MapClaims with additional functionality. This type supplies all methods available to jwt.MapClaims, however, it cannot be indexed directly.
// The Golang way of extending a type.
type Claims struct {
	// MapClaims the embedded jwt.MapClaims one can access in order to index as a map[string]interface{}
	jwt.MapClaims
}

// Get since you cannot index Claims, you need this to get a key value from the embedded map.
func (m *Claims) Get(key string) interface{} {
	return m.MapClaims[key]
}

// GetString get a key as a string. If the key exists, but is not a string, an empty string is returned.
func (m *Claims) GetString(key string) string {
	v := m.MapClaims[key]
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func findInStrArr(cmp string, arr []string) bool {
	for _, s := range arr {
		if subtle.ConstantTimeCompare([]byte(s), []byte(cmp)) != 0 {
			return true
		}
	}
	return false
}

// VerifyScope Compares the scope claim against cmp.
// If required is false, this method will return true if the value matches or is unset.
//
// This function normalizes the ambiguous return types by various OIDC providers. Ex:
//   - IdentityServer4 presents:
//     "scope": ["cps.app.client", "dng-filter.api.app", "kwscorer.api.app"]
//   - Keycloak presents:
//     "scope": "cps.app.client dng-filter.api.app kwscorer.api.app"
func (m *Claims) VerifyScope(cmp string, required bool) bool {
	sv := m.Get("scope")
	if sv == nil {
		return !required
	}
	switch v := sv.(type) {
	case string:
		// RFC8693 says scope should be space-sep string
		arr := strings.Split(v, " ")
		return findInStrArr(cmp, arr)
	case []string:
		// internal implementations could declare it as an array of strings
		return findInStrArr(cmp, v)
	case []interface{}:
		// Some OIDC providers return it as an array of strings and jwt package marshals it into an array of interface of strings
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return false
			}
			if subtle.ConstantTimeCompare([]byte(vs), []byte(cmp)) != 0 {
				return true
			}
		}
	}

	return false
}

// NewMapClaims creates a subclass-like of jwt.MapClaims having all of its functionality including additions.
// You just can't index on it as a map; You'd need to use Claims.MapClaims directly for that.
func NewMapClaims(claims jwt.MapClaims) *Claims {
	return &Claims{claims}
}
