package jwtv

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dsggregory/jwtv/pkg/mock"

	"github.com/golang-jwt/jwt"
	. "github.com/smartystreets/goconvey/convey"
)

func TestJWTValidator_Middleware(t *testing.T) {
	Convey("Middleware", t, func() {
		mj, err := mock.NewJWT("")
		So(err, ShouldBeNil)

		// a mock JWKS service to return our mock signing key
		jwkts := mj.NewJWKService()
		defer jwkts.Close()

		jv, err := NewJWTValidator()
		So(err, ShouldBeNil)

		// some route that we want to have authenticated
		testEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := jv.GetClaims(r)
			if claims == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// verify claims from the JWT
			good := claims.Get("good")
			if good == nil {
				// no claims mean no JWT
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// validate some claim
			if !good.(bool) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})
		ts := httptest.NewServer(jv.Middleware(testEndpoint))
		defer ts.Close()

		call := func(claims jwt.MapClaims) (*http.Response, error) {
			req, err := http.NewRequest(http.MethodGet, ts.URL, http.NoBody)
			if claims != nil {
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Authorization", "Bearer "+token)
			}
			return http.DefaultClient.Do(req)
		}
		Convey("validate claims", func() {
			Convey("should succeed with valid claims", func() {
				claims := jwt.MapClaims{
					"iss":  jwkts.URL(),
					"good": true,
				}
				resp, err := call(claims)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			})
			Convey("should fail with bad claims", func() {
				claims := jwt.MapClaims{
					"iss":  jwkts.URL(),
					"good": false,
				}
				resp, err := call(claims)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusForbidden)
			})
			Convey("should fail with no JWT", func() {
				resp, err := call(nil) // no JWT will be sent
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})
		})
	})
}
