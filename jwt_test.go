package jwtv

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dsggregory/jwtv/pkg/mock"

	"github.com/golang-jwt/jwt"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewJWTValidator(t *testing.T) {
	Convey("Full validation", t, func() {
		mj, err := mock.NewJWT("")
		So(err, ShouldBeNil)

		// a mock JWKS service to return our mock signing key
		jwkts := mj.NewJWKService()
		defer jwkts.Close()

		Convey("Claims", func() {
			newTestValidator := func(claims jwt.MapClaims) (*Claims, error) {
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Authorization", "Bearer "+token)

				jv, err := NewJWTValidator()
				if err != nil {
					return nil, err
				}
				return jv.Validate(req)
			}
			Convey("How does VerifyAudience work with required arg", func() {
				claims, err := newTestValidator(jwt.MapClaims{
					"iss": jwkts.URL(),
					"aud": []string{"pig", "chick", "goat"}, // RFC7519 says strOrArray
				})
				So(err, ShouldBeNil)
				So(claims.VerifyAudience("pig", true), ShouldBeTrue)
				So(claims.VerifyAudience("chick", false), ShouldBeTrue)
				So(claims.VerifyAudience("dog", true), ShouldBeFalse)
				So(claims.VerifyAudience("dog", false), ShouldBeFalse)

				claims, err = newTestValidator(jwt.MapClaims{
					"iss": jwkts.URL(),
				})
				So(err, ShouldBeNil)
				So(claims.VerifyAudience("pig", true), ShouldBeFalse)
				So(claims.VerifyAudience("pig", false), ShouldBeTrue) // no aud at all
			})
			Convey("How does VerifyScope work with required arg", func() {
				claims, err := newTestValidator(jwt.MapClaims{
					"iss":   jwkts.URL(),
					"scope": "one two three", // RFC8693 says space-sep string
				})
				So(err, ShouldBeNil)
				So(claims.VerifyScope("one", true), ShouldBeTrue)
				So(claims.VerifyScope("two", false), ShouldBeTrue)
				So(claims.VerifyScope("four", true), ShouldBeFalse)
				So(claims.VerifyScope("four", false), ShouldBeFalse)

				claims, err = newTestValidator(jwt.MapClaims{
					"iss": jwkts.URL(),
				})
				So(err, ShouldBeNil)
				So(claims.VerifyScope("one", true), ShouldBeFalse)
				So(claims.VerifyScope("one", false), ShouldBeTrue) // no scope at all
			})
			Convey("Special claims", func() {
				claims, err := newTestValidator(jwt.MapClaims{
					"iss":   jwkts.URL(),
					"scope": "one two three",                  // RFC8693 says space-sep string
					"aud":   []string{"pig", "chick", "goat"}, // RFC7519 says strOrArray
				})
				So(err, ShouldBeNil)
				So(claims.VerifyScope("one", true), ShouldBeTrue)
				So(claims.VerifyAudience("pig", true), ShouldBeTrue)
			})
			Convey("Empty scope claims", func() {
				claims, err := newTestValidator(jwt.MapClaims{"iss": jwkts.URL()})
				So(err, ShouldBeNil)
				So(claims.Get("scope"), ShouldBeNil)
			})
			Convey("Array scope claims", func() {
				claims, err := newTestValidator(jwt.MapClaims{
					"iss":   jwkts.URL(),
					"scope": []string{"one", "two", "three"},
				})
				So(err, ShouldBeNil)
				scope := claims.Get("scope")
				So(scope, ShouldNotBeNil)
				So(len(scope.([]interface{})), ShouldEqual, 3)
				So(claims.VerifyScope("two", true), ShouldBeTrue)
				So(claims.VerifyScope("four", true), ShouldBeFalse)
			})
			Convey("Get claims", func() {
				inclaims := jwt.MapClaims{
					"iss": jwkts.URL(),
					"foo": "bar",
				}
				claims, err := newTestValidator(inclaims)
				So(err, ShouldBeNil)
				iss := claims.GetString("iss")
				So(iss, ShouldEqual, inclaims["iss"])
				foo := claims.MapClaims["foo"].(string) // use the map
				So(foo, ShouldEqual, inclaims["foo"])
			})
		})
		Convey("New validator", func() {
			Convey("default JWKS URI", func() {
				claims := jwt.MapClaims{
					"iss": jwkts.URL(),
				}
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+token)

				jv, err := NewJWTValidator()
				So(err, ShouldBeNil)
				clr, err := jv.Validate(req)
				So(err, ShouldBeNil)
				So(clr.Get("iss"), ShouldEqual, claims["iss"])
				So(jwkts.FetchCounter, ShouldEqual, 1)

				// test that the next time uses the keyCache
				clr, err = jv.Validate(req)
				So(err, ShouldBeNil)
				So(jwkts.FetchCounter, ShouldEqual, 1) // used keyCache
			})
			Convey("specify JWKS URI", func() {
				claims := jwt.MapClaims{
					// "iss": jwkts.URL(),	no issuer to be sure test uses the option
				}
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+token)

				jv, err := NewJWTValidator(OptionSetJWKSWellKnownURI(jwkts.URL()))
				So(err, ShouldBeNil)
				clr, err := jv.Validate(req)
				So(err, ShouldBeNil)
				So(clr, ShouldNotBeNil)
			})
			Convey("bad JWKS", func() {
				claims := jwt.MapClaims{}
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+token)

				jv, err := NewJWTValidator(OptionSetJWKSWellKnownURI("https://0.0.0.0/jks"))
				So(err, ShouldBeNil)
				clr, err := jv.Validate(req)
				So(err, ShouldNotBeNil)
				So(clr, ShouldBeNil)
			})
			Convey("specify the RSA public key", func() {
				claims := jwt.MapClaims{}
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+token)

				Convey("from public key PEM", func() {
					jv, err := NewJWTValidator(OptionSetPublicKey(mj.PubPEM()))
					So(err, ShouldBeNil)
					clr, err := jv.Validate(req)
					So(err, ShouldBeNil)
					So(clr, ShouldNotBeNil)
				})
				Convey("from certificate PEM", func() {
					jv, err := NewJWTValidator(OptionSetPublicKey(mj.CertPEM))
					So(err, ShouldBeNil)
					clr, err := jv.Validate(req)
					So(err, ShouldBeNil)
					So(clr, ShouldNotBeNil)
				})
				Convey("from file", func() {
					fp, err := os.CreateTemp("/tmp", "pem")
					So(err, ShouldBeNil)
					defer func() {
						_ = fp.Close()
						_ = os.Remove(fp.Name())
					}()
					_, err = fp.WriteString(mj.CertPEM)
					So(err, ShouldBeNil)
					_ = fp.Close()
					jv, err := NewJWTValidator(OptionSetPublicKey(fp.Name()))
					So(err, ShouldBeNil)
					clr, err := jv.Validate(req)
					So(err, ShouldBeNil)
					So(clr, ShouldNotBeNil)
				})
			})
			Convey("bad public key", func() {
				claims := jwt.MapClaims{}
				token := mj.SignClaims(claims, time.Now().Add(time.Minute))

				req, err := http.NewRequest(http.MethodGet, "http://domain.com", http.NoBody)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+token)

				// malformed pem file or data
				jv, err := NewJWTValidator(OptionSetPublicKey("bad pem data"))
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "unable to decode PEM")
				So(jv, ShouldBeNil)

				// wrong public key
				badKey, err := rsa.GenerateKey(rand.Reader, 2048) // not the key used to sign JWT
				So(err, ShouldBeNil)
				So(err, ShouldBeNil)
				badPubDer, err := x509.MarshalPKIXPublicKey(&badKey.PublicKey)
				So(err, ShouldBeNil)
				badPubPem := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PUBLIC KEY",
					Bytes: badPubDer,
				})
				jv, err = NewJWTValidator(OptionSetPublicKey(string(badPubPem)))
				clr, err := jv.Validate(req)
				So(err, ShouldNotBeNil)
				So(clr, ShouldBeNil)
			})
		})
	})
}

func TestJWK(t *testing.T) {
	Convey("JWK Lookup keys", t, func() {
		mj, err := mock.NewJWT("")
		So(err, ShouldBeNil)

		// a mock JWKS service to return our mock signing key
		jwkts := mj.NewJWKService()
		defer jwkts.Close()

		Convey("nil issuer in token", func() {
			claims := jwt.MapClaims{}
			jv, err := NewJWTValidator()
			So(err, ShouldBeNil)

			token := mj.NewToken(claims, time.Now().Add(time.Minute), "1")
			_, err = jv.lookupKeyFromIssuer(token)
			So(err, ShouldNotBeNil)
		})
		Convey("should use cache", func() {
			claims := jwt.MapClaims{
				"iss": jwkts.URL(),
			}
			jv, err := NewJWTValidator()
			So(err, ShouldBeNil)

			token := mj.NewToken(claims, time.Now().Add(time.Minute), "1")
			pubKey, err := jv.lookupKeyFromIssuer(token)
			So(err, ShouldBeNil)
			So(pubKey, ShouldNotBeNil)
			So(jwkts.FetchCounter, ShouldEqual, 1)

			// uses cache on next lookup
			pubKey, err = jv.lookupKeyFromIssuer(token)
			So(err, ShouldBeNil)
			So(pubKey, ShouldNotBeNil)
			So(jwkts.FetchCounter, ShouldEqual, 1)
		})

		Convey("should use shared key fetcher", func() {
			fetcher := NewSharedFetcher(context.Background())
			claims := jwt.MapClaims{
				"iss": jwkts.URL(),
			}
			jv1, err := NewJWTValidator(OptionSetJWKSFetcher(fetcher))
			So(err, ShouldBeNil)

			jv2, err := NewJWTValidator(OptionSetJWKSFetcher(fetcher))
			So(err, ShouldBeNil)

			So(jv1.keyFetcher, ShouldEqual, jv2.keyFetcher)

			token := mj.NewToken(claims, time.Now().Add(time.Minute), "1")
			pubKey, err := jv1.lookupKeyFromIssuer(token)
			So(err, ShouldBeNil)
			So(pubKey, ShouldNotBeNil)
			So(jwkts.FetchCounter, ShouldEqual, 1)

			// uses shared fetcher on next lookup
			pubKey, err = jv2.lookupKeyFromIssuer(token)
			So(err, ShouldBeNil)
			So(pubKey, ShouldNotBeNil)
			So(jwkts.FetchCounter, ShouldEqual, 1)
		})
		Convey("should not continue to fetch unknown keyid", func() {
			fetchCount := jwkts.FetchCounter

			claims := jwt.MapClaims{
				"iss": jwkts.URL(),
			}
			jv, err := NewJWTValidator()
			So(err, ShouldBeNil)
			token := mj.NewToken(claims, time.Now().Add(time.Minute), "2") // not in cache nor JWKS
			pubKey, err := jv.lookupKeyFromIssuer(token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "not found")
			So(pubKey, ShouldBeNil)
			fetchCount++
			So(jwkts.FetchCounter, ShouldEqual, fetchCount)

			// this should return a negative cache hit and not fetch
			pubKey, err = jv.lookupKeyFromIssuer(token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "not found")
			So(pubKey, ShouldBeNil)
			So(jwkts.FetchCounter, ShouldEqual, fetchCount)
		})
	})

	Convey("Discover keys", t, func() {
		mj, err := mock.NewJWT("")
		So(err, ShouldBeNil)

		// a mock JWKS service to return our mock signing key
		jwkts := mj.NewJWKService()
		defer jwkts.Close()

		Convey("from Keycloak", func() {
			// a fake IDP OIDC discovery service
			const oidcBasePath = "/auth/realms/demo/protocol"
			oidcSvr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if strings.HasPrefix(req.URL.Path, oidcBasePath) {
					// keycloak presents this URI for the JWKS endpoint
					oc := OIDCConfiguration{JWKSURL: jwkts.URL() + oidcBasePath + "/openid-connect/certs"}
					_ = json.NewEncoder(w).Encode(&oc)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer oidcSvr.Close()

			claims := jwt.MapClaims{
				"iss": jwkts.URL(),
			}
			// for Keycloak, you need to include the path that contains the realm of interest
			jv, err := NewJWTValidator(OptionDiscoverJWKSCertsURI(oidcSvr.URL + oidcBasePath))
			So(err, ShouldBeNil)

			token := mj.NewToken(claims, time.Now().Add(time.Minute), "1")
			pubKey, err := jv.lookupKeyFromIssuer(token)
			So(err, ShouldBeNil)
			So(pubKey, ShouldNotBeNil)
			So(jwkts.FetchCounter, ShouldEqual, 1)
		})
	})
}
