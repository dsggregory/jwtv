package jwtv

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDiscovery(t *testing.T) {
	Convey("Discovery", t, func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"authorization_endpoint": "%s/auth"}`, r.URL.Path)))
		}))
		defer ts.Close()

		eps, err := DiscoverOidcEndpoints(http.DefaultClient, ts.URL+"/auth/realms/demo")
		So(err, ShouldBeNil)
		So(eps, ShouldNotBeNil)
	})

	Convey("Live Discovery", t, func() {
		oidcServer := os.Getenv("OIDC_SERVER")
		if oidcServer == "" {
			t.Skip("Skipping without OIDC_SERVER environment defined")
		}

		eps, err := DiscoverOidcEndpoints(http.DefaultClient, oidcServer)
		So(err, ShouldBeNil)
		So(eps, ShouldNotBeNil)
		So(eps.Issuer, ShouldNotBeEmpty)
		So(eps.TokenEndpoint, ShouldNotBeEmpty)
		So(eps.JwksURI, ShouldNotBeEmpty)
		So(eps.EndSessionEndpoint, ShouldNotBeEmpty)
		So(eps.RevocationEndpoint, ShouldNotBeEmpty)
	})
}
