package jwtv

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLookupWellKnown(t *testing.T) {
	Convey("Should match IdentityServer4 issuer", t, func() {
		href, err := matchWellKnownEndpointByIssuer("http://any.local")
		So(err, ShouldBeNil)
		So(href, ShouldContainSubstring, wellKnownIssuers[1].CertURI)
	})

	Convey("Should match KeyCloak issuer", t, func() {
		href, err := matchWellKnownEndpointByIssuer("http://any.local/realms/master")
		So(err, ShouldBeNil)
		So(href, ShouldContainSubstring, wellKnownIssuers[0].CertURI)
	})
}
