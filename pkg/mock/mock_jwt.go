// Package mock provides a convenient mock of JWT token and JWKS response to use in your tests. The mock does not require a private key and will create one if necessary.
//
// Example:
//
//			require "github.com/dsggregory/jwtv/pkg/mock"
//
//			// a mock JWT token signer
//	     mj, err := mock.NewJWT("")
//			So(err, ShouldBeNil)
//
//			// a mock JWKS service to return our mock signing key
//			jwkts := mj.NewJWKService()
//			defer jwkts.Close()
//
//			// create and sign a token
//			token := mj.SignClaims(jwt.MapClaims{}, time.Now().Add(time.Minute))
//			...
//			// use token in your http request
//			req.Header.Set("Authorization", "Bearer " + token)
package mock

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt"
)

// JWT a mock interface to JWT signing
type JWT struct {
	RsaPrivateKey *rsa.PrivateKey
	RsaPubkey     *rsa.PublicKey
	PrivKeyDer    []byte
	PubKeyDer     []byte

	// Cert X509 certificate (in DER) signed by the private key
	Cert    []byte
	CertPEM string

	n string // rsa public key modulus Base64urlUInt-encoded
	e string // public key exponent Base64urlUInt-encoded
}

// N the RSA modulus
func (m *JWT) N() string {
	return m.n
}

// E the RSA exponent
func (m *JWT) E() string {
	return m.e
}

// NewToken just create a token without signing it into an accessToken. See SignClaims for the latter.
func (m *JWT) NewToken(data jwt.MapClaims, expires time.Time, keyID string) *jwt.Token {
	claims := jwt.MapClaims{}
	claims["exp"] = expires.Unix() // well-known claim
	claims["authorization"] = true

	for i, v := range data {
		claims[i] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["type"] = "at+jwt"

	return token
}

// SignClaims mock a token issuer and return an accessToken suitable for inclusion in a Bearer Authorization header.
func (m *JWT) SignClaims(data jwt.MapClaims, expires time.Time) string {
	token := m.NewToken(data, expires, "1")
	accessToken, err := token.SignedString(m.RsaPrivateKey) // must be same alg as used by jwt.NewWithClaims()
	if err != nil {
		panic("signing mock token: " + err.Error())
	}
	return accessToken
}

// PubString Base64 version of the public key
func (m *JWT) PubString() string {
	return base64.RawStdEncoding.EncodeToString(m.PubKeyDer)
}

// PubPEM returns the PEM version of the Public Key, which could be used for OptionSetPublicKey.
func (m *JWT) PubPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: m.PubKeyDer}))
}

// CertB64 return the test certificate Base64 of DER to be used for example, the 'x5c' JWK response
func (m *JWT) CertB64() (string, error) {
	return base64.RawStdEncoding.EncodeToString(m.Cert), nil
}

// NewJWT creates an instance to mock a JWT to be signed by a known key file or generated key if keyPath is empty
func NewJWT(keyPath string) (*JWT, error) {
	m := JWT{}

	if keyPath == "" {
		privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		m.RsaPrivateKey = privatekey
		publickey := &privatekey.PublicKey
		m.RsaPubkey = publickey
	} else {
		pemData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemData)
		privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		m.RsaPrivateKey = privatekey
		publickey := &privatekey.PublicKey
		m.RsaPubkey = publickey
	}

	var err error
	m.PrivKeyDer = x509.MarshalPKCS1PrivateKey(m.RsaPrivateKey)
	m.PubKeyDer, err = x509.MarshalPKIXPublicKey(m.RsaPubkey)
	if err != nil {
		return nil, err
	}

	m.n, m.e = PubToB64UrlUint(m.RsaPubkey)

	// a X509 certificate to be used for 'x5c' JWK param, et.al.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &m.RsaPrivateKey.PublicKey, m.RsaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	m.Cert = derBytes

	pemd := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.Cert})
	m.CertPEM = string(pemd)

	return &m, nil
}

// Returns the integer in big-endian byte order
func int64ToBytes(s int64) []byte {
	u := uint64(s)
	l := int(unsafe.Sizeof(u))
	b := make([]byte, l)
	for i := 0; i < l; i++ {
		b[i] = byte((u >> uint(8*(l-i-1))) & 0xff)
	}
	return b
}

// Invert int64ToBytes
func bytesToInt64(b []byte) (int64, error) {
	u := uint64(0)
	l := int(unsafe.Sizeof(u))
	if len(b) != l {
		return 0, errors.New("bad length for input")
	}
	for i := 0; i < l; i++ {
		u |= uint64(b[i]) << uint(8*(l-i-1))
	}
	return int64(u), nil
}

// B64UrlUintToPub converts Base64UrlUint-encoded strings to an RSA public key
func B64UrlUintToPub(ns, es string) (*rsa.PublicKey, error) {
	enc := base64.RawURLEncoding
	pk := rsa.PublicKey{}

	buf := make([]byte, 4096)

	// N
	n, err := enc.Decode(buf, []byte(ns))
	if err != nil {
		return nil, err
	}
	pk.N = &big.Int{}
	pk.N.SetBytes(buf[0:n])

	// E
	n, err = enc.Decode(buf, []byte(es))
	if err != nil {
		return nil, err
	}
	pke64, err := bytesToInt64(buf[0:n])
	if err != nil {
		return nil, err
	}
	pk.E = int(pke64)

	return &pk, nil
}

// PubToB64UrlUint converts RSA public key to Base64UrlUint-encoded modulus and exponent strings, for testing
func PubToB64UrlUint(pk *rsa.PublicKey) (encN, encE string) {
	if pk == nil {
		return "", ""
	}

	enc := base64.RawURLEncoding

	N := pk.N
	E := pk.E // int

	bN := N.Bytes()
	bE := int64ToBytes(int64(E))

	lN := enc.EncodedLen(len(bN))
	lE := enc.EncodedLen(len(bE))

	rN := make([]byte, lN)
	rE := make([]byte, lE)

	enc.Encode(rN, bN)
	enc.Encode(rE, bE)

	return string(rN), string(rE)
}
