// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package testtls creates throwaway TLS material for tests and for the e2e
// suite: an ECDSA CA, a server certificate for 127.0.0.1, ::1 and localhost,
// and a client certificate, all written as PEM files into a directory.
//
// TEST ONLY. Nothing in a production binary may import it.
//
// Validity uses the real clock (now - 1h to now + 24h). That is deliberate and
// safe: certificate validity is only ever checked by crypto/tls against the same
// real clock, never compared with an injected one, so it cannot produce the
// "passes today, fails tomorrow" class of test failure.
package testtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Bundle holds the paths of the generated files.
type Bundle struct {
	// CA is the CA certificate (server trust anchor for agents, client CA for the server).
	CA string
	// Cert and Key are the server certificate and key.
	Cert, Key string
	// ClientCert and ClientKey are a client certificate signed by CA.
	ClientCert, ClientKey string
}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(cn string) (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		panic(err) // the system random source is gone; nothing sensible can continue
	}
	return n
}

// issue signs a leaf. server=true adds the server usage and the loopback names.
func (a *authority) issue(cn string, server bool) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
		tpl.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

func write(dir, name string, data []byte, mode os.FileMode) (string, error) {
	p := filepath.Join(dir, name)
	return p, os.WriteFile(p, data, mode)
}

// New writes a fresh CA, server certificate and client certificate into dir
// (which must exist). Keys are 0600.
func New(dir string) (Bundle, error) {
	ca, err := newCA("clamfleet test CA")
	if err != nil {
		return Bundle{}, err
	}
	var b Bundle
	if b.CA, err = write(dir, "ca.pem", ca.pem, 0o644); err != nil {
		return b, err
	}
	for _, leaf := range []struct {
		cn         string
		server     bool
		cert, key  *string
		certN, keN string
	}{
		{"clamfleet test server", true, &b.Cert, &b.Key, "server.pem", "server.key"},
		{"clamfleet test agent", false, &b.ClientCert, &b.ClientKey, "client.pem", "client.key"},
	} {
		c, k, err := ca.issue(leaf.cn, leaf.server)
		if err != nil {
			return b, fmt.Errorf("issue %s: %w", leaf.cn, err)
		}
		if *leaf.cert, err = write(dir, leaf.certN, c, 0o644); err != nil {
			return b, err
		}
		if *leaf.key, err = write(dir, leaf.keN, k, 0o600); err != nil {
			return b, err
		}
	}
	return b, nil
}

// Rogue writes a client certificate signed by an unrelated CA (so a server
// that trusts Bundle.CA must reject it) and returns the cert and key paths.
func Rogue(dir string) (cert, key string, err error) {
	ca, err := newCA("rogue CA")
	if err != nil {
		return "", "", err
	}
	c, k, err := ca.issue("rogue agent", false)
	if err != nil {
		return "", "", err
	}
	if cert, err = write(dir, "rogue.pem", c, 0o644); err != nil {
		return "", "", err
	}
	key, err = write(dir, "rogue.key", k, 0o600)
	return cert, key, err
}
