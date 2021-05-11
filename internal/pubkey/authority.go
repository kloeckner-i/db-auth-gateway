package pubkey

/*
 * Copyright 2021 kloeckner.i GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const minSerialNumber = 2

var errDecodePublicKey = errors.New("unable to decode supplied public key")

// Authority is a local certificate authority used by the mock service that is part of the db-auth-gateway tests.
type Authority struct {
	mu        sync.Mutex
	caKey     *rsa.PrivateKey
	caCert    *x509.Certificate
	caCertPEM string

	serialNumber int64
	issuedCerts  []string
	revokedCerts map[string]bool
}

// NewAuthority constructs a new self signed certificate authority.
func NewAuthority(subject pkix.Name, ttl time.Duration) (*Authority, error) {
	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ttl),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	caCertPEM := new(bytes.Buffer)

	if err := pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	}); err != nil {
		return nil, err
	}

	return &Authority{
		caKey:        caKey,
		caCert:       caCert,
		caCertPEM:    caCertPEM.String(),
		serialNumber: minSerialNumber,
		revokedCerts: make(map[string]bool),
	}, nil
}

// CertPEM returns the PEM encoded certificate authority certificate.
func (a *Authority) CertPEM() string {
	return a.caCertPEM
}

// Sign creates a signed certificate from the supplied public key.
func (a *Authority) Sign(pubKeyPEM string, subject pkix.Name, ttl time.Duration) (string, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(a.serialNumber),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(ttl),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	pubKeyDER, _ := pem.Decode([]byte(pubKeyPEM))
	if pubKeyDER == nil {
		return "", errDecodePublicKey
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDER.Bytes)
	if err != nil {
		return "", err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, a.caCert, pubKey, a.caKey)
	if err != nil {
		return "", err
	}

	a.serialNumber++

	certPEM := new(bytes.Buffer)

	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return "", err
	}

	issuedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	a.issuedCerts = append(a.issuedCerts, Fingerprint(issuedCert))
	a.mu.Unlock()

	return certPEM.String(), nil
}

// RevokeAll revokes all currently issued client certificates.
func (a *Authority) RevokeAll() {
	log.Info("Revoking all client certificates")

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, fingerprint := range a.issuedCerts {
		a.revokedCerts[fingerprint] = true
	}
}

// IsRevoked is used to check if a client certificate has been revoked.
func (a *Authority) IsRevoked(cert *x509.Certificate) bool {
	return a.revokedCerts[Fingerprint(cert)]
}
