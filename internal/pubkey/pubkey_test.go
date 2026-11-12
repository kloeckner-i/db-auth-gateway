package pubkey_test

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/kloeckner-i/db-auth-gateway/internal/pubkey"
	"github.com/stretchr/testify/assert"
)

// generateTestCerts creates a fresh CA and a server certificate signed by it, both PEM encoded.
// Generating them at test time avoids static fixtures that expire.
func generateTestCerts(t *testing.T) (caPEM, serverPEM string) {
	t.Helper()

	now := time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Conduit Test CA", Organization: []string{"DevOps"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "my-project:my-database", Organization: []string{"DevOps"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	encode := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	return encode(caDER), encode(serverDER)
}

func TestServerCertificateValidator(t *testing.T) {
	caCertPEM, serverCertPEM := generateTestCerts(t)

	caCert, err := pubkey.ParseCertificate(caCertPEM)
	if err != nil {
		t.Fatal(err)
	}

	encodedCert, _ := pem.Decode([]byte(serverCertPEM))
	if encodedCert == nil {
		t.Fatal("unable to decode certificate")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	validator := pubkey.NewServerCertificateValidator(rootCAs, "my-project:my-region:my-database")

	err = validator([][]byte{encodedCert.Bytes}, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseCertificate(t *testing.T) {
	_, serverCertPEM := generateTestCerts(t)

	cert, err := pubkey.ParseCertificate(serverCertPEM)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "my-project:my-database", cert.Subject.CommonName)
}

func TestEncodePublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := pubkey.EncodePublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, pubKeyPEM, "BEGIN PUBLIC KEY")
}
