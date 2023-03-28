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
	"testing"
	"time"

	"github.com/db-operator/db-auth-gateway/internal/pubkey"
	"github.com/stretchr/testify/assert"
)

func TestAuthority(t *testing.T) {
	authority, err := pubkey.NewAuthority(pkix.Name{
		CommonName: "Unit Test",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := authority.CertPEM()

	assert.Contains(t, certPEM, "BEGIN CERTIFICATE")

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := pubkey.EncodePublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	signedCertPEM, err := authority.Sign(pubKeyPEM, pkix.Name{
		CommonName: "unit test",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, signedCertPEM, "BEGIN CERTIFICATE")

	caCert, err := pubkey.ParseCertificate(authority.CertPEM())
	if err != nil {
		t.Fatal(err)
	}

	signedCert, err := pubkey.ParseCertificate(signedCertPEM)
	if err != nil {
		t.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	opts := x509.VerifyOptions{Roots: caCertPool}
	if _, err = signedCert.Verify(opts); err != nil {
		t.Fatal(err)
	}
}
