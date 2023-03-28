package pubkey

/*
 * Copyright 2015 Google Inc. All Rights Reserved.
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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/db-operator/db-auth-gateway/internal/util"
	log "github.com/sirupsen/logrus"
)

import "crypto/md5" // #nosec

var (
	// ErrCommonNameMismatch is returned when the server certificate common name does not match our database.
	ErrCommonNameMismatch = errors.New("certificate common name did not match")
	// ErrInvalidPEM is returned when a malformed certificate is provided.
	ErrInvalidPEM = errors.New("invalid pem")
	// ErrNoCertificate is returned when the server does not supply a valid certificate chain.
	ErrNoCertificate = errors.New("no certificate to verify")
)

// NewServerCertificateValidator creates a new custom server certificate validator from
// the given certificate authority, and instance details.
func NewServerCertificateValidator(rootCAs *x509.CertPool, instance string) func(
	rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoCertificate
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}

		opts := x509.VerifyOptions{Roots: rootCAs}
		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		parsedInstance, err := util.ParseInstance(instance)
		if err != nil {
			return err
		}

		projectName := fmt.Sprintf("%s:%s", parsedInstance["project"], parsedInstance["name"])
		if cert.Subject.CommonName != projectName {
			log.WithFields(log.Fields{
				"certificateCommonName": cert.Subject.CommonName,
				"expectedCommonName":    projectName,
			}).Warn("Certificate common name mismatch")

			return ErrCommonNameMismatch
		}

		return nil
	}
}

// ParseCertificate decodes a PEM encoded certificate.
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	bl, _ := pem.Decode([]byte(certPEM))
	if bl == nil {
		return nil, ErrInvalidPEM
	}

	return x509.ParseCertificate(bl.Bytes)
}

// EncodePublicKey encodes an RSA public key into its PEM representation.
func EncodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pubKeyPEM := new(bytes.Buffer)

	if err := pem.Encode(pubKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}); err != nil {
		return "", err
	}

	return pubKeyPEM.String(), nil
}

// Fingerprint returns the encoded fingerprint for the given certificate.
func Fingerprint(cert *x509.Certificate) string {
	var fingerprint bytes.Buffer

	/* #nosec. */
	for i, v := range md5.Sum(cert.Raw) {
		if i > 0 {
			_, _ = fmt.Fprintf(&fingerprint, ":")
		}

		_, _ = fmt.Fprintf(&fingerprint, "%02X", v)
	}

	return fingerprint.String()
}
