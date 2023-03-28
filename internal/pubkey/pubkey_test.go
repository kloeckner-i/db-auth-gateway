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
	"encoding/pem"
	"testing"

	"github.com/db-operator/db-auth-gateway/internal/pubkey"
	"github.com/stretchr/testify/assert"
)

const serverCertPEM = `-----BEGIN CERTIFICATE-----
MIIELjCCAxagAwIBAgIUZmShyDLziQh83C+9Om9qGUtIoukwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJl
cmxpbjEPMA0GA1UEChMGRGV2T3BzMRgwFgYDVQQLEw9Db25kdWl0IFRlc3QgQ0Ex
GDAWBgNVBAMTD0NvbmR1aXQgVGVzdCBDQTAeFw0yMTAyMjQxMzA3MDBaFw0zMTAy
MjUwMTA3MDBaMH0xCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdHZXJtYW55MQ8wDQYD
VQQHEwZCZXJsaW4xDzANBgNVBAoTBkRldk9wczEZMBcGA1UECxMQQ29uZHVpdCBE
YXRhYmFzZTEfMB0GA1UEAxMWbXktcHJvamVjdDpteS1kYXRhYmFzZTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJykewpZJoyv9me0vLDXXMDYK9o677AP
qaqdBJvDwu05Yr/CaphYkkjrrb2xJ/ME/+Z5Nj2fmKQud5iNLeGppPT0FriYxjYp
epUa1MrOpRIfZAUS/ddhCn4bmIJJaGY8/9pBT70O9NYymga41YkWW6uqVjslfxN1
EcPTmRvroFFDWEsDJigU6JKOOaCJUa11SsGHfsBo0xf9V6vMaAi5XlzYazaQmHd5
k5xhhP7+gzEMEmknZv5YlEPNIJniFlilF6cedjBN6oCEWcVy1haqzMGH7/VGFHZn
bUgAOCM0eOROGnXVC7hP9GxgfK5i8C0x6ZMlAQ5gt06Ziv1F4wVc8jUCAwEAAaOB
rTCBqjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBfyPFOj4IJRH+3XFVTcg4gIPdq1
MB8GA1UdIwQYMBaAFFKnUX7vV5f2A8Us1BmHDrS//Xy4MCsGA1UdEQQkMCKGIG15
LXByb2plY3Q6bXktcmVnaW9uOm15LWRhdGFiYXNlMA0GCSqGSIb3DQEBCwUAA4IB
AQBKFWVVKoTiuOzUIsINqE1uTpAWwEEpUOCvyj+aTFUloHbxfluk1aUavl9Almv7
yac9fuWgIGpM58nLdBBIdnz/VdieMpnD20Ao3vJEZ7LzLICcohidRZf1+DYUEgBG
qvPcawrAhiYI5QXKMIGhED0/tQ+b8FeijgWZ9R8/9AEcA0aHrms//V/bHsS+4H+K
ICqMbQmH3+MPpd4xSfv192jPJWwYv9+wMZweN0AD3Js24n70w3gXHBojQaIuc6DG
WD9pmGCwsGn6VuPWmVlxME0Ywp3tOAuuhC5jaM5JOW8OiHYHjmoMIxZ9PjcQbsc7
slUrj50dVRKrPgugXlWduU/o
-----END CERTIFICATE-----`

const caCertPEM = `-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIUK22pJu0d3BNA50W7yza4da4lBA4wDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJl
cmxpbjEPMA0GA1UEChMGRGV2T3BzMRgwFgYDVQQLEw9Db25kdWl0IFRlc3QgQ0Ex
GDAWBgNVBAMTD0NvbmR1aXQgVGVzdCBDQTAeFw0yMTAyMjQxMjU0MDBaFw0yNjAy
MjMxMjU0MDBaMHUxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdHZXJtYW55MQ8wDQYD
VQQHEwZCZXJsaW4xDzANBgNVBAoTBkRldk9wczEYMBYGA1UECxMPQ29uZHVpdCBU
ZXN0IENBMRgwFgYDVQQDEw9Db25kdWl0IFRlc3QgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDRW+wUB2Xkn2VV2VsX6ztrQgHuV20JBb+zrd7gKUDz
pzjFUBRZ/jEBEmIPP+7TJjFrI5aVw/iYEzcw8EqN+kpg1xSM3ld9tFK/jmD98DXg
c3SJEL7QxwDMfspdqBqXtRdmSA/xl6jfspSEbP/hDeTzhib0IOIiurH1gUOCVWMA
S1AbmnJgQKvMXb+R9VKXwlb23LRH9KCR7UNKaGz/kDuJQKaBgWRLPJeddyOXuTwa
ikB6LpQyEx052pFrEcAks8OtAB2OFvPWLDzPGNxa1JXxnMKLSLZxCrnrCfc6pLsw
Y90YhKJuFG5KWzyfQXDdLR8se6jgQc5ChtcoIGR9s6oZAgMBAAGjQjBAMA4GA1Ud
DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRSp1F+71eX9gPF
LNQZhw60v/18uDANBgkqhkiG9w0BAQsFAAOCAQEASAaDjzMoNEKb6OqaFPsoIIQq
lBJafueZAzjcslavSIdP4XLd+Ua8be226Cwegs4gSGwxHp6CK/ih8P5FEEUh7bYW
GJgQ4MOL1En4WFF9jeH8jgSWvmr1or8IccuKmcmHCyGVaVkbt+DFdEGpLH6USjF/
p57SXdK8OXExFxNrc4RkC7HP04wTIZDyGQCAtZ0BprG1aK1l4VhiQdT+gj4TubDg
hfQmyMQzBMwKjae2dRciMmIPmVMc8FCk+MaRlBJ40RCjtdliICJc+r8/hRMLrzKy
h8P7/ELsOg0b3mfyOd0nfYo6uw+NMZ0HGvc1Mjv8qX6oLGulTwAeLdSAkurteg==
-----END CERTIFICATE-----`

func TestServerCertificateValidator(t *testing.T) {
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
