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

	"github.com/kloeckner-i/db-auth-gateway/internal/pubkey"
	"github.com/stretchr/testify/assert"
)

const serverCertPEM = `-----BEGIN CERTIFICATE-----
MIID4jCCAsqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJERTEQ
MA4GA1UECBMHR2VybWFueTEPMA0GA1UEBxMGQmVybGluMQ8wDQYDVQQKEwZEZXZP
cHMxGDAWBgNVBAsTD0NvbmR1aXQgVGVzdCBDQTEYMBYGA1UEAxMPQ29uZHVpdCBU
ZXN0IENBMB4XDTI2MDgwNjA4NDQxMloXDTQ2MDgwNjA5NDQxMlowfTELMAkGA1UE
BhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJlcmxpbjEPMA0GA1UE
ChMGRGV2T3BzMRkwFwYDVQQLExBDb25kdWl0IERhdGFiYXNlMR8wHQYDVQQDExZt
eS1wcm9qZWN0Om15LWRhdGFiYXNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAtMsYjOV58jIZk2jMAEQNav9xh+JhesGMSWmwoqh/lAkRwEKB8tvZWkBR
6TzXMMWt3P9rOkxUh39iDF/JPOM4Ns5B+tAHsYMdEmI9Jqz+/PqfHp81KOc8vtth
uwnxAcRAPAwk4ajyd7jBoVSZrDiU5pRq2Q2rwWbqYQzW6K8zaHEwQajYFELr8G4w
GjX7hm+lWGl0k4zK54Zk7nPIuCd/A0mf3zzN2se1Y/VPwDae1295l6pNXSuCgC7U
cA8CfIiUi8ArwyE9AQXFXh1RupbTDLCd5Q1wqT6JfMVZFTn90Of11uByrATxhbhR
FmgCnjH1WONpEhT/7pUNMrV7+pH1/wIDAQABo3UwczAOBgNVHQ8BAf8EBAMCBaAw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUqbgHIFjTD1UeA4fAWFCf
qOIEBTIwKwYDVR0RBCQwIoIgbXktcHJvamVjdDpteS1yZWdpb246bXktZGF0YWJh
c2UwDQYJKoZIhvcNAQELBQADggEBAGYgZjKdbWS+d6s+JedZfEmRWT1za4UXozk7
Qm+5hh7BsH/oGljCQQ0ESsTXxfeSV6aV0R9CEZnACtfL4QqqsFIFj0aqNLgKAOXo
azdPJZlhNiBZom/opZOQPXAiPQIYYSIjDcQ2Mfrz/MtWdNNyvVUkIV/xvgCj7Eix
jPzZFi272E43NM8axJSDRaDuS3Dgl5RfnxvrdeLNVOLfOrBog8MG4balz333vSAS
WoBFVge13kclhR30y4HHyMXcXou7DDlUvm7iKOTvBRyjz+DYkwqIXnhiRU1hxJmY
u42U68tKkNx/APQrjb/P/PvloHJzUuq2OqJFg4rCBzJJuQARAZM=
-----END CERTIFICATE-----`

const caCertPEM = `-----BEGIN CERTIFICATE-----
MIIDpzCCAo+gAwIBAgIBATANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJERTEQ
MA4GA1UECBMHR2VybWFueTEPMA0GA1UEBxMGQmVybGluMQ8wDQYDVQQKEwZEZXZP
cHMxGDAWBgNVBAsTD0NvbmR1aXQgVGVzdCBDQTEYMBYGA1UEAxMPQ29uZHVpdCBU
ZXN0IENBMB4XDTI2MDgwNjA4NDQxMloXDTQ2MDgwNjA5NDQxMlowdTELMAkGA1UE
BhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJlcmxpbjEPMA0GA1UE
ChMGRGV2T3BzMRgwFgYDVQQLEw9Db25kdWl0IFRlc3QgQ0ExGDAWBgNVBAMTD0Nv
bmR1aXQgVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALz6
BH7C5ZEfSBYY73e7jYBJ2xtZemDbWDSiUVlrgbhbc03KjCbmFO95Hry/ER4aDNRp
eWWKi+zqJuSv3NbcGnT1Q0RhQXcg1ZUesMUaaH+qITZQ488MDnctbuQOMzX8uuo6
r4kbSPynrUrolcgWQMXOTBbD3P5PZA3dQxJP0xjrhZZBxaZP5hAWbeCbHfPjIlc4
RJ+Pxdhw/sC5OuEvLRDrQ+f6g3Vgwin7uUdH/XLXoZ4zs704Esbdp9UKGLcWRM9k
sdZKfPX3bKmVPvsbXPnAI4KSNBjQs9p8x3xQJ0BFEaaV1qLcH/DmfzsC1ePOMDVH
0v+CC2rFhYOuPA5tnXMCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFKm4ByBY0w9VHgOHwFhQn6jiBAUyMA0GCSqGSIb3
DQEBCwUAA4IBAQC8FuKjaOyC4WRTy1YqHV3O5AoyhhAx1dp8JYaKWg2tMy5dKpDF
txNU4jaFbjBPYefFIKKrNqxb0jpYu6zozRmd/NgRVdh95LlSKnXCkqAv0VaLXPyx
yIufm73MzFmvX68HSD6p9LejlqAd4ffxPoAOZmyxXdJL9DWQPrxDgAjRh4P5EuFI
tC0hWfiC1kQWQttGuzN+G9ULl3vMBDWjqmE7IIDspfBEVkKfJEwVZjHjw3Srxwxf
FrXdfoBqO0nYnFSjznCsbj1BnlD3zSai7qBPiUarNQFJHmDK9WuLJ5JUXjfwxdxJ
y9fx0h2TQZkPJvKGt6Jczirj7mFcrL91tZ+4
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
