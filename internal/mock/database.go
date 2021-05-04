package mock

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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kloeckner-i/db-auth-gateway/internal/pubkey"
	"github.com/kloeckner-i/db-auth-gateway/internal/util"
	log "github.com/sirupsen/logrus"
)

// DatabaseProxy is a mutual tls proxy for the end-to-end test suite.
type DatabaseProxy struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	ctxMu      sync.Mutex
	authority  *pubkey.Authority
	serverKey  *rsa.PrivateKey
	serverCert *x509.Certificate
	proxyPort  int
	dbAddress  string
}

// ErrRevokedCertificate is returned when a certificate has been revoked.
var ErrRevokedCertificate = errors.New("certificate has been revoked")

// NewDatabaseProxy constructs a new mutual tls proxy for the supplied database.
func NewDatabaseProxy(authority *pubkey.Authority, proxyPort int, instance, dbAddress string) (*DatabaseProxy, error) {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubKeyPEM, err := pubkey.EncodePublicKey(&serverKey.PublicKey)
	if err != nil {
		return nil, err
	}

	parsedInstance, err := util.ParseInstance(instance)
	if err != nil {
		return nil, err
	}

	projectName := fmt.Sprintf("%s:%s", parsedInstance["project"], parsedInstance["name"])

	serverCertPEM, err := authority.Sign(pubKeyPEM, pkix.Name{
		CommonName: projectName,
	}, time.Hour)
	if err != nil {
		return nil, err
	}

	serverCert, err := pubkey.ParseCertificate(serverCertPEM)
	if err != nil {
		return nil, err
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	return &DatabaseProxy{
		ctx:        ctx,
		ctxCancel:  ctxCancel,
		authority:  authority,
		serverKey:  serverKey,
		serverCert: serverCert,
		proxyPort:  proxyPort,
		dbAddress:  dbAddress,
	}, nil
}

// Run starts the database mutual tls proxy.
func (dp *DatabaseProxy) Run() error {
	caCert, err := pubkey.ParseCertificate(dp.authority.CertPEM())
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	serverCertChain := []tls.Certificate{
		{Certificate: [][]byte{dp.serverCert.Raw}, PrivateKey: dp.serverKey},
		{Certificate: [][]byte{caCert.Raw}},
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: serverCertChain,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, verifiedChain := range verifiedChains {
				for _, cert := range verifiedChain {
					if dp.authority.IsRevoked(cert) {
						return ErrRevokedCertificate
					}
				}
			}

			return nil
		},
	}

	tlsConn, err := tls.Listen("tcp", fmt.Sprintf(":%d", dp.proxyPort), tlsConfig)
	if err != nil {
		return err
	}

	defer func() {
		if err := tlsConn.Close(); err != nil {
			log.Warn(err)
		}
	}()

	for {
		conn, err := tlsConn.Accept()
		if err != nil {
			log.Error(err)

			continue
		}

		go func() {
			dbConn, err := net.Dial("tcp", dp.dbAddress)
			if err != nil {
				log.Error(err)
			}

			dp.ctxMu.Lock()

			connCtx, connCancel := context.WithCancel(dp.ctx)

			dp.ctxMu.Unlock()

			cancellableConn := util.MakeCancellable(connCtx, conn)

			cancellableDBConn := util.MakeCancellable(connCtx, dbConn)

			var wg sync.WaitGroup

			wg.Add(2)

			go func() {
				if _, err := io.Copy(cancellableDBConn, cancellableConn); err != nil {
					log.Warn(err)
				}

				if !errors.Is(err, context.Canceled) {
					connCancel()
				}

				wg.Done()
			}()

			go func() {
				if _, err := io.Copy(cancellableConn, cancellableDBConn); err != nil {
					log.Warn(err)
				}

				if !errors.Is(err, context.Canceled) {
					connCancel()
				}

				wg.Done()
			}()

			wg.Wait()

			log.Info("Closing connection")

			if err := cancellableDBConn.Close(); err != nil {
				log.Warn(err)
			}

			if err := cancellableConn.Close(); err != nil {
				log.Warn(err)
			}
		}()
	}
}

// CloseAll closes all existing connections.
func (dp *DatabaseProxy) CloseAll() {
	log.Info("Closing all established connections")

	dp.ctxMu.Lock()
	defer dp.ctxMu.Unlock()

	dp.ctxCancel()

	dp.ctx, dp.ctxCancel = context.WithCancel(context.Background())
}
