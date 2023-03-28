package pkg

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/db-operator/db-auth-gateway/internal/config"
	"github.com/db-operator/db-auth-gateway/internal/pubkey"
	"github.com/db-operator/db-auth-gateway/internal/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

const acceptLoopInterval = 100 * time.Millisecond

// Prometheus meters.
var (
	activeConnectionsMeter = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "active_connections",
		Help: "The total number of active connections",
	})
	totalBytesTransferredMeter = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "total_bytes_transferred",
		Help: "The total number of bytes transferred between the client and the database",
	})
)

// Gateway stores an instance of a Gateway task.
type Gateway struct {
	ListenAddress  string
	RemotePort     int
	CredentialFile string
	Instance       string
	MaxConnections int64
	ConfigProvider config.Provider
}

// Run is used to start an instance of the Gateway task and begin accepting connections.
func (c *Gateway) Run(ctx context.Context) error {
	addr, err := net.ResolveTCPAddr("tcp", c.ListenAddress)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"listenAddress": c.ListenAddress,
	}).Info("Accepting incoming connections")

	// We use both a waitgroup and an atomic counter so that we can leverage the strengths of both.
	var (
		wg                sync.WaitGroup
		activeConnections int64
	)

	// Run the proxy goroutines with their own context so we can better control the shutdown process.
	proxyCtx, proxyCtxCancel := context.WithCancel(context.Background())

	for {
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{
				"listenAddress": c.ListenAddress,
			}).Info("Stopping listener")

			if err := listener.Close(); err != nil {
				log.WithFields(log.Fields{
					"listenAddress": c.ListenAddress,
					"err":           err,
				}).Warn("Failed to close listener")
			}

			log.Info("Cancelling all active connections")

			proxyCtxCancel()
			wg.Wait()

			return nil
		default:
		}

		// Do not block forever as we want to be able to catch context cancellations.
		if err := listener.SetDeadline(time.Now().Add(acceptLoopInterval)); err != nil {
			proxyCtxCancel()

			return err
		}

		conn, err := listener.AcceptTCP()
		if err != nil {
			// Ignore the deadline messages.
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Timeout() {
				continue
			}

			proxyCtxCancel()

			return err
		}

		clientConn := util.MakeCancellable(proxyCtx, conn)

		clientAddress := conn.RemoteAddr().String()

		// Refuse new connections if we are over the configured limit.
		if c.MaxConnections > 0 && atomic.LoadInt64(&activeConnections) >= c.MaxConnections {
			log.WithFields(log.Fields{
				"clientAddress":  clientAddress,
				"maxConnections": c.MaxConnections,
			}).Info("Refusing incoming connection due to max connections limit")

			if err := clientConn.Close(); err != nil {
				proxyCtxCancel()

				return err
			}

			continue
		}

		log.WithFields(log.Fields{
			"clientAddress": clientAddress,
		}).Info("Handling incoming connection")

		activeConnectionsMeter.Inc()

		atomic.AddInt64(&activeConnections, 1)

		wg.Add(1)

		go func() {
			if err := c.handleClientConnection(ctx, clientConn, clientAddress); err != nil {
				log.WithFields(log.Fields{
					"clientAddress": clientAddress,
					"err":           err,
				}).Error("Handling client connection failed")
			}

			activeConnectionsMeter.Dec()

			atomic.AddInt64(&activeConnections, -1)

			wg.Done()
		}()
	}
}

func (c *Gateway) handleClientConnection(ctx context.Context,
	clientConn *util.CancellableConnection, clientAddress string) error {
	defer func() {
		log.WithFields(log.Fields{
			"clientAddress": clientAddress,
		}).Info("Closing client connection")

		if err := clientConn.Close(); err != nil {
			log.WithFields(log.Fields{
				"clientAddress": clientAddress,
				"err":           err,
			}).Warn("Closing client connection failed")
		}
	}()

	if err := c.proxyConnection(ctx, clientConn, clientAddress); err != nil {
		log.WithFields(log.Fields{
			"clientAddress": clientAddress,
			"err":           err,
		}).Warn("Remote connection failed, trying refreshing configuration")

		if err := c.ConfigProvider.RefreshConfig(); err != nil {
			log.WithFields(log.Fields{
				"clientAddress": clientAddress,
				"err":           err,
			}).Error("Refreshing configuration failed")
		}

		return err
	}

	return nil
}

func (c *Gateway) proxyConnection(
	ctx context.Context, clientConn net.Conn, clientAddress string) error {
	connCtx, connCancel := context.WithCancel(ctx)

	remoteConn, remoteAddress, err := c.connectRemote(connCtx)
	if err != nil {
		connCancel()

		return err
	}

	// Link the lifecycle of the client and remote connections.
	// So that they can be both cancelled with the same context.
	clientConnCancellable := util.MakeCancellable(connCtx, clientConn)

	// The client connection isn't closed here as we may attempt to retry using it.
	// Eg. a configuration refresh and retry.
	// Closing it is delegated upstream.
	defer func() {
		log.WithFields(log.Fields{
			"remoteAddress": remoteAddress,
		}).Info("Closing remote connection")

		if err := remoteConn.Close(); err != nil {
			log.WithFields(log.Fields{
				"remoteAddress": remoteAddress,
			}).Warn("Closing remote connection failed")
		}
	}()

	log.WithFields(log.Fields{
		"clientAddress": clientAddress,
		"remoteAddress": remoteAddress,
	}).Info("Proxying database connection")

	var wg sync.WaitGroup

	wg.Add(2)

	var transferred int64

	var copyErr error

	var copyErrMu sync.Mutex

	go func() {
		totalBytes, err := io.Copy(clientConnCancellable, remoteConn)
		if err != nil && !errors.Is(err, context.Canceled) {
			copyErrMu.Lock()
			if copyErr == nil {
				copyErr = err
			}
			copyErrMu.Unlock()
		}

		log.WithFields(log.Fields{
			"remoteAddress": remoteAddress,
			"totalBytes":    totalBytes,
		}).Info("Completed proxying from the server")

		atomic.AddInt64(&transferred, totalBytes)

		if !errors.Is(err, context.Canceled) {
			log.WithFields(log.Fields{
				"remoteAddress": remoteAddress,
			}).Info("Gracefully closing other half of the connection")

			// Gracefully cancel the other half of the connection.
			connCancel()
		}

		wg.Done()
	}()

	go func() {
		totalBytes, err := io.Copy(remoteConn, clientConnCancellable)
		if err != nil && !errors.Is(err, context.Canceled) {
			copyErrMu.Lock()
			if copyErr == nil {
				copyErr = err
			}
			copyErrMu.Unlock()
		}

		log.WithFields(log.Fields{
			"clientAddress": clientAddress,
			"totalBytes":    totalBytes,
		}).Info("Completed proxying from the client")

		atomic.AddInt64(&transferred, totalBytes)

		if !errors.Is(err, context.Canceled) {
			log.WithFields(log.Fields{
				"clientAddress": clientAddress,
			}).Info("Gracefully closing other half of the connection")

			// Gracefully cancel the other half of the connection.
			connCancel()
		}

		wg.Done()
	}()

	wg.Wait()

	totalBytesTransferredMeter.Observe(float64(transferred))

	// copyErr be nil if no errors occurred.
	return copyErr
}

func (c *Gateway) connectRemote(ctx context.Context) (*util.CancellableConnection, string, error) {
	primaryAddress, err := c.ConfigProvider.GetPrimaryAddress()
	if err != nil {
		return nil, primaryAddress, err
	}

	caCert, err := c.ConfigProvider.GetAuthorityCertificate()
	if err != nil {
		return nil, primaryAddress, err
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	clientCert, err := c.ConfigProvider.GetClientCertificate()
	if err != nil {
		return nil, primaryAddress, err
	}

	log.WithFields(log.Fields{
		"remoteAddress": primaryAddress,
		"fingerprint":   pubkey.Fingerprint(clientCert.Leaf),
	}).Info("Establishing remote connection")

	/* #nosec */
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      rootCAs,
		// Custom server certificate validation due to:
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pubkey.NewServerCertificateValidator(rootCAs, c.Instance),
	}

	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", primaryAddress, c.RemotePort))
	if err != nil {
		return nil, primaryAddress, err
	}

	return util.MakeCancellable(ctx, tls.Client(conn, tlsConfig)), primaryAddress, nil
}
