package config

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/db-operator/db-auth-gateway/internal/api"
	"github.com/db-operator/db-auth-gateway/internal/pubkey"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// ErrNoPrimaryAddress is returned when a database does not have a valid primary address.
var ErrNoPrimaryAddress = errors.New("no primary address found for database")

// Prometheus meters.
var (
	configRefreshDurationMeter = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "config_refresh_duration",
		Help: "The duration elapsed between configuration refreshes",
	})
	configRefreshSuccessMeter = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "config_refresh_success",
		Help: "The number of times that configuration refreshes have succeeded",
	})
	configRefreshFailuresMeter = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "config_refresh_failure",
		Help: "The number of times that configuration refreshes have failed",
	})
)

// Provider is a cached configuration provider. We cache the database configuration so that we don't spam
// the Google Cloud API and use excess API quota.
type Provider interface {
	GetPrimaryAddress() (string, error)
	GetClientCertificate() (*tls.Certificate, error)
	GetAuthorityCertificate() (*x509.Certificate, error)
	RefreshConfig() error
}

// GCloudProvider is a configuration provider for Google Cloud managed databases.
type GCloudProvider struct {
	mu                      sync.Mutex
	ctx                     context.Context
	apiClient               *api.Client
	instance                string
	minRefreshInterval      time.Duration
	periodicRefreshInterval time.Duration
	keyPair                 *rsa.PrivateKey
	clientCertificate       *tls.Certificate
	dbInstance              *sqladmin.DatabaseInstance
	lastRefresh             time.Time
}

// NewConfigProvider constructs a new configuration provider from an API client and instance.
func NewConfigProvider(ctx context.Context,
	apiClient *api.Client, instance string,
	minRefreshInterval, periodicRefreshInterval time.Duration) (Provider, error) {
	log.Info("Generating RSA key pair for encrypting connections")

	// Generate a new RSA key pair which will be used for our client certificates
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	configProvider := &GCloudProvider{
		ctx:                     ctx,
		apiClient:               apiClient,
		instance:                instance,
		minRefreshInterval:      minRefreshInterval,
		periodicRefreshInterval: periodicRefreshInterval,
		keyPair:                 keyPair,
	}

	// If not uniquely seeded the math random sequence will be the same for every instance,
	// this is obviously what we are trying to avoid.
	mrand.Seed(time.Now().UTC().UnixNano() ^ int64(os.Getpid()))

	// Periodically refresh the ephemeral client certificate.
	go configProvider.periodicRefreshTask()

	return configProvider, nil
}

// GetPrimaryAddress returns the active primary ip address of the database (eg. its public load balancer).
func (p *GCloudProvider) GetPrimaryAddress() (string, error) {
	p.mu.Lock()
	dbInstance := p.dbInstance
	p.mu.Unlock()

	if dbInstance == nil {
		if err := p.RefreshConfig(); err != nil {
			return "", err
		}

		p.mu.Lock()
		dbInstance = p.dbInstance
		p.mu.Unlock()
	}

	var primaryAddress string

	for _, addr := range dbInstance.IpAddresses {
		if addr.Type == "PRIMARY" {
			primaryAddress = addr.IpAddress
		}
	}

	if primaryAddress == "" {
		return "", ErrNoPrimaryAddress
	}

	return primaryAddress, nil
}

// GetClientCertificate returns the latest ephemeral client certificate.
func (p *GCloudProvider) GetClientCertificate() (*tls.Certificate, error) {
	p.mu.Lock()
	clientCertificate := p.clientCertificate
	p.mu.Unlock()

	if clientCertificate == nil {
		if err := p.RefreshConfig(); err != nil {
			return nil, err
		}

		p.mu.Lock()
		clientCertificate = p.clientCertificate
		p.mu.Unlock()
	}

	return clientCertificate, nil
}

// GetAuthorityCertificate returns the latest root certificate authority.
func (p *GCloudProvider) GetAuthorityCertificate() (*x509.Certificate, error) {
	p.mu.Lock()
	dbInstance := p.dbInstance
	p.mu.Unlock()

	if dbInstance == nil {
		if err := p.RefreshConfig(); err != nil {
			return nil, err
		}

		p.mu.Lock()
		dbInstance = p.dbInstance
		p.mu.Unlock()
	}

	return pubkey.ParseCertificate(dbInstance.ServerCaCert.Cert)
}

// RefreshConfig downloads the latest database configuration and issues an updated client certificate.
func (p *GCloudProvider) RefreshConfig() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// To avoid exhausting client API quota, don't spam it.
	log.WithFields(log.Fields{
		"minRefreshInterval": p.minRefreshInterval,
		"sinceLastRefresh":   time.Since(p.lastRefresh),
	}).Info("Checking time of last configuration refresh")

	if time.Since(p.lastRefresh) < p.minRefreshInterval {
		log.Warn("Not refreshing configuration due to a recent refresh having already occurred")

		return nil
	}

	log.Info("Fetching updated database configuration")

	var err error

	p.dbInstance, err = p.apiClient.GetInstance(p.instance)
	if err != nil {
		configRefreshFailuresMeter.Inc()

		return err
	}

	log.Info("Fetching new client certificate")

	resp, err := p.apiClient.CreateClientCertificate(p.instance, p.keyPair.Public())
	if err != nil {
		configRefreshFailuresMeter.Inc()

		return err
	}

	cert, err := pubkey.ParseCertificate(resp.Cert)
	if err != nil {
		configRefreshFailuresMeter.Inc()

		return err
	}

	log.WithFields(log.Fields{
		"fingerprint": pubkey.Fingerprint(cert),
	}).Info("Received new client certificate")

	p.clientCertificate = &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  p.keyPair,
		Leaf:        cert,
	}

	configRefreshDurationMeter.Observe(float64(time.Since(p.lastRefresh)) / float64(time.Second))

	configRefreshSuccessMeter.Inc()

	p.lastRefresh = time.Now()

	return nil
}

func (p *GCloudProvider) periodicRefreshTask() {
	for {
		/* #nosec */
		refreshCycleInterval := p.periodicRefreshInterval/2 + time.Duration(mrand.Int63n(int64(p.periodicRefreshInterval)))
		if refreshCycleInterval < p.minRefreshInterval {
			refreshCycleInterval = p.minRefreshInterval
		}

		log.WithFields(log.Fields{
			"refreshCycleInterval": refreshCycleInterval,
		}).Info("Waiting for next client certificate refresh")

		select {
		case <-time.After(refreshCycleInterval):
			log.Info("Client certificate will expire soon, attempting refresh")

			if err := p.RefreshConfig(); err != nil {
				log.WithFields(log.Fields{
					"err": err,
				}).Warn("Periodic configuration refresh failed")
			}
		case <-p.ctx.Done():
			return
		}
	}
}
