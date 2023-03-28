package config_test

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
	"crypto/x509"
	"log"
	"os"
	"testing"
	"time"

	"github.com/db-operator/db-auth-gateway/internal/api"
	"github.com/db-operator/db-auth-gateway/internal/config"
	"github.com/db-operator/db-auth-gateway/internal/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	opts := []option.ClientOption{
		option.WithEndpoint("http://localhost:8080"),
		option.WithHTTPClient(oauth2.NewClient(ctx, &api.DisabledTokenSource{})),
	}

	sqladminService, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		log.Fatal("error occurs during getting sqladminService", err)
	}

	_, err = sqladminService.Instances.Insert("my-project", &sqladmin.DatabaseInstance{
		Name: "my-region~my-database",
	}).Do()
	if err != nil {
		log.Fatal("error occurs during getting sqladminService", err)
	}

	os.Exit(m.Run())
}

func TestGetPrimaryAddress(t *testing.T) {
	configProvider, err := newConfigProvider()
	if err != nil {
		t.Fatal(err)
	}

	primaryAddress, err := configProvider.GetPrimaryAddress()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, util.GetMockAddress(), primaryAddress)
}

func TestGetClientCertificate(t *testing.T) {
	configProvider, err := newConfigProvider()
	if err != nil {
		t.Fatal(err)
	}

	clientCertificate, err := configProvider.GetClientCertificate()
	if err != nil {
		t.Fatal(err)
	}

	parsedCertificate, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "ephemeral-client-certificate", parsedCertificate.Subject.CommonName)
}

func TestGetAuthorityCertificate(t *testing.T) {
	configProvider, err := newConfigProvider()
	if err != nil {
		t.Fatal(err)
	}

	parsedCertificate, err := configProvider.GetAuthorityCertificate()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Mock CA", parsedCertificate.Subject.CommonName)
}

func TestRefreshConfig(t *testing.T) {
	configProvider, err := newConfigProvider()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := configProvider.GetClientCertificate()
	if err != nil {
		t.Fatal(err)
	}

	oldCert := cert.Certificate[0]

	if err := configProvider.RefreshConfig(); err != nil {
		t.Fatal(err)
	}

	cert, err = configProvider.GetClientCertificate()
	if err != nil {
		t.Fatal(err)
	}

	newCert := cert.Certificate[0]

	assert.NotEqual(t, oldCert, newCert)
}

func newConfigProvider() (config.Provider, error) {
	ctx := context.Background()

	apiClient, err := api.NewClientFromCredentialFile(ctx, api.DisabledCredentialFile,
		"http://"+util.GetMockAddress()+":8080")
	if err != nil {
		return nil, err
	}

	return config.NewConfigProvider(ctx, apiClient, "my-project:my-region:my-database", 0, time.Minute)
}
