package api

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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/db-operator/db-auth-gateway/internal/util"
	"golang.org/x/oauth2"
	goauth "golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// DisabledCredentialFile is a special value for the credential file path that we disable oauth authentication
// this is used for local testing.
const DisabledCredentialFile = "DISABLED"

// ErrUnsupportedDatabaseVersion is returned when a user attempts to use db-auth-gateway
// with an incompatible database version.
var ErrUnsupportedDatabaseVersion = errors.New("unsupported database version")

// Client is an instance of the cloud database api client for use with Google Cloud.
type Client struct {
	sqladminService *sqladmin.Service
}

// NewClientFromCredentialFile constructs a new Google Cloud API client from the supplied JSON credential file.
func NewClientFromCredentialFile(ctx context.Context, credentialFile, apiEndpoint string) (*Client, error) {
	var credentialJSON []byte

	if credentialFile != DisabledCredentialFile {
		var err error

		credentialJSON, err = ioutil.ReadFile(credentialFile)
		if err != nil {
			return nil, err
		}
	}

	opts := []option.ClientOption{
		option.WithScopes(sqladmin.SqlserviceAdminScope),
	}

	if apiEndpoint != "" {
		opts = append(opts, option.WithEndpoint(apiEndpoint))
	}

	if credentialFile == DisabledCredentialFile {
		opts = append(opts, option.WithHTTPClient(oauth2.NewClient(ctx, &DisabledTokenSource{})))
	} else if cfg, err := goauth.JWTConfigFromJSON(credentialJSON, sqladmin.SqlserviceAdminScope); err == nil {
		opts = append(opts, option.WithHTTPClient(cfg.Client(ctx)))
	} else {
		cred, err := goauth.CredentialsFromJSON(ctx, credentialJSON, sqladmin.SqlserviceAdminScope)
		if err != nil {
			return nil, err
		}

		opts = append(opts, option.WithHTTPClient(oauth2.NewClient(ctx, cred.TokenSource)))
	}

	sqladminService, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &Client{sqladminService}, nil
}

// GetInstance queries the API for information about a given database instance.
func (c *Client) GetInstance(instance string) (*sqladmin.DatabaseInstance, error) {
	parsedInstance, err := util.ParseInstance(instance)
	if err != nil {
		return nil, err
	}

	regionName := fmt.Sprintf("%s~%s", parsedInstance["region"], parsedInstance["name"])

	dbInstance, err := c.sqladminService.Instances.Get(parsedInstance["project"], regionName).Do()
	if err != nil {
		return nil, err
	}

	if dbInstance.BackendType != "SECOND_GEN" {
		return nil, ErrUnsupportedDatabaseVersion
	}

	return dbInstance, nil
}

// CreateClientCertificate is used to create a new ephemeral client certificate from the supplied key pair.
// This client certificate is used for mutual TLS authentication with the database.
func (c *Client) CreateClientCertificate(instance string, pubKey crypto.PublicKey) (*sqladmin.SslCert, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	parsedInstance, err := util.ParseInstance(instance)
	if err != nil {
		return nil, err
	}

	regionName := fmt.Sprintf("%s~%s", parsedInstance["region"], parsedInstance["name"])
	req := c.sqladminService.SslCerts.CreateEphemeral(parsedInstance["project"], regionName,
		&sqladmin.SslCertsCreateEphemeralRequest{
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Bytes: pkix, Type: "RSA PUBLIC KEY"})),
		},
	)

	return req.Do()
}

// DisabledTokenSource is a mocked oauth token source for local testing.
type DisabledTokenSource struct{}

// Token issues a mocked bearer token for local testing.
func (ts *DisabledTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "let-me-in-pls",
		TokenType:    "Bearer",
		RefreshToken: "gimme-the-new-key-thx",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}
