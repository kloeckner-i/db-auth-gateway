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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kloeckner-i/db-auth-gateway/internal/util"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// DisabledCredentialFile is a special value for the credential file path that we disable oauth authentication
// this is used for local testing.
const DisabledCredentialFile = "DISABLED"

// ErrUnsupportedDatabaseVersion is returned when a user attempts to use db-auth-gateway
// with an incompatible database version.
var ErrUnsupportedDatabaseVersion = errors.New("unsupported database version")

// ErrEmptyCredential is returned when the credential JSON is empty.
var ErrEmptyCredential = errors.New("credential provided is 0 bytes")

// Client is an instance of the cloud database api client for use with Google Cloud.
type Client struct {
	sqladminService *sqladmin.Service
}

// NewClientFromCredentialFile constructs a new Google Cloud API client from the supplied JSON credential file.
func NewClientFromCredentialFile(ctx context.Context, credentialFile, apiEndpoint string) (*Client, error) {
	opts := []option.ClientOption{
		option.WithScopes(sqladmin.SqlserviceAdminScope),
	}

	if apiEndpoint != "" {
		opts = append(opts, option.WithEndpoint(apiEndpoint))
	}

	if credentialFile == DisabledCredentialFile {
		opts = append(opts, option.WithHTTPClient(oauth2.NewClient(ctx, &DisabledTokenSource{})))
	} else {
		credJSON, err := os.ReadFile(credentialFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read credential file: %w", err)
		}

		credType, err := getCredentialType(credJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to determine credential type: %w", err)
		}

		opts = append(opts, option.WithAuthCredentialsFile(credType, credentialFile))
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

// getCredentialType parses the credential JSON to determine the type.
func getCredentialType(data []byte) (option.CredentialsType, error) {
	if len(data) == 0 {
		return option.CredentialsType(""), ErrEmptyCredential
	}

	var cred struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &cred); err != nil {
		return option.CredentialsType(""), err
	}

	return option.CredentialsType(cred.Type), nil
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
