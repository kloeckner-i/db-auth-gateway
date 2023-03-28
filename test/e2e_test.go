// +build e2e

package test

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
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/db-operator/db-auth-gateway/internal/api"
	"github.com/db-operator/db-auth-gateway/internal/util"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// The port to run the proxy under test on.
	gatewayPort         = 5433
	gatewayStartTimeout = 5 * time.Second
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

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	gatewayBinPath := path.Clean(wd + "/../target/db-auth-gateway")

	if _, err := os.Stat(gatewayBinPath); err != nil {
		log.Fatal(err)
	}

	gatewayHostAndPort := fmt.Sprintf("localhost:%d", gatewayPort)

	cmd := exec.Command(gatewayBinPath,
		"--api-endpoint=http://"+util.GetMockAddress()+":8080",
		"--credential-file=DISABLED",
		"--min-refresh-interval=0",
		"--listen="+gatewayHostAndPort,
		"--instance=my-project:my-region:my-database")

	logFilePath := path.Clean(wd + "/../target/db-auth-gateway.log")

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		log.Fatal(err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	go func() {
		if err = cmd.Start(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for db-auth-gateway to start.
	var start time.Time
	for start = time.Now(); time.Since(start) < gatewayStartTimeout; {
		_, err := net.DialTimeout("tcp", gatewayHostAndPort, 100*time.Millisecond)
		if err == nil {
			break
		}
	}

	if time.Since(start) > gatewayStartTimeout {
		log.Fatal("db-auth-gateway took too long to start")
	}

	res := m.Run()

	if err := cmd.Process.Kill(); err != nil {
		log.Warn(err)
	}

	if err := logFile.Close(); err != nil {
		log.Fatal(err)
	}

	os.Exit(res)
}

func TestEndToEnd(t *testing.T) {
	connString := fmt.Sprintf("postgres://postgres:mysecretpassword@localhost:%d", gatewayPort)

	db, err := sql.Open("pgx", connString)
	if err != nil {
		t.Fatal(err)
	}

	// Make the test more predictable.
	db.SetMaxOpenConns(1)

	var count int64

	err = db.QueryRow(`SELECT COUNT(*) FROM pg_catalog.pg_user`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, count > 0)

	// The connection pool handles a certificate rotation gracefully.
	if err := rotateCertificates(); err != nil {
		t.Fatal(err)
	}

	count = 0

	// The Ping will fail and the connection will be recycled from the pool.
	// Unfortunately the pgx client doesn't really listen proactively for connection close events.
	// https://github.com/jackc/pgx/issues/672
	err = db.Ping()

	assert.NotNil(t, err)

	err = db.QueryRow(`SELECT COUNT(*) FROM pg_catalog.pg_user`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, count > 0)
}

func rotateCertificates() error {
	client := &http.Client{}

	request, err := http.NewRequest(http.MethodPost, "http://"+util.GetMockAddress()+":8080/revoke", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("bad status code")
	}

	return nil
}
