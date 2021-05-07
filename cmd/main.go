package main

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
	"crypto/x509/pkix"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkg "github.com/kloeckner-i/db-auth-gateway/internal"
	"github.com/kloeckner-i/db-auth-gateway/internal/api"
	"github.com/kloeckner-i/db-auth-gateway/internal/config"
	"github.com/kloeckner-i/db-auth-gateway/internal/mock"
	"github.com/kloeckner-i/db-auth-gateway/internal/pubkey"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	defaultMinRefreshInterval      = time.Minute
	defaultPeriodicRefreshInterval = 5 * time.Minute
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})

	if term.IsTerminal(int(os.Stdout.Fd())) {
		log.SetLevel(log.DebugLevel)
		log.SetFormatter(&log.TextFormatter{})
	}

	if err := execute(); err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Fatal("Failed to execute command")
	}
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "db-auth-gateway",
		Short: "db-auth-gateway is an authentication proxy for Google Cloud managed databases",
		RunE:  startGateway,
	}

	rootCmd.Flags().String("credential-file", "", "JSON file containing the Google Cloud credentials")
	rootCmd.Flags().String("instance", "", "Fully qualified database instance to connect to (project:region:name)")
	rootCmd.Flags().StringP("listen", "l", ":5432", "Address and port to listen on")
	rootCmd.Flags().Int("remote-port", 3307, "Port to connect to the remote server on")
	rootCmd.Flags().Int64("max-connections", 0, "The maximum number of active connections. Defaults to 0 (unlimited)")
	rootCmd.Flags().Duration("min-refresh-interval", defaultMinRefreshInterval,
		"The minimum amount of time to wait between API calls")
	rootCmd.Flags().Duration("periodic-refresh-interval", defaultPeriodicRefreshInterval,
		"Eagerly refresh the database configuration to avoid stale client certificates. "+
			"This duration is only a nominal value, each refresh cycle will vary by up to fifty percent.")
	rootCmd.Flags().String("api-endpoint", "", "If specified the URL to use for API calls")

	if err := rootCmd.MarkFlagRequired("credential-file"); err != nil {
		return err
	}

	if err := rootCmd.MarkFlagRequired("instance"); err != nil {
		return err
	}

	mockCmd := &cobra.Command{
		Use:   "mock",
		Short: "Run a local Google managed database mock (for testing)",
		RunE:  startMock,
	}

	mockCmd.Flags().String("instance", "", "Fully qualified database instance to connect to (project:region:name)")
	mockCmd.Flags().String("db-address", "", "Address of the database for which to proxy")
	mockCmd.Flags().Int("api-port", 8080, "Port on which to serve the mocked sqladmin API")
	mockCmd.Flags().Int("proxy-port", 3307, "Port on which to serve the database proxy")

	if err := mockCmd.MarkFlagRequired("instance"); err != nil {
		return err
	}

	if err := mockCmd.MarkFlagRequired("db-address"); err != nil {
		return err
	}

	rootCmd.AddCommand(mockCmd)

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}

func startGateway(cmd *cobra.Command, args []string) error {
	listenAddress, err := cmd.Flags().GetString("listen")
	if err != nil {
		return err
	}

	remotePort, err := cmd.Flags().GetInt("remote-port")
	if err != nil {
		return err
	}

	credentialFile, err := cmd.Flags().GetString("credential-file")
	if err != nil {
		return err
	}

	instance, err := cmd.Flags().GetString("instance")
	if err != nil {
		return err
	}

	maxConnections, err := cmd.Flags().GetInt64("max-connections")
	if err != nil {
		return err
	}

	minRefreshInterval, err := cmd.Flags().GetDuration("min-refresh-interval")
	if err != nil {
		return err
	}

	periodicRefreshInterval, err := cmd.Flags().GetDuration("periodic-refresh-interval")
	if err != nil {
		return err
	}

	apiEndpoint, err := cmd.Flags().GetString("api-endpoint")
	if err != nil {
		return err
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	apiClient, err := api.NewClientFromCredentialFile(ctx, credentialFile, apiEndpoint)
	if err != nil {
		ctxCancel()

		return err
	}

	configProvider, err := config.NewConfigProvider(ctx, apiClient, instance, minRefreshInterval, periodicRefreshInterval)
	if err != nil {
		ctxCancel()

		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-signals

		log.Info("Received term signal, gracefully shutting down")

		ctxCancel()
	}()

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		prometheusAddress := ":9090"

		log.WithFields(log.Fields{
			"prometheusAddress": prometheusAddress,
		}).Info("Starting prometheus metrics server")

		if err := http.ListenAndServe(prometheusAddress, nil); err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Fatal("Failed to start prometheus metrics server")
		}
	}()

	gateway := pkg.Gateway{
		ListenAddress:  listenAddress,
		RemotePort:     remotePort,
		CredentialFile: credentialFile,
		Instance:       instance,
		MaxConnections: maxConnections,
		ConfigProvider: configProvider,
	}

	return gateway.Run(ctx)
}

func startMock(cmd *cobra.Command, args []string) error {
	instance, err := cmd.Flags().GetString("instance")
	if err != nil {
		return err
	}

	dbAddress, err := cmd.Flags().GetString("db-address")
	if err != nil {
		return err
	}

	apiPort, err := cmd.Flags().GetInt("api-port")
	if err != nil {
		return err
	}

	proxyPort, err := cmd.Flags().GetInt("proxy-port")
	if err != nil {
		return err
	}

	authority, err := pubkey.NewAuthority(pkix.Name{
		CommonName: "Mock CA",
	}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	dbProxy, err := mock.NewDatabaseProxy(authority, proxyPort, instance, dbAddress)
	if err != nil {
		log.Fatal(err)
	}

	sqlAdminAPI, err := mock.NewSQLAdminAPI(dbProxy, authority, apiPort)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		if err := dbProxy.Run(); err != nil {
			log.Fatal(err)
		}
	}()

	if err := sqlAdminAPI.Run(); err != nil {
		log.Fatal(err)
	}

	return nil
}
