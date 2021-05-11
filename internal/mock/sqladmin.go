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
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kloeckner-i/db-auth-gateway/internal/pubkey"
	"github.com/kloeckner-i/db-auth-gateway/internal/util"
	log "github.com/sirupsen/logrus"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

/* #nosec. */
const allowedBearerToken = "let-me-in-pls"

// SQLAdminAPI is a mocked version of the Google sqladmin API.
type SQLAdminAPI struct {
	dbProxy   *DatabaseProxy
	authority *pubkey.Authority
	apiPort   int
}

// NewSQLAdminAPI constructs a new mocked sqladmin API.
func NewSQLAdminAPI(dbProxy *DatabaseProxy, authority *pubkey.Authority, apiPort int) (*SQLAdminAPI, error) {
	return &SQLAdminAPI{dbProxy, authority, apiPort}, nil
}

// Run runs the mocked sqladmin API.
func (sql *SQLAdminAPI) Run() error {
	r := mux.NewRouter()

	r.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}", sql.getInstanceHandler)
	r.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}/createEphemeral", sql.createEphemeralHandler)

	// Custom extension to the API for testing
	r.HandleFunc("/revoke", sql.revokeCertificatesHandler)

	return http.ListenAndServe(fmt.Sprintf(":%d", sql.apiPort), r)
}

func (sql *SQLAdminAPI) getInstanceHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Warn(err)
		}
	}()

	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, allowedBearerToken) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	vars := mux.Vars(r)

	respBytes, err := json.Marshal(&sqladmin.DatabaseInstance{
		BackendType:    "SECOND_GEN",
		ConnectionName: vars["project"] + ":" + strings.ReplaceAll(vars["instance"], "~", ":"),
		IpAddresses: []*sqladmin.IpMapping{
			{
				IpAddress: util.GetMockAddress(),
				Type:      "PRIMARY",
			},
		},
		ServerCaCert: &sqladmin.SslCert{
			Cert: sql.authority.CertPEM(),
		},
	})
	if err != nil {
		log.Error(err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(respBytes); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) createEphemeralHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Warn(err)
		}
	}()

	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, allowedBearerToken) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var createRequest sqladmin.SslCertsCreateEphemeralRequest

	if err := json.NewDecoder(r.Body).Decode(&createRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if _, err := w.Write([]byte(err.Error())); err != nil {
			log.Error(err)
		}

		return
	}

	certPEM, err := sql.authority.Sign(createRequest.PublicKey, pkix.Name{
		CommonName: "ephemeral-client-certificate",
	}, time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if _, err := w.Write([]byte(err.Error())); err != nil {
			log.Error(err)
		}

		return
	}

	respBytes, err := json.Marshal(&sqladmin.SslCert{
		Cert: certPEM,
	})
	if err != nil {
		log.Error(err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(respBytes); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) revokeCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	sql.authority.RevokeAll()

	sql.dbProxy.CloseAll()

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte("OK")); err != nil {
		log.Error(err)
	}
}
