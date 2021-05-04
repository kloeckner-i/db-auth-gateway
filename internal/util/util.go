package util

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
	"errors"
	"os"
	"regexp"
)

// mockAddressEnvVar is an environment variable that can be used to set the address of the Google API mock for
// testing. If not supplied db-auth-gateway defaults to localhost. This is typically only going to be required when
// running on the Gitlab CI.
const mockAddressEnvVar = "MOCK_ADDRESS"

// ErrInvalidDatabaseInstance is returned when a malformed database instance is supplied.
var ErrInvalidDatabaseInstance = errors.New("invalid database instance")

// ParseInstance is used to split the components out of a fully qualified database instance.
func ParseInstance(instance string) (map[string]string, error) {
	r := regexp.MustCompile(`^(?P<project>.+):(?P<region>.+):(?P<name>.+)$`)

	match := r.FindStringSubmatch(instance)

	if len(match) != r.NumSubexp()+1 {
		return nil, ErrInvalidDatabaseInstance
	}

	parsedInstance := make(map[string]string)

	for i, name := range r.SubexpNames() {
		if i != 0 && name != "" {
			parsedInstance[name] = match[i]
		}
	}

	return parsedInstance, nil
}

// GetMockAddress is used by the tests to determine the address of the Google API mock.
func GetMockAddress() string {
	mockAddress := os.Getenv(mockAddressEnvVar)
	if mockAddress == "" {
		return "127.0.0.1"
	}

	return mockAddress
}
