package util_test

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
	"testing"

	"github.com/db-operator/db-auth-gateway/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestParseInstance(t *testing.T) {
	instance := "kloeckner-i:europe-west3:example-db"
	expected := map[string]string{
		"project": "kloeckner-i",
		"region":  "europe-west3",
		"name":    "example-db",
	}

	actual, err := util.ParseInstance(instance)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, actual)
}

func TestParseMalformedInstance(t *testing.T) {
	instance := "kloeckner-i:europe-west3_example-db"

	_, err := util.ParseInstance(instance)

	assert.NotNil(t, err)
}
