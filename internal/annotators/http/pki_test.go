/*******************************************************************************
 * Copyright 2022 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/project-alvarium/alvarium-sdk-go/internal/annotators"
	"github.com/project-alvarium/alvarium-sdk-go/pkg/config"
	"github.com/project-alvarium/alvarium-sdk-go/test"
	"github.com/stretchr/testify/assert"
)

func TestHttpPkiAnnotator_Do(t *testing.T) {
	b, err := ioutil.ReadFile("../../../test/res/config.json")
	if err != nil {
		t.Fatalf(err.Error())
	}

	var cfg config.SdkInfo
	err = json.Unmarshal(b, &cfg)

	if err != nil {
		t.Fatalf(err.Error())
	}

	//Redefining the paths for the public and the private key as this test file is in a subfolder of the annotators folder
	cfg.Signature.PublicKey.Path = "../../../test/keys/ed25519/public.key"
	cfg.Signature.PrivateKey.Path = "../../../test/keys/ed25519/private.key"

	badKeyType := cfg
	badKeyType.Signature.PublicKey.Type = "invalid"

	keyNotFound := cfg
	keyNotFound.Signature.PublicKey.Path = "/dev/null/private.key"

	//This is an example of a test request
	req1 := httptest.NewRequest("POST", "/foo", nil)

	req1.Header.Set("Host", "example.com")
	req1.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Content-Length", "18")
	req1.Header.Set("Signature-Input", "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"")
	req1.Header.Set("Signature", "sig-b26=:b0e259eefdae116021f5ef58cb19bf34fce74163bbb2d22226cd662088423e39036437c0e80c7b7361633c6b2f147c93122fdf47d06976e405ce7b4cae0b0200:")

	//Call the parser on the request to sign its result
	signatureInfo := requestParser(req1)

	t.Run("parser_test", func(t *testing.T) {
		expectedSeed := "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"\n"
		assert.Equal(t, expectedSeed, signatureInfo.seed)
	})

	// signer := ed25519.New()

	// Set up example signed data type for test purposes

	// prv, err := ioutil.ReadFile(cfg.Signature.PrivateKey.Path)
	// if err != nil {
	// 	t.Fatalf(err.Error())
	// }

	// t1.Signature = signer.Sign(prv, []byte(t1.Seed))

	// fmt.Printf("t1.Seed: %v\n", t1.Seed)
	//fmt.Printf("t1.Signature: %v\n", t1.Signature)
	// t.Log(t1.Signature)
	// end of basic example type setup

	req2 := httptest.NewRequest("POST", "/foo", nil)
	req2.Header.Set("Signature", "")

	req3 := httptest.NewRequest("POST", "/foo", nil)
	req3.Header.Set("Signature-Input", "")

	tests := []struct {
		name        string
		req         *http.Request
		cfg         config.SdkInfo
		expectError bool
	}{
		{"pki annotation OK", req1, cfg, false},
		{"pki bad key type", req1, badKeyType, true},
		{"pki key not found", req1, keyNotFound, true},
		// {"pki empty signature", req2, cfg, false},
		// {"pki invalid signature", req3, cfg, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(tt.req.Context(), "testData", tt.req)
			tpm := NewHttpPkiAnnotator(tt.cfg)
			anno, err := tpm.Do(ctx, nil)
			fmt.Printf("err: %v\n", err)
			t.Log(anno)
			test.CheckError(err, tt.expectError, tt.name, t)
			if err == nil {
				result, err := annotators.VerifySignature(tt.cfg.Signature.PublicKey, anno)
				if err != nil {
					t.Error(err.Error())
				} else if !result {
					t.Error("signature not verified")
				}
				if tt.name == "pki empty signature" || tt.name == "pki invalid signature" {
					if anno.IsSatisfied {
						t.Errorf("satisfied should be false")
					}
				}
			}
		})
	}
}
