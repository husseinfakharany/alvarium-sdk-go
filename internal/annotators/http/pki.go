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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/project-alvarium/alvarium-sdk-go/internal/annotators"
	"github.com/project-alvarium/alvarium-sdk-go/internal/signprovider"
	"github.com/project-alvarium/alvarium-sdk-go/internal/signprovider/ed25519"
	"github.com/project-alvarium/alvarium-sdk-go/pkg/config"
	"github.com/project-alvarium/alvarium-sdk-go/pkg/contracts"
	"github.com/project-alvarium/alvarium-sdk-go/pkg/interfaces"
)

// HttpPkiAnnotator is used to validate whether the signature on a given piece of data is valid, both sent in the HTTP message
type HttpPkiAnnotator struct {
	hash contracts.HashType
	kind contracts.AnnotationType
	sign config.SignatureInfo
}

func NewHttpPkiAnnotator(cfg config.SdkInfo) interfaces.Annotator {
	a := HttpPkiAnnotator{}
	a.hash = cfg.Hash.Type
	a.kind = contracts.AnnotationPKIHttp
	a.sign = cfg.Signature
	return &a
}

func (a *HttpPkiAnnotator) Do(ctx context.Context, data []byte) (contracts.Annotation, error) {
	key := annotators.DeriveHash(a.hash, data)
	hostname, _ := os.Hostname()

	//Call parser on request
	req := ctx.Value("testData")
	signatureInfo := requestParser(req.(*http.Request))

	var sig signable
	sig.Seed = signatureInfo.seed
	sig.Signature = signatureInfo.signature

	// var k keyInfo
	// k.ID = signatureInfo.keyid
	// k.Type = signatureInfo.algorithm

	ok, err := sig.verifySignature(a.sign.PublicKey)
	if err != nil {
		return contracts.Annotation{}, err
	}

	annotation := contracts.NewAnnotation(string(key), a.hash, hostname, a.kind, ok)
	signed, err := annotators.SignAnnotation(a.sign.PrivateKey, annotation)

	if err != nil {
		return contracts.Annotation{}, err
	}
	annotation.Signature = string(signed)
	return annotation, nil
}

type signable struct {
	Seed      string
	Signature string
}

type keyInfo struct {
	ID   string
	Type string
}

func (s *signable) verifySignature(key config.KeyInfo) (bool, error) {
	if len(s.Signature) == 0 { // no signature detected
		return false, nil
	}
	var p signprovider.Provider
	//switch contracts.KeyAlgorithm(key.Type) {
	switch key.Type {
	case contracts.KeyEd25519:
		p = ed25519.New()

	// New case to match the one sent in the 'alg' params in the http message,
	// redirects to the same algorithm used in the regular pki annotator for now
	// we may want to change this in the future and implement the ECDsaP256
	case contracts.KeyECDsaP256:
		p = ed25519.New()
	default:
		return false, fmt.Errorf("unreczed key type %s", key.Type)
	}
	// Path can change from one enviroment to another
	// When using Kubernetes, we can search for the keyid directly in the secrets folder, as all keys can be stored there
	//keyPath := "../../../test/keys/ed25519/public.key"
	pub, err := ioutil.ReadFile(key.Path)
	if err != nil {
		return false, err
	}
	fmt.Printf("s.Signature: %v\n", s.Signature)
	ok := p.Verify(pub, []byte(s.Seed), []byte(s.Signature))
	return ok, nil
}
