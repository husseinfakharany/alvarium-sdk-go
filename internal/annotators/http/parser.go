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
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type signatureInfo struct {
	seed      string
	signature string
	keyid     string
	algorithm string
}

func RemoveExtraSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func requestParser(r *http.Request) signatureInfo {

	//Signature Inputs extraction
	var rgx = regexp.MustCompile(`\((.*?)\)`)
	signatureInput := r.Header.Get("Signature-Input")
	signature := r.Header.Get("Signature")

	rs := rgx.FindStringSubmatch(signatureInput)
	signatureInputList := strings.Split(rs[1], " ")

	signatureInputFields := make(map[string][]string)
	var keyid, algorithm string

	signatureInputParsedSection := strings.Split(signatureInput, ";")
	for _, s := range signatureInputParsedSection {

		if strings.Contains(s, "alg") {
			algorithm_raw := strings.Split(s, "=")[1]
			algorithm = strings.Trim(algorithm_raw, "\"")
		}

		if strings.Contains(s, "key") {
			keyid_raw := strings.Split(s, "=")[1]
			keyid = strings.Trim(keyid_raw, "\"")
		}

	}

	parsedSignatureInput := ""

	for _, field := range signatureInputList {
		//remove double quotes from the field to access it directly in the header map
		key := field[1 : len(field)-1]
		if key[0:1] == "@" {
			switch specialtyComponent(key) {
			case method:
				signatureInputFields[key] = []string{r.Method}
			case authority:
				signatureInputFields[key] = []string{r.Host}
			case scheme:
				protool := r.Proto
				scheme := strings.ToLower(strings.Split(protool, "/")[0])
				signatureInputFields[key] = []string{scheme}
			case requestTarget:
				signatureInputFields[key] = []string{r.RequestURI}
			case path:
				signatureInputFields[key] = []string{r.URL.Path}
			case query:
				var query string = "?"
				query += r.URL.RawQuery
				signatureInputFields[key] = []string{query}
			case queryParams:
				queryParamsRawMap := r.URL.Query()
				var queryParams []string
				for key, value := range queryParamsRawMap {
					b := new(bytes.Buffer)
					fmt.Fprintf(b, ";name=\"%s\": %s", key, value[0])
					queryParams = append(queryParams, b.String())
				}

				signatureInputFields[key] = queryParams
			default:
				fmt.Errorf("Unhandled Specialty Component %s", key)
			}
		} else {
			fieldValues := r.Header.Values(key)

			if len(fieldValues) == 1 {
				value := RemoveExtraSpaces(r.Header.Get(key))
				signatureInputFields[key] = []string{value}

			} else {

				value := ""
				for i := 0; i < len(fieldValues); i++ {
					value += fieldValues[i]
					if i != (len(fieldValues) - 1) {
						value += ", "
					}
				}
				value = RemoveExtraSpaces(value)
				signatureInputFields[key] = []string{value}
			}
		}
		// Construct final output string
		keyValues := signatureInputFields[key]
		if len(keyValues) == 1 {
			parsedSignatureInput += ("\"" + key + "\": " + keyValues[0] + "\n")
		} else {
			for _, v := range keyValues {
				parsedSignatureInput += ("\"" + key + "\"" + v + "\n")
			}
		}
	}

	//remove signature name
	index := strings.Index(signatureInput, "=")
	signatureInput = signatureInput[index+1:]
	index = strings.Index(signature, ":")
	signature = signature[index+1:]
	signature = signature[:len(signature)-1]

	// check if the new line needs to be removed from the end
	parsedSignatureInput += ("\"@signature-params\": " + signatureInput + "\n")
	s := signatureInfo{seed: parsedSignatureInput, signature: signature, keyid: keyid, algorithm: algorithm}
	return s
}
