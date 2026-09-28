// SPDX-License-Identifier: AGPL-3.0-only

// Package assignment holds the canonical JSON encoding shared by the signed
// assignment documents (deployment.v4 digests and active-assignment-manifest
// v2) and the Python contracts.
package assignment

import (
	"bytes"
	"encoding/json"
	"errors"
)

// CanonicalJSON renders any JSON-encodable value as the sorted-key, compact,
// ASCII-only encoding shared with the Python contracts (no trailing newline).
func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(generic); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	for _, b := range out {
		if b > 0x7f {
			return nil, errors.New("canonical json must be ascii")
		}
	}
	return out, nil
}
