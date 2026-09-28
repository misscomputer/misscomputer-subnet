// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"errors"
	"strings"
)

// FailureCode is the receipt v4 error_code vocabulary (contract §6.7). The
// scheduler derives attribution from the code, so the exact strings are wire
// values.
type FailureCode string

const (
	CodeArtifactFetchFailed    FailureCode = "artifact_fetch_failed"
	CodeArtifactVerifyFailed   FailureCode = "artifact_verify_failed"
	CodeImageLoadFailed        FailureCode = "image_load_failed"
	CodeImageIdentityMismatch  FailureCode = "image_identity_mismatch"
	CodeContainerCreateFailed  FailureCode = "container_create_failed"
	CodeContainerExited        FailureCode = "container_exited"
	CodeHealthTimeout          FailureCode = "health_timeout"
	CodeHealthUnexpectedStatus FailureCode = "health_unexpected_status"
	CodeHealthMarkerMissing    FailureCode = "health_marker_missing"
	CodeResourceExhausted      FailureCode = "resource_exhausted"
	CodeDeactivated            FailureCode = "deactivated"
	CodeInternal               FailureCode = "internal"
)

// Failure carries a receipt error code with its diagnostic cause.
type Failure struct {
	Code FailureCode
	Err  error
}

func (f *Failure) Error() string {
	if f.Err == nil {
		return string(f.Code)
	}
	return string(f.Code) + ": " + f.Err.Error()
}

func (f *Failure) Unwrap() error { return f.Err }

// Fail wraps err with code unless err already carries a code.
func Fail(code FailureCode, err error) error {
	var existing *Failure
	if errors.As(err, &existing) {
		return err
	}
	return &Failure{Code: code, Err: err}
}

// FailureCodeOf returns the code carried by err, or internal.
func FailureCodeOf(err error) FailureCode {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return CodeInternal
}

// ReceiptError renders a receipt error string: printable ASCII only and at
// most 512 bytes. Callers never pass container output here.
func ReceiptError(err error) string {
	if err == nil {
		return ""
	}
	var builder strings.Builder
	for _, char := range err.Error() {
		if char < 0x20 || char > 0x7e {
			char = '?'
		}
		builder.WriteRune(char)
		if builder.Len() >= 512 {
			break
		}
	}
	return builder.String()
}
