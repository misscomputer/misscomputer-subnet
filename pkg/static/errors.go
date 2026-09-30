// SPDX-License-Identifier: AGPL-3.0-only

package static

import (
	"errors"
	"fmt"
	"syscall"
)

// Code is the static-deployment-receipt v1 error_code vocabulary
// (static-site contract §8.3). The values are wire strings.
type Code string

const (
	CodeFetchFailed                  Code = "static_fetch_failed"
	CodeVerifyFailed                 Code = "static_verify_failed"
	CodeStorageExhausted             Code = "static_storage_exhausted"
	CodeServerImplementationMismatch Code = "static_server_implementation_mismatch"
	CodeManifestInvalid              Code = "static_manifest_invalid"
	CodeLimitsExceeded               Code = "static_limits_exceeded"
	CodeDeactivated                  Code = "deactivated"
	CodeInternal                     Code = "internal"
)

// ReceiptErrorAttribution is the frozen attribution of every static receipt
// error_code. Verified bound content that is itself invalid can only be
// caused by the platform ("unknown"); none of these codes is fraud.
var ReceiptErrorAttribution = map[string]string{
	string(CodeFetchFailed):                  "miner",
	string(CodeVerifyFailed):                 "miner",
	string(CodeStorageExhausted):             "miner",
	string(CodeServerImplementationMismatch): "miner",
	string(CodeManifestInvalid):              "unknown",
	string(CodeLimitsExceeded):               "unknown",
	string(CodeDeactivated):                  "none",
	string(CodeInternal):                     "miner",
}

// Error carries a receipt error code with its diagnostic cause.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// Fail wraps err with code unless it already carries one; ENOSPC anywhere
// is storage exhaustion.
func Fail(code Code, err error) error {
	var existing *Error
	if errors.As(err, &existing) {
		return err
	}
	if errors.Is(err, syscall.ENOSPC) {
		code = CodeStorageExhausted
	}
	return &Error{Code: code, Err: err}
}

func failf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// CodeOf returns the code carried by err, or internal.
func CodeOf(err error) Code {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return CodeInternal
}
