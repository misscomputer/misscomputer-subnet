// SPDX-License-Identifier: AGPL-3.0-only

// Package service contains shared process-level safety helpers for the Go
// neuron bridge daemons.
package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func LoadOrCreateSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("service signing key path is required")
	}
	payload, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, fmt.Errorf("stat service signing key: %w", statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("service signing key file must not be group/world accessible")
		}
		decoded, decodeErr := hex.DecodeString(strings.TrimSpace(string(payload)))
		if decodeErr != nil || len(decoded) != ed25519.PrivateKeySize {
			return nil, errors.New("service signing key file is invalid")
		}
		return ed25519.PrivateKey(decoded), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read service signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create service key directory: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".service-key-*")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.WriteString(hex.EncodeToString(privateKey)); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func ValidateBind(address string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid bind address: %w", err)
	}
	if allowNonLoopback {
		return nil
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("refusing non-loopback bridge bind without explicit override")
	}
	return nil
}
