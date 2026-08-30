// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestIntegrationSourceHasNoInfrastructureChainWalletOrApplyCapability(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbiddenImports := []string{
		"net/http", "os/exec", "database/sql", "github.com/cloud" + "flare", "bittensor", "/pkg/neuron",
		"/pkg/remote", "/pkg/bridge", "/pkg/service", "/pkg/edge", "/pkg/tunnel",
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Decls {
			declaration, ok := spec.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, item := range declaration.Specs {
				importSpec, ok := item.(*ast.ImportSpec)
				if !ok {
					continue
				}
				value, err := strconv.Unquote(importSpec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range forbiddenImports {
					if strings.Contains(value, forbidden) {
						t.Fatalf("%s imports forbidden campaign capability %q", path, value)
					}
				}
			}
		}
	}
}
