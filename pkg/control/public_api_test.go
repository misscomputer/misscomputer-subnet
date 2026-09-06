// SPDX-License-Identifier: AGPL-3.0-only

package control_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/control"
)

func TestProberExportsNoChallengeCaptureSeam(t *testing.T) {
	typeOfProber := reflect.TypeOf(control.Prober{})
	if field, exists := typeOfProber.FieldByName("Probe"); exists && field.PkgPath == "" {
		t.Fatalf("control.Prober exports a probe injection field carrying the raw challenge: %v", field.Type)
	}
	for index := 0; index < typeOfProber.NumField(); index++ {
		field := typeOfProber.Field(index)
		if field.PkgPath == "" && field.Type.Kind() == reflect.Interface {
			if _, exists := field.Type.MethodByName("ProbeReplica"); exists {
				t.Fatalf("exported field %q exposes a targeted probe callback", field.Name)
			}
		}
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate public API guard source")
	}
	packages, err := parser.ParseDir(token.NewFileSet(), filepath.Dir(currentFile), func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range packages["control"].Files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec := specification.(*ast.TypeSpec)
				if typeSpec.Name.Name == "ReplicaProber" && typeSpec.Name.IsExported() {
					t.Fatal("control exports ReplicaProber")
				}
				interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
				if !ok || !typeSpec.Name.IsExported() {
					continue
				}
				for _, method := range interfaceType.Methods.List {
					for _, name := range method.Names {
						if name.Name == "ProbeReplica" && name.IsExported() {
							t.Fatalf("exported interface %q exposes ProbeReplica", typeSpec.Name.Name)
						}
					}
				}
			}
		}
	}
}
