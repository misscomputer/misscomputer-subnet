// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"log"
	"net/http"
	"os"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func main() {
	layerPath := os.Getenv("WORKLOAD_LAYER")
	expectedDigest := os.Getenv("EXPECTED_LAYER_DIGEST")
	if layerPath == "" || expectedDigest == "" {
		log.Fatal("WORKLOAD_LAYER and EXPECTED_LAYER_DIGEST are required")
	}
	layer, err := os.ReadFile(layerPath)
	if err != nil {
		log.Fatalf("read verified workload layer: %v", err)
	}
	if got := artifact.Digest(layer); got != expectedDigest {
		log.Fatalf("workload layer digest mismatch: got %s want %s", got, expectedDigest)
	}
	spec, err := workload.Decode(layer)
	if err != nil {
		log.Fatalf("decode workload layer: %v", err)
	}
	log.Fatal(http.ListenAndServe(":8080", workload.Handler(spec)))
}
