/*











































   Copyright 2026 Sumicare

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package podman

import (
	"io"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/timestamp"
)

func TestNewWitnessClient(t *testing.T) {
	client := NewWitnessClient()
	if client == nil {
		t.Error("expected non-nil WitnessClient")
	}
}

func TestWitnessRunOpts_Fields(t *testing.T) {
	opts := WitnessRunOpts{
		StepName:      "build-step",
		SignerKeyPath: "/path/to/key.pem",
		Attestors:     []string{"material", "product"},
	}

	if opts.StepName != "build-step" {
		t.Errorf("expected StepName build-step, got %s", opts.StepName)
	}

	if opts.SignerKeyPath != "/path/to/key.pem" {
		t.Errorf("expected SignerKeyPath /path/to/key.pem, got %s", opts.SignerKeyPath)
	}

	if len(opts.Attestors) != 2 {
		t.Errorf("expected 2 attestors, got %d", len(opts.Attestors))
	}
}

func TestSimpleTimestamper_Interface(t *testing.T) {
	var ts timestamp.Timestamper = &simpleTimestamper{}

	data, err := ts.Timestamp(t.Context(), io.NopCloser(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty timestamp data")
	}
}

func TestCollectSubjects_Empty(t *testing.T) {
	tests := []struct {
		name  string
		input []attestation.CompletedAttestor
	}{
		{"nil", nil},
		{"empty_slice", []attestation.CompletedAttestor{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subjects := collectSubjects(tt.input)
			if len(subjects) != 0 {
				t.Errorf("expected empty subjects, got %d", len(subjects))
			}
		})
	}
}

func TestAttestBuild_MissingKey(t *testing.T) {
	client := NewWitnessClient()

	err := client.AttestBuild(t.Context(), WitnessRunOpts{
		StepName:      "test-step",
		SignerKeyPath: "/nonexistent/key.pem",
		OutputPath:    "/tmp/test-attestation.json",
	}, func() error { return nil })
	if err == nil {
		t.Error("expected error for missing signer key")
	}

	if !strings.Contains(err.Error(), "failed to open signer key") {
		t.Errorf("expected 'failed to open signer key' in error, got: %s", err.Error())
	}
}
