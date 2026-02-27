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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	witnessCrypto "github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/timestamp"
)

// WitnessClient wraps the go-witness library for in-toto attestation.
type WitnessClient struct{}

// NewWitnessClient creates a new WitnessClient.
func NewWitnessClient() *WitnessClient {
	return &WitnessClient{}
}

// WitnessRunOpts holds parameters for creating a witness attestation around a build.
type WitnessRunOpts struct {
	StepName         string
	SignerKeyPath    string
	OutputPath       string
	ArchivistaServer string
	WorkingDir       string
	Attestors        []string
	ExportSLSA       bool
	EnableArchivista bool
}

// AttestBuild wraps a build function with in-toto witness attestation,
// recording materials before and products after the build.
func (c *WitnessClient) AttestBuild(
	ctx context.Context,
	opts WitnessRunOpts,
	buildFn func() error,
) error {
	tflog.Info(ctx, "Creating witness attestation for build", map[string]any{
		"step_name":   opts.StepName,
		"output_path": opts.OutputPath,
	})

	// Load the signing key
	keyFile, err := os.Open(opts.SignerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open signer key %s: %w", opts.SignerKeyPath, err)
	}
	defer keyFile.Close()

	signer, err := witnessCrypto.NewSignerFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load signer key: %w", err)
	}

	// Initialize attestors
	attestors := []attestation.Attestor{
		material.New(),
		product.New(),
		commandrun.New(
			commandrun.WithCommand([]string{"podman-provider", "build"}),
		),
	}

	// Create attestation context with attestors as second argument
	attCtx, err := attestation.NewContext(opts.StepName, attestors)
	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	// Run attestor collection (no arguments)
	if attestErr := attCtx.RunAttestors(); attestErr != nil {
		tflog.Warn(
			ctx,
			"Pre-attestation collection warning",
			map[string]any{"error": attestErr.Error()},
		)
	}

	// Execute the actual build
	if buildErr := buildFn(); buildErr != nil {
		return fmt.Errorf("build failed during attestation: %w", buildErr)
	}

	// Collect subjects from completed attestors
	completed := attCtx.CompletedAttestors()
	subjects := collectSubjects(completed)

	// Create the in-toto statement with predicate
	predicate, err := json.Marshal(map[string]any{
		"buildType": "podman-provider",
		"builder":   map[string]string{"id": "sumicare-provider-podman"},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal predicate: %w", err)
	}

	statement, err := intoto.NewStatement(intoto.PayloadType, predicate, subjects)
	if err != nil {
		return fmt.Errorf("failed to create in-toto statement: %w", err)
	}

	// Serialize statement as the DSSE body
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("failed to marshal in-toto statement: %w", err)
	}

	// Create DSSE envelope
	envelope, err := dsse.Sign(
		intoto.PayloadType,
		bytes.NewReader(statementBytes),
		dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(&simpleTimestamper{}),
	)
	if err != nil {
		return fmt.Errorf("failed to sign attestation envelope: %w", err)
	}

	// Ensure output directory exists
	if dir := filepath.Dir(opts.OutputPath); dir != "" {
		mkdirErr := os.MkdirAll(dir, 0o755)
		if mkdirErr != nil {
			return fmt.Errorf("failed to create attestation output directory %s: %w", dir, mkdirErr)
		}
	}

	// Write envelope to output path
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation envelope: %w", err)
	}

	if writeErr := os.WriteFile( //nolint:gosec // OutputPath is user-provided destination for attestation output
		opts.OutputPath,
		envelopeBytes,
		0o600,
	); writeErr != nil {
		return fmt.Errorf("failed to write attestation to %s: %w", opts.OutputPath, writeErr)
	}

	tflog.Info(ctx, "Witness attestation created", map[string]any{
		"output_path": opts.OutputPath,
	})

	return nil
}

// simpleTimestamper implements timestamp.Timestamper for DSSE signing.
type simpleTimestamper struct{}

func (simpleTimestamper) Timestamp(_ context.Context, _ io.Reader) ([]byte, error) {
	return time.Now().UTC().MarshalBinary()
}

// ensure simpleTimestamper implements the interface.
var _ timestamp.Timestamper = (*simpleTimestamper)(nil)

// collectSubjects extracts subject digests from completed attestors.
func collectSubjects(
	completedAttestors []attestation.CompletedAttestor,
) map[string]witnessCrypto.DigestSet {
	subjects := make(map[string]witnessCrypto.DigestSet)

	for _, a := range completedAttestors {
		if subjecter, ok := a.Attestor.(attestation.Subjecter); ok {
			maps.Copy(subjects, subjecter.Subjects())
		}
	}

	return subjects
}
