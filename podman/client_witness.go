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

type WitnessClient struct{}

func NewWitnessClient() *WitnessClient {
	return &WitnessClient{}
}

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

// AttestBuild wraps buildFn with in-toto witness attestation.
func (c *WitnessClient) AttestBuild(
	ctx context.Context,
	opts WitnessRunOpts,
	buildFn func() error,
) error {
	tflog.Info(ctx, "Creating witness attestation for build", map[string]any{
		"step_name":   opts.StepName,
		"output_path": opts.OutputPath,
	})

	keyFile, err := os.Open(opts.SignerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open signer key %s: %w", opts.SignerKeyPath, err)
	}
	defer keyFile.Close()

	signer, err := witnessCrypto.NewSignerFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load signer key: %w", err)
	}

	attestors := []attestation.Attestor{
		material.New(),
		product.New(),
		commandrun.New(
			commandrun.WithCommand([]string{"podman-provider", "build"}),
		),
	}

	attCtx, err := attestation.NewContext(opts.StepName, attestors)
	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	if attestErr := attCtx.RunAttestors(); attestErr != nil {
		tflog.Warn(
			ctx,
			"Pre-attestation collection warning",
			map[string]any{"error": attestErr.Error()},
		)
	}

	if buildErr := buildFn(); buildErr != nil {
		return fmt.Errorf("build failed during attestation: %w", buildErr)
	}

	completed := attCtx.CompletedAttestors()
	subjects := collectSubjects(completed)

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

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("failed to marshal in-toto statement: %w", err)
	}

	envelope, err := dsse.Sign(
		intoto.PayloadType,
		bytes.NewReader(statementBytes),
		dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(&simpleTimestamper{}),
	)
	if err != nil {
		return fmt.Errorf("failed to sign attestation envelope: %w", err)
	}

	if dir := filepath.Dir(opts.OutputPath); dir != "" {
		mkdirErr := os.MkdirAll(dir, 0o755)
		if mkdirErr != nil {
			return fmt.Errorf("failed to create attestation output directory %s: %w", dir, mkdirErr)
		}
	}

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

type simpleTimestamper struct{}

func (simpleTimestamper) Timestamp(_ context.Context, _ io.Reader) ([]byte, error) {
	return time.Now().UTC().MarshalBinary()
}

var _ timestamp.Timestamper = (*simpleTimestamper)(nil)

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
