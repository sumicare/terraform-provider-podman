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
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/attestation/sbom"
	witnessCrypto "github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/invopop/jsonschema"
)

type WitnessClient struct{}

func NewWitnessClient() *WitnessClient {
	return &WitnessClient{}
}

type WitnessRunOpts struct {
	StepName         string
	SignerKeyPath    string
	Passphrase       string
	OutputPath       string
	ArchivistaServer string
	WorkingDir       string
	Attestors        []string
	ExportSLSA       bool
	EnableArchivista bool
}

// AttestBuild wraps buildFn with in-toto witness attestation.
// The attestation collects:
//   - environment: OS, hostname, user (build environment provenance)
//   - git: commit hash, branch, remotes (source provenance)
//   - material: file digests in build context before the build
//   - buildrun: the actual podman image build (execute phase)
//   - product: file digests after the build (captures SBOM output)
//   - sbom: parses any CycloneDX/SPDX products into the attestation
func (c *WitnessClient) AttestBuild(
	ctx context.Context,
	opts WitnessRunOpts,
	buildFn func() error,
) error {
	tflog.Info(ctx, "Creating witness attestation for build", map[string]any{
		"step_name":   opts.StepName,
		"output_path": opts.OutputPath,
		"working_dir": opts.WorkingDir,
	})

	keyFile, err := os.Open(opts.SignerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open signer key %s: %w", opts.SignerKeyPath, err)
	}
	defer keyFile.Close()

	parsedKey, err := witnessCrypto.TryParseKeyFromReaderWithPassword(keyFile, []byte(opts.Passphrase))
	if err != nil {
		return fmt.Errorf("failed to load signer key: %w", err)
	}

	signer, err := witnessCrypto.NewSigner(parsedKey)
	if err != nil {
		return fmt.Errorf("failed to create signer from key: %w", err)
	}

	attestors := []attestation.Attestor{
		environment.New(),
		git.New(),
		material.New(),
		&buildRunAttestor{fn: buildFn},
		product.New(),
		sbom.NewSBOMAttestor(),
	}

	attCtx, err := attestation.NewContext(
		opts.StepName,
		attestors,
		attestation.WithWorkingDir(opts.WorkingDir),
	)
	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	if attestErr := attCtx.RunAttestors(); attestErr != nil {
		tflog.Warn(ctx, "Attestor collection warning",
			map[string]any{"error": attestErr.Error()})
	}

	// Filter out errored attestors for the collection. Execute-phase
	// failures (e.g. the build itself) are fatal — we must not produce
	// an attestation for a failed build.
	var successful []attestation.CompletedAttestor
	for _, ca := range attCtx.CompletedAttestors() {
		if ca.Error != nil {
			if ca.Attestor.RunType() == attestation.ExecuteRunType {
				return fmt.Errorf("build attestor %q failed: %w", ca.Attestor.Name(), ca.Error)
			}

			tflog.Warn(ctx, "Attestor failed (excluded from collection)",
				map[string]any{"attestor": ca.Attestor.Name(), "error": ca.Error.Error()})
			continue
		}
		successful = append(successful, ca)
	}

	collection := attestation.NewCollection(opts.StepName, successful)

	predicate, err := json.Marshal(collection)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation collection: %w", err)
	}

	statement, err := intoto.NewStatement(
		attestation.CollectionType,
		predicate,
		collection.Subjects(),
	)
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
		"output_path":    opts.OutputPath,
		"attestor_count": len(successful),
		"subject_count":  len(collection.Subjects()),
	})

	return nil
}

type simpleTimestamper struct{}

func (simpleTimestamper) Timestamp(_ context.Context, _ io.Reader) ([]byte, error) {
	return time.Now().UTC().MarshalBinary()
}

var _ timestamp.Timestamper = (*simpleTimestamper)(nil)

// buildRunAttestor is a custom Execute-phase attestor that wraps a Go
// function instead of shelling out to a CLI command. This lets the
// attestation context run material → build → product in the correct order.
type buildRunAttestor struct {
	fn       func() error
	ExitCode int `json:"exitcode"`
}

const (
	buildRunName = "buildrun"
	buildRunType = "https://witness.dev/attestations/buildrun/v0.1"
)

func (b *buildRunAttestor) Name() string                 { return buildRunName }
func (b *buildRunAttestor) Type() string                 { return buildRunType }
func (b *buildRunAttestor) RunType() attestation.RunType { return attestation.ExecuteRunType }
func (b *buildRunAttestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(b) }
func (b *buildRunAttestor) Attest(_ *attestation.AttestationContext) error {
	if b.fn == nil {
		return nil
	}
	if err := b.fn(); err != nil {
		b.ExitCode = 1
		return fmt.Errorf("build failed during attestation: %w", err)
	}
	return nil
}
