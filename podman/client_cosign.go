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
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	cosignAttest "github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cosignSign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

// CosignClient wraps the cosign Go library for image signing and attestation.
type CosignClient struct{}

// NewCosignClient creates a new CosignClient.
func NewCosignClient() *CosignClient {
	return &CosignClient{}
}

// SignOpts holds parameters for signing an image with cosign.
type SignOpts struct {
	ImageRef  string
	KeyPath   string
	Password  string //nolint:gosec // Password is only used for cosign key encryption, not a secret leak
	FulcioURL string
	RekorURL  string
	Keyless   bool
}

// AttestOpts holds parameters for attaching an attestation to an image.
type AttestOpts struct {
	ImageRef      string
	KeyPath       string
	Password      string //nolint:gosec // Password is only used for cosign key encryption, not a secret leak
	FulcioURL     string
	RekorURL      string
	PredicatePath string
	PredicateType string
	Keyless       bool
}

// SignImage signs an OCI image using cosign (key-based or keyless).
func (c *CosignClient) SignImage(ctx context.Context, opts SignOpts) error {
	tflog.Info(ctx, "Signing image with cosign", map[string]any{
		"image_ref": opts.ImageRef,
		"keyless":   opts.Keyless,
	})

	if opts.Password != "" {
		if err := os.Setenv("COSIGN_PASSWORD", opts.Password); err != nil {
			return fmt.Errorf("failed to set COSIGN_PASSWORD: %w", err)
		}

		defer os.Unsetenv("COSIGN_PASSWORD") //nolint:errcheck // best-effort cleanup
	}

	ko := options.KeyOpts{
		SkipConfirmation: true,
	}

	signOpts := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	if opts.Keyless {
		if opts.FulcioURL != "" {
			ko.FulcioURL = opts.FulcioURL
		}

		if opts.RekorURL != "" {
			ko.RekorURL = opts.RekorURL
			signOpts.Rekor.URL = opts.RekorURL
		}
	} else {
		ko.KeyRef = opts.KeyPath
		signOpts.TlogUpload = false
	}

	ro := &options.RootOptions{}

	err := cosignSign.SignCmd(ro, ko, signOpts, []string{opts.ImageRef})
	if err != nil {
		return fmt.Errorf("cosign sign failed for %s: %w", opts.ImageRef, err)
	}

	return nil
}

// AttestImage attaches an in-toto attestation to an OCI image using cosign attest.
func (c *CosignClient) AttestImage(ctx context.Context, opts AttestOpts) error {
	tflog.Info(ctx, "Attaching attestation to image", map[string]any{
		"image_ref":      opts.ImageRef,
		"predicate_path": opts.PredicatePath,
		"predicate_type": opts.PredicateType,
	})

	if opts.Password != "" {
		if err := os.Setenv("COSIGN_PASSWORD", opts.Password); err != nil {
			return fmt.Errorf("failed to set COSIGN_PASSWORD: %w", err)
		}

		defer os.Unsetenv("COSIGN_PASSWORD") //nolint:errcheck // best-effort cleanup
	}

	predicateType := opts.PredicateType
	if predicateType == "" {
		predicateType = "custom"
	}

	cmd := &cosignAttest.AttestCommand{
		KeyOpts: options.KeyOpts{
			SkipConfirmation: true,
		},
		PredicatePath: opts.PredicatePath,
		PredicateType: predicateType,
		TlogUpload:    true,
	}

	if opts.Keyless {
		if opts.FulcioURL != "" {
			cmd.FulcioURL = opts.FulcioURL
		}

		if opts.RekorURL != "" {
			cmd.RekorURL = opts.RekorURL
		}
	} else {
		cmd.KeyRef = opts.KeyPath
		cmd.TlogUpload = false
	}

	err := cmd.Exec(ctx, opts.ImageRef)
	if err != nil {
		return fmt.Errorf("cosign attest failed for %s: %w", opts.ImageRef, err)
	}

	return nil
}

// GenerateKeyPairResult holds the paths and PEM bytes of a generated cosign key pair.
type GenerateKeyPairResult struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PrivateKeyPEM  []byte
	PublicKeyPEM   []byte
	Reused         bool
}

// EnsureKeyPair returns an existing cosign key pair from dir if both
// cosign.key and cosign.pub already exist, otherwise generates a new
// ECDSA key pair (with an empty password) and writes it there.
// This allows multiple resources in the same root module to share a
// single auto-generated key.
func (c *CosignClient) EnsureKeyPair(
	ctx context.Context,
	dir string,
) (*GenerateKeyPairResult, error) {
	privPath := filepath.Join(dir, "cosign.key")
	pubPath := filepath.Join(dir, "cosign.pub")

	// Reuse existing key pair if both files are present.
	privBytes, privErr := os.ReadFile(privPath)
	pubBytes, pubErr := os.ReadFile(pubPath)

	if privErr == nil && pubErr == nil && len(privBytes) > 0 && len(pubBytes) > 0 {
		tflog.Info(ctx, "Reusing existing cosign key pair", map[string]any{
			"private_key": privPath,
			"public_key":  pubPath,
		})

		return &GenerateKeyPairResult{
			PrivateKeyPath: privPath,
			PublicKeyPath:  pubPath,
			PrivateKeyPEM:  privBytes,
			PublicKeyPEM:   pubBytes,
			Reused:         true,
		}, nil
	}

	// Generate a new key pair.
	tflog.Info(ctx, "Generating cosign key pair", map[string]any{"dir": dir})

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create key output directory %s: %w", dir, err)
	}

	keys, err := cosign.GenerateKeyPair(func(_ bool) ([]byte, error) {
		return []byte(""), nil
	})
	if err != nil {
		return nil, fmt.Errorf("cosign key pair generation failed: %w", err)
	}

	if writeErr := os.WriteFile(privPath, keys.PrivateBytes, 0o600); writeErr != nil {
		return nil, fmt.Errorf("failed to write private key to %s: %w", privPath, writeErr)
	}

	if writeErr := os.WriteFile(pubPath, keys.PublicBytes, 0o600); writeErr != nil {
		return nil, fmt.Errorf("failed to write public key to %s: %w", pubPath, writeErr)
	}

	tflog.Info(ctx, "Cosign key pair generated", map[string]any{
		"private_key": privPath,
		"public_key":  pubPath,
	})

	return &GenerateKeyPairResult{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		PrivateKeyPEM:  keys.PrivateBytes,
		PublicKeyPEM:   keys.PublicBytes,
		Reused:         false,
	}, nil
}
