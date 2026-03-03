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
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	cosignAttest "github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cosignSign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

type CosignClient struct{}

func NewCosignClient() *CosignClient {
	return &CosignClient{}
}

type SignOpts struct {
	ImageRef  string
	KeyPath   string
	Password  string //nolint:gosec // Password is only used for cosign key encryption, not a secret leak
	FulcioURL string
	RekorURL  string
	Keyless   bool
}

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

func (c *CosignClient) SignImage(ctx context.Context, opts SignOpts) error {
	tflog.Info(ctx, "Signing image with cosign", map[string]any{
		"image_ref": opts.ImageRef,
		"keyless":   opts.Keyless,
	})

	ko := options.KeyOpts{
		SkipConfirmation: true,
	}

	if opts.Password != "" {
		password := opts.Password
		ko.PassFunc = func(_ bool) ([]byte, error) {
			return []byte(password), nil
		}
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

type VerifyOpts struct {
	ImageRef string
	KeyPath  string
	RekorURL string
	SkipTlog bool
}

func (c *CosignClient) VerifyImage(ctx context.Context, opts VerifyOpts) error {
	tflog.Info(ctx, "Verifying image signature with cosign", map[string]any{
		"image_ref": opts.ImageRef,
		"key_path":  opts.KeyPath,
	})

	args := []string{"verify", "--key", opts.KeyPath}

	if opts.SkipTlog {
		args = append(args, "--insecure-ignore-tlog=true")
	}

	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}

	args = append(args, opts.ImageRef)

	cmd := exec.CommandContext(ctx, "cosign", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cosign verify failed for %s: %s: %w", opts.ImageRef, string(output), err)
	}

	tflog.Info(ctx, "Image signature verified successfully", map[string]any{
		"image_ref": opts.ImageRef,
	})

	return nil
}

func (c *CosignClient) AttestImage(ctx context.Context, opts AttestOpts) error {
	tflog.Info(ctx, "Attaching attestation to image", map[string]any{
		"image_ref":      opts.ImageRef,
		"predicate_path": opts.PredicatePath,
		"predicate_type": opts.PredicateType,
	})

	predicateType := opts.PredicateType
	if predicateType == "" {
		predicateType = "custom"
	}

	ko := options.KeyOpts{
		SkipConfirmation: true,
	}

	if opts.Password != "" {
		password := opts.Password
		ko.PassFunc = func(_ bool) ([]byte, error) {
			return []byte(password), nil
		}
	}

	cmd := &cosignAttest.AttestCommand{
		KeyOpts:       ko,
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

// passphraseFile is the name of the file inside the key directory that stores
// the random passphrase used to encrypt auto-generated cosign key pairs.
const passphraseFile = "PASSPHRASE"

// passphraseLength is the number of random printable ASCII characters.
const passphraseLength = 32

type GenerateKeyPairResult struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PrivateKeyPEM  []byte
	PublicKeyPEM   []byte
	Passphrase     string
	Reused         bool
}

// ensurePassphrase reads an existing passphrase from dir/PASSPHRASE or generates
// a new random ASCII passphrase, writes it with 0600 permissions, and returns it.
func ensurePassphrase(dir string) (string, error) {
	path := filepath.Join(dir, passphraseFile)

	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		return strings.TrimRight(string(data), "\n\r"), nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create key directory %s: %w", dir, err)
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"

	buf := make([]byte, passphraseLength)

	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random passphrase: %w", err)
		}

		buf[i] = charset[n.Int64()]
	}

	passphrase := string(buf)

	if err := os.WriteFile(path, []byte(passphrase), 0o600); err != nil {
		return "", fmt.Errorf("failed to write passphrase to %s: %w", path, err)
	}

	return passphrase, nil
}

// EnsureKeyPair reuses an existing key pair from dir, or generates a new one.
// Multiple resources in the same root module share a single auto-generated key.
func (c *CosignClient) EnsureKeyPair(
	ctx context.Context,
	dir string,
) (*GenerateKeyPairResult, error) {
	privPath := filepath.Join(dir, "cosign.key")
	pubPath := filepath.Join(dir, "cosign.pub")

	privBytes, privErr := os.ReadFile(privPath)
	pubBytes, pubErr := os.ReadFile(pubPath)

	passphrase, passErr := ensurePassphrase(dir)
	if passErr != nil {
		return nil, passErr
	}

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
			Passphrase:     passphrase,
			Reused:         true,
		}, nil
	}

	tflog.Info(ctx, "Generating cosign key pair", map[string]any{"dir": dir})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create key output directory %s: %w", dir, err)
	}

	keys, err := cosign.GenerateKeyPair(func(_ bool) ([]byte, error) {
		return []byte(passphrase), nil
	})
	if err != nil {
		return nil, fmt.Errorf("cosign key pair generation failed: %w", err)
	}

	if writeErr := os.WriteFile(privPath, keys.PrivateBytes, 0o600); writeErr != nil {
		return nil, fmt.Errorf("failed to write private key to %s: %w", privPath, writeErr)
	}

	if writeErr := os.WriteFile(pubPath, keys.PublicBytes, 0o644); writeErr != nil {
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
		Passphrase:     passphrase,
		Reused:         false,
	}, nil
}
