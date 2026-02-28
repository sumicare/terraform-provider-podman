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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
)

func TestNewCosignClient(t *testing.T) {
	client := NewCosignClient()
	if client == nil {
		t.Error("expected non-nil CosignClient")
	}
}

func TestCosignOpts_Defaults(t *testing.T) {
	t.Run("sign", func(t *testing.T) {
		opts := SignOpts{}

		if opts.Keyless {
			t.Error("expected Keyless to be false by default")
		}

		if opts.FulcioURL != "" {
			t.Error("expected FulcioURL to be empty by default")
		}

		if opts.RekorURL != "" {
			t.Error("expected RekorURL to be empty by default")
		}
	})

	t.Run("attest", func(t *testing.T) {
		opts := AttestOpts{
			PredicateType: "slsaprovenance",
		}

		if opts.Keyless {
			t.Error("expected Keyless to be false by default")
		}

		if opts.PredicateType != "slsaprovenance" {
			t.Errorf("expected PredicateType slsaprovenance, got %s", opts.PredicateType)
		}
	})
}

func TestCosignClient_EnsureKeyPair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".cosign")
	client := NewCosignClient()

	// First call: generates a new key pair.
	result, err := client.EnsureKeyPair(t.Context(), dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair (generate) failed: %v", err)
	}

	if result.Reused {
		t.Error("expected Reused=false on first call")
	}

	// Snapshot the result structure (paths are deterministic within the temp dir).
	type snapshot struct {
		PrivKeyFile string `json:"priv_key_file"`
		PubKeyFile  string `json:"pub_key_file"`
		PrivHeader  string `json:"priv_header"`
		PubHeader   string `json:"pub_header"`
		Reused      bool   `json:"reused"`
		HasPrivPEM  bool   `json:"has_priv_pem"`
		HasPubPEM   bool   `json:"has_pub_pem"`
	}

	privHeader := strings.SplitN(string(result.PrivateKeyPEM), "\n", 2)[0]
	pubHeader := strings.SplitN(string(result.PublicKeyPEM), "\n", 2)[0]

	snap := snapshot{
		PrivKeyFile: filepath.Base(result.PrivateKeyPath),
		PubKeyFile:  filepath.Base(result.PublicKeyPath),
		Reused:      result.Reused,
		HasPrivPEM:  len(result.PrivateKeyPEM) > 0,
		HasPubPEM:   len(result.PublicKeyPEM) > 0,
		PrivHeader:  privHeader,
		PubHeader:   pubHeader,
	}

	g := goldie.New(t, goldie.WithFixtureDir(".goldie"))

	bs, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}

	g.Assert(t, "cosign_ensure_keypair_generate", bs)

	// Verify files on disk match result bytes.
	privDisk, _ := os.ReadFile(result.PrivateKeyPath)
	pubDisk, _ := os.ReadFile(result.PublicKeyPath)

	if !bytes.Equal(result.PrivateKeyPEM, privDisk) {
		t.Error("PrivateKeyPEM does not match file on disk")
	}

	if !bytes.Equal(result.PublicKeyPEM, pubDisk) {
		t.Error("PublicKeyPEM does not match file on disk")
	}
}

func TestCosignClient_EnsureKeyPair_Reuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".cosign")
	client := NewCosignClient()

	// Generate first.
	first, err := client.EnsureKeyPair(t.Context(), dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair (generate) failed: %v", err)
	}

	// Second call: must reuse the same key.
	second, err := client.EnsureKeyPair(t.Context(), dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair (reuse) failed: %v", err)
	}

	if !second.Reused {
		t.Error("expected Reused=true on second call")
	}

	if !bytes.Equal(first.PrivateKeyPEM, second.PrivateKeyPEM) {
		t.Error("reused private key bytes differ from original")
	}

	if !bytes.Equal(first.PublicKeyPEM, second.PublicKeyPEM) {
		t.Error("reused public key bytes differ from original")
	}
}

func TestCosignClient_EnsureKeyPair_CreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deep", ".cosign")
	client := NewCosignClient()

	result, err := client.EnsureKeyPair(t.Context(), dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair failed: %v", err)
	}

	if _, privErr := os.Stat(result.PrivateKeyPath); os.IsNotExist(privErr) {
		t.Error("private key file was not created in nested directory")
	}

	if _, pubErr := os.Stat(result.PublicKeyPath); os.IsNotExist(pubErr) {
		t.Error("public key file was not created in nested directory")
	}
}
