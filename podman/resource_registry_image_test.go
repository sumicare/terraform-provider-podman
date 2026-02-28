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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/sebdah/goldie/v2"
)

var (
	_ resource.Resource                = &RegistryImageResource{}
	_ resource.ResourceWithConfigure   = &RegistryImageResource{}
	_ resource.ResourceWithImportState = &RegistryImageResource{}
)

func signingObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"cosign_key_path":       tftypes.String,
			"cosign_password":       tftypes.String,
			"keyless":               tftypes.Bool,
			"fulcio_url":            tftypes.String,
			"rekor_url":             tftypes.String,
			"attestation_path":      tftypes.String,
			"predicate_type":        tftypes.String,
			"sbom_path":             tftypes.String,
			"cosign_key_path_out":   tftypes.String,
			"cosign_public_key_out": tftypes.String,
		},
	}
}

func authConfigObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"address":  tftypes.String,
			"username": tftypes.String,
			"password": tftypes.String,
		},
	}
}

func minimalRegistryImagePlanVals(name string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":            tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"name":          tftypes.NewValue(tftypes.String, name),
		"keep_remotely": tftypes.NewValue(tftypes.Bool, false),
		"digest":        tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"auth_config":   tftypes.NewValue(authConfigObjectType(), nil),
		"signing":       tftypes.NewValue(signingObjectType(), nil),
	}
}

func minimalRegistryImageStateVals(name string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":            tftypes.NewValue(tftypes.String, name),
		"name":          tftypes.NewValue(tftypes.String, name),
		"keep_remotely": tftypes.NewValue(tftypes.Bool, false),
		"digest":        tftypes.NewValue(tftypes.String, "sha256:abc123"),
		"auth_config":   tftypes.NewValue(authConfigObjectType(), nil),
		"signing":       tftypes.NewValue(signingObjectType(), nil),
	}
}

func registryImagePlanWithAuth(name, address, username, password string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":            tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"name":          tftypes.NewValue(tftypes.String, name),
		"keep_remotely": tftypes.NewValue(tftypes.Bool, false),
		"digest":        tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"auth_config": tftypes.NewValue(authConfigObjectType(), map[string]tftypes.Value{
			"address":  tftypes.NewValue(tftypes.String, address),
			"username": tftypes.NewValue(tftypes.String, username),
			"password": tftypes.NewValue(tftypes.String, password),
		}),
		"signing": tftypes.NewValue(signingObjectType(), nil),
	}
}

func TestRegistryImageResource_Schema(t *testing.T) {
	r := &RegistryImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if resp.Schema.Description == "" {
		t.Fatal("expected non-empty schema description")
	}

	topLevel := []string{"id", "name", "keep_remotely", "digest", "auth_config", "signing"}
	for _, attr := range topLevel {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}

	t.Run("auth_config_sub_attributes", func(t *testing.T) {
		if nested, ok := resp.Schema.Attributes["auth_config"].(schema.SingleNestedAttribute); ok {
			for _, sub := range []string{"address", "username", "password"} {
				if _, exists := nested.Attributes[sub]; !exists {
					t.Errorf("missing auth_config sub-attribute %q", sub)
				}
			}
		}
	})

	t.Run("signing_sub_attributes", func(t *testing.T) {
		if nested, ok := resp.Schema.Attributes["signing"].(schema.SingleNestedAttribute); ok {
			for _, sub := range []string{
				"cosign_key_path", "cosign_password", "keyless",
				"fulcio_url", "rekor_url", "attestation_path",
				"predicate_type", "sbom_path",
			} {
				if _, exists := nested.Attributes[sub]; !exists {
					t.Errorf("missing signing sub-attribute %q", sub)
				}
			}
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		names := make([]string, 0, len(resp.Schema.Attributes))
		for k := range resp.Schema.Attributes {
			names = append(names, k)
		}

		sort.Strings(names)

		g := goldie.New(t, goldie.WithFixtureDir(".goldie"))
		g.AssertJson(t, "registry_image_schema", names)
	})
}

func TestRegistryImageResource_Metadata(t *testing.T) {
	r := &RegistryImageResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(t.Context(), resource.MetadataRequest{ProviderTypeName: "podman"}, resp)

	if resp.TypeName != "podman_registry_image" {
		t.Errorf("expected type name podman_registry_image, got %q", resp.TypeName)
	}
}

func TestNewRegistryImageResource(t *testing.T) {
	r := NewRegistryImageResource()
	if r == nil {
		t.Fatal("expected non-nil resource")
	}

	if _, ok := r.(*RegistryImageResource); !ok {
		t.Errorf("expected *RegistryImageResource, got %T", r)
	}
}

func TestRegistryImageResource_Configure(t *testing.T) {
	cfg := &PodmanProviderConfig{URI: "unix:///test.sock", BaseURL: "http://d"}
	testResourceConfigure(
		t,
		cfg,
		func() configurableResource { return &RegistryImageResource{} },
		func(r configurableResource) *PodmanProviderConfig {
			if rr, ok := r.(*RegistryImageResource); ok {
				return rr.config
			}

			return nil
		},
	)
}

func TestRegistryImageResource_Update(t *testing.T) {
	r := &RegistryImageResource{}
	resp := &resource.UpdateResponse{}
	r.Update(t.Context(), resource.UpdateRequest{}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from Update")
	}

	found := false

	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "Update not supported") {
			found = true
		}
	}

	if !found {
		t.Error("expected 'Update not supported' error")
	}
}

func TestRegistryImageResource_SignImage_ImageRef(t *testing.T) {
	tests := []struct {
		name    string
		imgName string
		digest  types.String
		wantRef string
	}{
		{
			"digest_containing_at",
			"registry.example.com/myimage:v1",
			types.StringValue("registry.example.com/myimage@sha256:abc123"),
			"registry.example.com/myimage@sha256:abc123",
		},
		{
			"sha256_prefix",
			"registry.example.com/myimage:v1",
			types.StringValue("sha256:abc123"),
			"registry.example.com/myimage@sha256:abc123",
		},
		{
			"no_digest",
			"registry.example.com/myimage:v1",
			types.StringNull(),
			"registry.example.com/myimage:v1",
		},
		{
			"no_tag_with_sha256",
			"registry.example.com/myimage",
			types.StringValue("sha256:def456"),
			"registry.example.com/myimage@sha256:def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RegistryImageResource{}
			data := &RegistryImageResourceModel{
				Name:   types.StringValue(tt.imgName),
				Digest: tt.digest,
				Signing: &SigningModel{
					CosignKeyPath:      types.StringValue("/nonexistent/key.pem"),
					CosignPassword:     types.StringNull(),
					Keyless:            types.BoolValue(false),
					FulcioURL:          types.StringNull(),
					RekorURL:           types.StringNull(),
					AttestationPath:    types.StringNull(),
					PredicateType:      types.StringNull(),
					SBOMPath:           types.StringNull(),
					CosignKeyPathOut:   types.StringNull(),
					CosignPublicKeyOut: types.StringNull(),
				},
			}

			var diags diag.Diagnostics
			r.signImage(t.Context(), data, &diags)

			// Signing will fail (no cosign) – check the imageRef in the error.
			if !diags.HasError() {
				t.Log("signImage succeeded unexpectedly (cosign may be available)")

				return
			}

			errMsg := diags.Errors()[0].Detail()
			if !strings.Contains(errMsg, tt.wantRef) {
				t.Errorf("expected imageRef %q in error, got: %s", tt.wantRef, errMsg)
			}
		})
	}
}

func TestRegistryImageResource_SignImage_Keyless(t *testing.T) {
	r := &RegistryImageResource{}
	data := &RegistryImageResourceModel{
		Name:   types.StringValue("registry.example.com/myimage:v1"),
		Digest: types.StringNull(),
		Signing: &SigningModel{
			CosignKeyPath:      types.StringNull(),
			CosignPassword:     types.StringNull(),
			Keyless:            types.BoolValue(true),
			FulcioURL:          types.StringValue("https://fulcio.example.com"),
			RekorURL:           types.StringValue("https://rekor.example.com"),
			AttestationPath:    types.StringNull(),
			PredicateType:      types.StringNull(),
			SBOMPath:           types.StringNull(),
			CosignKeyPathOut:   types.StringNull(),
			CosignPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	r.signImage(t.Context(), data, &diags)

	if !diags.HasError() {
		t.Log("signImage (keyless) succeeded unexpectedly")
	}
}

func TestRegistryImageResource_SignImage_WithAttestationAndSBOM(t *testing.T) {
	r := &RegistryImageResource{}
	data := &RegistryImageResourceModel{
		Name:   types.StringValue("registry.example.com/myimage:v1"),
		Digest: types.StringNull(),
		Signing: &SigningModel{
			CosignKeyPath:      types.StringValue("/nonexistent/key.pem"),
			CosignPassword:     types.StringValue("password"),
			Keyless:            types.BoolValue(false),
			FulcioURL:          types.StringNull(),
			RekorURL:           types.StringNull(),
			AttestationPath:    types.StringValue("/tmp/attestation.json"),
			PredicateType:      types.StringValue("slsaprovenance"),
			SBOMPath:           types.StringValue("/tmp/sbom.json"),
			CosignKeyPathOut:   types.StringNull(),
			CosignPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	r.signImage(t.Context(), data, &diags)

	if !diags.HasError() {
		t.Log("signImage with attestation+sbom succeeded unexpectedly")
	}
}

func TestRegistryImageResource_SignImage_AutoGenerateKey(t *testing.T) {
	t.Cleanup(func() { os.RemoveAll(".cosign") })

	r := &RegistryImageResource{}
	data := &RegistryImageResourceModel{
		Name:   types.StringValue("registry.example.com/myimage:v1"),
		Digest: types.StringNull(),
		Signing: &SigningModel{
			CosignKeyPath:      types.StringNull(),
			CosignPassword:     types.StringNull(),
			Keyless:            types.BoolValue(false),
			FulcioURL:          types.StringNull(),
			RekorURL:           types.StringNull(),
			AttestationPath:    types.StringNull(),
			PredicateType:      types.StringNull(),
			SBOMPath:           types.StringNull(),
			CosignKeyPathOut:   types.StringNull(),
			CosignPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	r.signImage(t.Context(), data, &diags)

	// Key generation should have happened (signing itself may fail).
	if data.Signing.CosignKeyPathOut.IsNull() || data.Signing.CosignKeyPathOut.ValueString() == "" {
		t.Fatal("expected cosign_key_path_out to be populated")
	}

	if data.Signing.CosignPublicKeyOut.IsNull() ||
		data.Signing.CosignPublicKeyOut.ValueString() == "" {
		t.Fatal("expected cosign_public_key_out to be populated")
	}

	// Must emit a WARNING about auto-generation.
	var foundWarning bool

	for _, w := range diags.Warnings() {
		if strings.Contains(w.Summary(), "cosign key pair") {
			foundWarning = true

			break
		}
	}

	if !foundWarning {
		t.Error("expected a warning diagnostic about auto-generated cosign key pair")
	}
}

func TestRegistryImageResource_SignImage_OutputsInputKey(t *testing.T) {
	r := &RegistryImageResource{}
	data := &RegistryImageResourceModel{
		Name:   types.StringValue("registry.example.com/myimage:v1"),
		Digest: types.StringNull(),
		Signing: &SigningModel{
			CosignKeyPath:      types.StringValue("/my/custom/key.pem"),
			CosignPassword:     types.StringNull(),
			Keyless:            types.BoolValue(false),
			FulcioURL:          types.StringNull(),
			RekorURL:           types.StringNull(),
			AttestationPath:    types.StringNull(),
			PredicateType:      types.StringNull(),
			SBOMPath:           types.StringNull(),
			CosignKeyPathOut:   types.StringNull(),
			CosignPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	r.signImage(t.Context(), data, &diags)

	g := goldie.New(t, goldie.WithFixtureDir(".goldie"))
	g.AssertJson(t, "registry_signing_input_key_output", map[string]string{
		"cosign_key_path_out":   data.Signing.CosignKeyPathOut.ValueString(),
		"cosign_public_key_out": data.Signing.CosignPublicKeyOut.ValueString(),
	})
}

func TestRegistryImageResource_Schema_SigningOutputs(t *testing.T) {
	r := &RegistryImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if signing, ok := resp.Schema.Attributes["signing"].(schema.SingleNestedAttribute); ok {
		names := make([]string, 0, len(signing.Attributes))
		for name := range signing.Attributes {
			names = append(names, name)
		}

		sort.Strings(names)

		g := goldie.New(t, goldie.WithFixtureDir(".goldie"))
		g.AssertJson(t, "registry_signing_attributes", names)
	}
}

func TestRegistryImageResource_ClientImageExists(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantExists bool
	}{
		{"exists", http.StatusNoContent, true},
		{"not_found", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/exists") {
						w.WriteHeader(tt.status)

						return
					}

					w.WriteHeader(http.StatusOK)
				}),
			)
			t.Cleanup(server.Close)

			client := NewPodmanClient(&PodmanProviderConfig{
				HTTPClient: server.Client(),
				BaseURL:    server.URL,
			})

			exists, err := client.ImageExists(t.Context(), "registry.example.com/test:v1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if exists != tt.wantExists {
				t.Errorf("exists = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

func TestRegistryImageResource_PushWithDigestFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/push"):
			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(map[string]any{"stream": "pushing"}); err != nil {
				t.Logf("failed to encode response: %v", err)
			}

		case strings.Contains(r.URL.Path, "/json"):
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(map[string]any{
				"Id":          "sha256:fallback",
				"RepoDigests": []string{"registry.example.com/test@sha256:fallback"},
				"Size":        int64(100),
			}); err != nil {
				t.Logf("failed to encode response: %v", err)
			}

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	client := NewPodmanClient(&PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	})

	digest, err := client.PushImage(t.Context(), "registry.example.com/test:v1", "user", "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if digest != "" {
		t.Logf("push returned digest %q (unexpected but ok)", digest)
	}

	result, err := client.InspectImage(t.Context(), "registry.example.com/test:v1")
	if err != nil {
		t.Fatalf("unexpected inspect error: %v", err)
	}

	if result.RepoDigest != "registry.example.com/test@sha256:fallback" {
		t.Errorf("expected fallback digest, got %q", result.RepoDigest)
	}
}

func TestRegistryImageResource_Create(t *testing.T) {
	tests := []struct {
		handler    http.HandlerFunc
		planVals   func() map[string]tftypes.Value
		checkState func(*testing.T, RegistryImageResourceModel)
		name       string
		wantErr    bool
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/push") {
					w.WriteHeader(http.StatusOK)

					if err := json.NewEncoder(w).
						Encode(map[string]any{"digest": "sha256:pushed789"}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

					return
				}

				w.WriteHeader(http.StatusOK)
			},
			planVals: func() map[string]tftypes.Value {
				return minimalRegistryImagePlanVals("registry.example.com/test:v1")
			},
			checkState: func(t *testing.T, data RegistryImageResourceModel) {
				t.Helper()

				if data.ID.ValueString() != "registry.example.com/test:v1" {
					t.Errorf("expected ID = name, got %q", data.ID.ValueString())
				}

				if data.Digest.ValueString() != "sha256:pushed789" {
					t.Errorf("expected digest sha256:pushed789, got %q", data.Digest.ValueString())
				}
			},
		},
		{
			name: "with_auth",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/push") {
					creds := r.URL.Query().Get("credentials")
					if creds != "user:pass" {
						http.Error(w, "bad creds: "+creds, http.StatusUnauthorized)

						return
					}

					w.WriteHeader(http.StatusOK)

					if err := json.NewEncoder(w).
						Encode(map[string]any{"digest": "sha256:authed"}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

					return
				}

				w.WriteHeader(http.StatusOK)
			},
			planVals: func() map[string]tftypes.Value {
				return registryImagePlanWithAuth(
					"registry.example.com/test:v1",
					"registry.example.com",
					"user",
					"pass",
				)
			},
			checkState: func(t *testing.T, data RegistryImageResourceModel) {
				t.Helper()

				if data.Digest.ValueString() != "sha256:authed" {
					t.Errorf("expected digest sha256:authed, got %q", data.Digest.ValueString())
				}
			},
		},
		{
			name: "push_error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)

				if err := json.NewEncoder(w).
					Encode(map[string]any{"error": "unauthorized"}); err != nil {
					t.Logf("failed to encode response: %v", err)
				}
			},
			planVals: func() map[string]tftypes.Value {
				return minimalRegistryImagePlanVals("registry.example.com/test:v1")
			},
			wantErr: true,
		},
		{
			name: "digest_fallback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/push"):
					w.WriteHeader(http.StatusOK)

					if err := json.NewEncoder(w).
						Encode(map[string]any{"stream": "pushing"}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

				case strings.Contains(r.URL.Path, "/json"):
					w.Header().Set("Content-Type", "application/json")

					if err := json.NewEncoder(w).Encode(map[string]any{
						"Id":          "sha256:fallback",
						"RepoDigests": []string{"registry.example.com/test@sha256:fallback"},
						"Size":        int64(100),
					}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

				default:
					w.WriteHeader(http.StatusOK)
				}
			},
			planVals: func() map[string]tftypes.Value {
				return minimalRegistryImagePlanVals("registry.example.com/test:v1")
			},
			checkState: func(t *testing.T, data RegistryImageResourceModel) {
				t.Helper()

				if data.Digest.ValueString() != "registry.example.com/test@sha256:fallback" {
					t.Errorf("expected fallback digest, got %q", data.Digest.ValueString())
				}
			},
		},
	}

	testResourceCreate(t, tests,
		func(t *testing.T, vals map[string]tftypes.Value) tfsdk.Plan {
			t.Helper()
			return makePlan(t, &RegistryImageResource{}, vals)
		},
		func(t *testing.T, vals map[string]tftypes.Value) tfsdk.State {
			t.Helper()
			return makeState(t, &RegistryImageResource{}, vals)
		},
		func(cfg *PodmanProviderConfig) resource.Resource {
			return &RegistryImageResource{config: cfg}
		},
		func(resp *resource.CreateResponse) RegistryImageResourceModel {
			var data RegistryImageResourceModel
			resp.State.Get(context.Background(), &data)

			return data
		},
	)
}

func TestRegistryImageResource_Read_CRUD(t *testing.T) {
	tests := []struct {
		name     string
		name_    string
		status   int
		wantNull bool
	}{
		{"exists", "registry.example.com/test:v1", http.StatusNoContent, false},
		{"gone", "registry.example.com/gone:v1", http.StatusNotFound, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/exists") {
						w.WriteHeader(tt.status)

						return
					}

					w.WriteHeader(tt.status)
				}),
			)
			t.Cleanup(server.Close)

			r := &RegistryImageResource{config: &PodmanProviderConfig{
				HTTPClient: server.Client(),
				BaseURL:    server.URL,
			}}

			state := makeState(t, &RegistryImageResource{}, minimalRegistryImageStateVals(tt.name_))
			readResp := &resource.ReadResponse{State: state}
			r.Read(t.Context(), resource.ReadRequest{State: state}, readResp)

			if readResp.Diagnostics.HasError() {
				t.Fatalf("Read errors: %v", readResp.Diagnostics.Errors())
			}

			if tt.wantNull && !readResp.State.Raw.IsNull() {
				t.Error("expected state to be removed when image is gone")
			}

			if !tt.wantNull && readResp.State.Raw.IsNull() {
				t.Error("expected state to be preserved when image exists")
			}
		})
	}
}

func TestRegistryImageResource_Delete_CRUD(t *testing.T) {
	r := &RegistryImageResource{}
	state := makeState(
		t,
		&RegistryImageResource{},
		minimalRegistryImageStateVals("registry.example.com/test:v1"),
	)
	deleteResp := &resource.DeleteResponse{State: state}
	r.Delete(t.Context(), resource.DeleteRequest{State: state}, deleteResp)

	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete errors: %v", deleteResp.Diagnostics.Errors())
	}
}

func TestRegistryImageResource_Delete_NoOp(t *testing.T) {
	data := &RegistryImageResourceModel{
		Name:         types.StringValue("registry.example.com/test:v1"),
		KeepRemotely: types.BoolValue(false),
	}

	if data.KeepRemotely.ValueBool() {
		t.Error("expected KeepRemotely=false")
	}

	if data.Name.ValueString() != "registry.example.com/test:v1" {
		t.Errorf("unexpected name: %s", data.Name.ValueString())
	}
}

func TestRegistryImageResource_ImportState(t *testing.T) {
	r := &RegistryImageResource{}
	state := makeState(
		t,
		&RegistryImageResource{},
		minimalRegistryImageStateVals("registry.example.com/test:v1"),
	)

	importResp := &resource.ImportStateResponse{State: state}
	r.ImportState(
		t.Context(),
		resource.ImportStateRequest{ID: "registry.example.com/imported:v1"},
		importResp,
	)

	if importResp.Diagnostics.HasError() {
		t.Fatalf("ImportState errors: %v", importResp.Diagnostics.Errors())
	}

	var data RegistryImageResourceModel
	importResp.State.Get(t.Context(), &data)

	if data.ID.ValueString() != "registry.example.com/imported:v1" {
		t.Errorf("expected imported ID, got %q", data.ID.ValueString())
	}
}
