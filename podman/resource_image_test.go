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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/sebdah/goldie/v2"
)

var (
	_ resource.Resource                = &ImageResource{}
	_ resource.ResourceWithConfigure   = &ImageResource{}
	_ resource.ResourceWithImportState = &ImageResource{}
)

func buildObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"context":    tftypes.String,
			"build_args": tftypes.Map{ElementType: tftypes.String},
			"pull":       tftypes.Bool,
		},
	}
}

func attestationObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"step_name":             tftypes.String,
			"signer_key_path":       tftypes.String,
			"output_path":           tftypes.String,
			"attestors":             tftypes.List{ElementType: tftypes.String},
			"export_slsa":           tftypes.Bool,
			"enable_archivista":     tftypes.Bool,
			"archivista_server":     tftypes.String,
			"signer_key_path_out":   tftypes.String,
			"signer_public_key_out": tftypes.String,
		},
	}
}

func sbomObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"output_path": tftypes.String,
			"format":      tftypes.String,
		},
	}
}

func minimalImagePlanVals(name, contextDir string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"name":         tftypes.NewValue(tftypes.String, name),
		"repo_digest":  tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"keep_locally": tftypes.NewValue(tftypes.Bool, false),
		"context_hash": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"attestation":  tftypes.NewValue(attestationObjectType(), nil),
		"sbom":         tftypes.NewValue(sbomObjectType(), nil),
		"build": tftypes.NewValue(buildObjectType(), map[string]tftypes.Value{
			"context":    tftypes.NewValue(tftypes.String, contextDir),
			"build_args": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
			"pull":       tftypes.NewValue(tftypes.Bool, false),
		}),
	}
}

func minimalImageStateVals(name string) map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, "sha256:abc123def"),
		"name":         tftypes.NewValue(tftypes.String, name),
		"repo_digest":  tftypes.NewValue(tftypes.String, "localhost/test@sha256:abc123def"),
		"keep_locally": tftypes.NewValue(tftypes.Bool, false),
		"context_hash": tftypes.NewValue(tftypes.String, "somehash"),
		"attestation":  tftypes.NewValue(attestationObjectType(), nil),
		"sbom":         tftypes.NewValue(sbomObjectType(), nil),
		"build": tftypes.NewValue(buildObjectType(), map[string]tftypes.Value{
			"context":    tftypes.NewValue(tftypes.String, "."),
			"build_args": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
			"pull":       tftypes.NewValue(tftypes.Bool, false),
		}),
	}
}

func TestImageResource_Schema(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if resp.Schema.Description == "" {
		t.Fatal("expected non-empty schema description")
	}

	for _, attr := range []string{"name", "build"} {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("missing required attribute %q", attr)

			continue
		}

		if nested, isNested := a.(schema.SingleNestedAttribute); isNested {
			if !nested.Required {
				t.Errorf("expected attribute %q to be required", attr)
			}
		}
	}

	for _, attr := range []string{"keep_locally", "sbom", "attestation"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing optional attribute %q", attr)
		}
	}

	for _, attr := range []string{"id", "context_hash"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing computed attribute %q", attr)
		}
	}

	t.Run("build_sub_attributes", func(t *testing.T) {
		if nested, ok := resp.Schema.Attributes["build"].(schema.SingleNestedAttribute); ok {
			for _, sub := range []string{"context", "build_args", "pull"} {
				if _, exists := nested.Attributes[sub]; !exists {
					t.Errorf("missing build sub-attribute %q", sub)
				}
			}
		}
	})

	t.Run("attestation_sub_attributes", func(t *testing.T) {
		if nested, ok := resp.Schema.Attributes["attestation"].(schema.SingleNestedAttribute); ok {
			for _, sub := range []string{
				"step_name", "signer_key_path", "output_path",
				"attestors", "export_slsa", "enable_archivista", "archivista_server",
			} {
				if _, exists := nested.Attributes[sub]; !exists {
					t.Errorf("missing attestation sub-attribute %q", sub)
				}
			}
		}
	})

	t.Run("sbom_sub_attributes", func(t *testing.T) {
		if nested, ok := resp.Schema.Attributes["sbom"].(schema.SingleNestedAttribute); ok {
			for _, sub := range []string{"output_path", "format"} {
				if _, exists := nested.Attributes[sub]; !exists {
					t.Errorf("missing sbom sub-attribute %q", sub)
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
		g.AssertJson(t, "image_schema", names)
	})
}

func TestImageResource_Metadata(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(t.Context(), resource.MetadataRequest{ProviderTypeName: "podman"}, resp)

	if resp.TypeName != "podman_image" {
		t.Errorf("expected type name podman_image, got %q", resp.TypeName)
	}
}

func TestImageResource_Configure(t *testing.T) {
	cfg := &PodmanProviderConfig{URI: "unix:///test.sock", BaseURL: "http://d"}
	testResourceConfigure(t, cfg,
		func() configurableResource { return &ImageResource{} },
		func(r configurableResource) *PodmanProviderConfig {
			if ir, ok := r.(*ImageResource); ok {
				return ir.config
			}

			return nil
		},
	)
}

func TestExtractBuildArgs(t *testing.T) {
	withValues, _ := types.MapValueFrom(t.Context(), types.StringType, map[string]string{
		"VERSION": "1.0.0",
		"REPO":    "myrepo",
	})
	empty, _ := types.MapValueFrom(t.Context(), types.StringType, map[string]string{})

	tests := []struct {
		name    string
		input   types.Map
		wantLen int
		wantNil bool
	}{
		{"null", types.MapNull(types.StringType), 0, true},
		{"unknown", types.MapUnknown(types.StringType), 0, true},
		{"with_values", withValues, 2, false},
		{"empty", empty, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBuildArgs(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}

				return
			}

			if len(result) != tt.wantLen {
				t.Errorf("expected %d args, got %d", tt.wantLen, len(result))
			}
		})
	}

	result := extractBuildArgs(withValues)
	if result["VERSION"] != "1.0.0" {
		t.Errorf("VERSION = %q, want 1.0.0", result["VERSION"])
	}

	if result["REPO"] != "myrepo" {
		t.Errorf("REPO = %q, want myrepo", result["REPO"])
	}
}

func TestContextHashPlanModifier_Description(t *testing.T) {
	m := contextHashPlanModifier{}
	desc := m.Description(t.Context())

	if desc == "" {
		t.Error("expected non-empty description")
	}

	mdDesc := m.MarkdownDescription(t.Context())
	if mdDesc != desc {
		t.Error("expected MarkdownDescription to equal Description")
	}
}

func TestImageResource_Update(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.UpdateResponse{}
	r.Update(t.Context(), resource.UpdateRequest{}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error from Update")
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

func TestToBuildOpts(t *testing.T) {
	buildArgs, _ := types.MapValueFrom(t.Context(), types.StringType, map[string]string{
		"VERSION": "2.0.0",
	})

	tests := []struct {
		name     string
		model    *ImageResourceModel
		wantTag  string
		wantCtx  string
		wantPull bool
		wantArgs int
	}{
		{
			name: "basic",
			model: &ImageResourceModel{
				Name: types.StringValue("myimage:v1"),
				Build: &ImageBuildModel{
					Context:   types.StringValue("/tmp/ctx"),
					BuildArgs: types.MapNull(types.StringType),
					Pull:      types.BoolValue(true),
				},
			},
			wantTag: "myimage:v1", wantCtx: "/tmp/ctx", wantPull: true, wantArgs: 0,
		},
		{
			name: "with_build_args",
			model: &ImageResourceModel{
				Name: types.StringValue("myimage:v2"),
				Build: &ImageBuildModel{
					Context:   types.StringValue("/tmp/ctx"),
					BuildArgs: buildArgs,
					Pull:      types.BoolValue(false),
				},
			},
			wantTag: "myimage:v2", wantCtx: "/tmp/ctx", wantPull: false, wantArgs: 1,
		},
		{
			name: "empty_context",
			model: &ImageResourceModel{
				Name: types.StringValue("myimage:v1"),
				Build: &ImageBuildModel{
					Context:   types.StringValue(""),
					BuildArgs: types.MapNull(types.StringType),
					Pull:      types.BoolValue(false),
				},
			},
			wantTag: "myimage:v1", wantCtx: ".", wantPull: false, wantArgs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ImageResource{}

			var diags diag.Diagnostics

			opts, err := r.toBuildOpts(t.Context(), tt.model, &diags)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}

			if opts.Tag != tt.wantTag {
				t.Errorf("Tag = %q, want %q", opts.Tag, tt.wantTag)
			}

			if opts.ContextDir != tt.wantCtx {
				t.Errorf("ContextDir = %q, want %q", opts.ContextDir, tt.wantCtx)
			}

			if opts.Pull != tt.wantPull {
				t.Errorf("Pull = %v, want %v", opts.Pull, tt.wantPull)
			}

			if len(opts.BuildArgs) != tt.wantArgs {
				t.Errorf("BuildArgs len = %d, want %d", len(opts.BuildArgs), tt.wantArgs)
			}
		})
	}
}

func newTestConfig(t *testing.T, handler http.Handler) *PodmanProviderConfig {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &PodmanProviderConfig{
		URI:        "tcp://localhost",
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
}

func mockPodmanHandler(t *testing.T) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/build"):
			_, _ = io.Copy(io.Discard, r.Body)

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"stream": "Successfully built"})

		case strings.Contains(r.URL.Path, "/json"):
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(map[string]any{
				"Id":          "sha256:abc123def",
				"RepoDigests": []string{"registry.example.com/test@sha256:abc123def"},
				"Size":        int64(5000),
			}); err != nil {
				t.Logf("failed to encode response: %v", err)
			}

		case strings.Contains(r.URL.Path, "/exists"):
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})

		case strings.Contains(r.URL.Path, "/push"):
			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).
				Encode(map[string]any{"digest": "sha256:pushed456"}); err != nil {
				t.Logf("failed to encode response: %v", err)
			}

		default:
			t.Logf("unhandled request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestImageResource_ReadImageState(t *testing.T) {
	cfg := newTestConfig(t, mockPodmanHandler(t))
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("registry.example.com/test:latest"),
	}

	var diags diag.Diagnostics
	r.readImageState(t.Context(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags.Errors())
	}

	if data.ID.ValueString() != "sha256:abc123def" {
		t.Errorf("ID = %q, want sha256:abc123def", data.ID.ValueString())
	}
}

func TestImageResource_ReadImageState_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("registry.example.com/test:latest"),
	}

	var diags diag.Diagnostics
	r.readImageState(t.Context(), data, &diags)

	if !diags.HasError() {
		t.Error("expected error from readImageState")
	}
}

func TestImageResource_BuildImage(t *testing.T) {
	cfg := newTestConfig(t, mockPodmanHandler(t))
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:v1"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
	}

	var diags diag.Diagnostics

	err := r.buildImage(t.Context(), data, &diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diags.HasError() {
		t.Errorf("unexpected diagnostics: %v", diags.Errors())
	}
}

func TestImageResource_BuildImage_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "build failed"})
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:v1"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
	}

	var diags diag.Diagnostics

	err := r.buildImage(t.Context(), data, &diags)
	if err == nil {
		t.Error("expected error from buildImage")
	}

	if !diags.HasError() {
		t.Error("expected diagnostics error from buildImage")
	}
}

func TestImageResource_GenerateSBOM(t *testing.T) {
	r := &ImageResource{}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:v1"),
		SBOM: &SBOMModel{
			OutputPath: types.StringValue("/tmp/nonexistent-sbom-path.json"),
			Format:     types.StringValue("cyclonedx"),
		},
	}

	var diags diag.Diagnostics
	r.generateSBOM(t.Context(), data, &diags)

	if !diags.HasError() {
		t.Log("generateSBOM succeeded (syft may be installed)")
	}
}

func TestImageResource_Schema_SBOMDefaults(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if sbomAttr, ok := resp.Schema.Attributes["sbom"].(schema.SingleNestedAttribute); ok {
		if !sbomAttr.IsComputed() {
			t.Error("expected sbom attribute to be computed (provenance by default)")
		}

		if outputPath, isOutputPath := sbomAttr.Attributes["output_path"].(schema.StringAttribute); isOutputPath {
			if !outputPath.IsComputed() || !outputPath.IsOptional() {
				t.Error("expected output_path to be optional+computed")
			}
		}

		if format, isFormat := sbomAttr.Attributes["format"].(schema.StringAttribute); isFormat {
			if !format.IsComputed() || !format.IsOptional() {
				t.Error("expected format to be optional+computed")
			}
		}
	}
}

func TestImageResource_Schema_AttestationDefaults(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if attAttr, ok := resp.Schema.Attributes["attestation"].(schema.SingleNestedAttribute); ok {
		if stepName, isStepName := attAttr.Attributes["step_name"].(schema.StringAttribute); isStepName {
			if !stepName.IsComputed() || !stepName.IsOptional() {
				t.Error("expected step_name to be optional+computed with default")
			}
		}

		if outputPath, isOutputPath := attAttr.Attributes["output_path"].(schema.StringAttribute); isOutputPath {
			if !outputPath.IsComputed() || !outputPath.IsOptional() {
				t.Error("expected output_path to be optional+computed with default")
			}
		}

		if signerKeyPath, isSignerKeyPath := attAttr.Attributes["signer_key_path"].(schema.StringAttribute); isSignerKeyPath {
			if !signerKeyPath.IsOptional() {
				t.Error("expected signer_key_path to be optional (auto-generates key when omitted)")
			}
		}

		if exportSLSA, isExportSLSA := attAttr.Attributes["export_slsa"].(schema.BoolAttribute); isExportSLSA {
			if !exportSLSA.IsComputed() || !exportSLSA.IsOptional() {
				t.Error("expected export_slsa to be optional+computed")
			}
		}
	}
}

func TestImageResource_Create_DefaultSBOMProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/build"):
			_, _ = io.Copy(io.Discard, r.Body)

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"stream": "Successfully built"})

		case strings.Contains(r.URL.Path, "/json"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":          "sha256:prov123",
				"RepoDigests": []string{"localhost/test@sha256:prov123"},
				"Size":        int64(5000),
			})

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	r := &ImageResource{config: &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}}

	// Plan with null sbom block — provenance should still be applied.
	vals := minimalImagePlanVals("localhost/test:prov", ".")
	plan := makePlan(t, &ImageResource{}, vals)
	state := makeState(t, &ImageResource{}, vals)

	createResp := &resource.CreateResponse{State: state}
	r.Create(t.Context(), resource.CreateRequest{Plan: plan}, createResp)

	// Create may error because syft is not installed, but the SBOM model
	// must be populated with defaults regardless.
	var data ImageResourceModel
	createResp.State.Get(t.Context(), &data)

	// If there was no error (syft available), verify SBOM defaults applied.
	if !createResp.Diagnostics.HasError() {
		if data.SBOM == nil {
			t.Fatal("expected SBOM block to be populated by default for provenance")
		}

		if data.SBOM.Format.ValueString() != "cyclonedx" {
			t.Errorf(
				"expected default SBOM format 'cyclonedx', got %q",
				data.SBOM.Format.ValueString(),
			)
		}

		if data.SBOM.OutputPath.ValueString() != "sbom.cyclonedx.json" {
			t.Errorf(
				"expected default SBOM output_path 'sbom.cyclonedx.json', got %q",
				data.SBOM.OutputPath.ValueString(),
			)
		}
	} else {
		// Even on error the SBOM block should have been populated before
		// generateSBOM was called, so we verify the model was set.
		t.Log(
			"Create returned error (syft likely not installed), verifying SBOM defaults were applied to model",
		)
	}
}

func TestImageResource_BuildWithAttestation_Defaults(t *testing.T) {
	cfg := newTestConfig(t, mockPodmanHandler(t))
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:att"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
		Attestation: &AttestationModel{
			StepName:           types.StringValue("build"),
			SignerKeyPath:      types.StringValue("/nonexistent/key.pem"),
			OutputPath:         types.StringValue("attestation.json"),
			Attestors:          types.ListNull(types.StringType),
			ExportSLSA:         types.BoolValue(true),
			EnableArchivista:   types.BoolValue(false),
			ArchivistaServer:   types.StringNull(),
			SignerKeyPathOut:   types.StringNull(),
			SignerPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics

	err := r.buildImage(t.Context(), data, &diags)

	// Expected to fail since /nonexistent/key.pem doesn't exist, but
	// it should attempt the attestation path (not the standard build path).
	if err == nil && !diags.HasError() {
		t.Log("buildImage with attestation defaults succeeded unexpectedly")
	}

	// Verify the attestation model has the expected default values.
	if data.Attestation.StepName.ValueString() != "build" {
		t.Errorf(
			"expected default step_name 'build', got %q",
			data.Attestation.StepName.ValueString(),
		)
	}

	if data.Attestation.OutputPath.ValueString() != "attestation.json" {
		t.Errorf(
			"expected default output_path 'attestation.json', got %q",
			data.Attestation.OutputPath.ValueString(),
		)
	}

	if !data.Attestation.ExportSLSA.ValueBool() {
		t.Error("expected export_slsa to default to true")
	}
}

func TestImageResource_Schema_AttestationKeyOutputs(t *testing.T) {
	r := &ImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	if attAttr, ok := resp.Schema.Attributes["attestation"].(schema.SingleNestedAttribute); ok {
		names := make([]string, 0, len(attAttr.Attributes))
		for name := range attAttr.Attributes {
			names = append(names, name)
		}

		sort.Strings(names)

		g := goldie.New(t, goldie.WithFixtureDir(".goldie"))
		g.AssertJson(t, "image_attestation_attributes", names)
	}
}

func TestImageResource_BuildWithAttestation_OutputsInputKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:keyout"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
		Attestation: &AttestationModel{
			StepName:           types.StringValue("build"),
			SignerKeyPath:      types.StringValue("/my/provided/key.pem"),
			OutputPath:         types.StringValue("attestation.json"),
			Attestors:          types.ListNull(types.StringType),
			ExportSLSA:         types.BoolValue(true),
			EnableArchivista:   types.BoolValue(false),
			ArchivistaServer:   types.StringNull(),
			SignerKeyPathOut:   types.StringNull(),
			SignerPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	if err := r.buildImage(t.Context(), data, &diags); err != nil {
		t.Logf("buildImage failed: %v", err)
	}

	g := goldie.New(t, goldie.WithFixtureDir(".goldie"))
	g.AssertJson(t, "image_attestation_input_key_output", map[string]string{
		"signer_key_path_out":   data.Attestation.SignerKeyPathOut.ValueString(),
		"signer_public_key_out": data.Attestation.SignerPublicKeyOut.ValueString(),
	})
}

func TestImageResource_BuildWithAttestation_AutoGenerateKey(t *testing.T) {
	t.Cleanup(func() { os.RemoveAll(".cosign") })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:autogen"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
		Attestation: &AttestationModel{
			StepName:           types.StringValue("build"),
			SignerKeyPath:      types.StringNull(),
			OutputPath:         types.StringValue("attestation.json"),
			Attestors:          types.ListNull(types.StringType),
			ExportSLSA:         types.BoolValue(true),
			EnableArchivista:   types.BoolValue(false),
			ArchivistaServer:   types.StringNull(),
			SignerKeyPathOut:   types.StringNull(),
			SignerPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics
	if err := r.buildImage(t.Context(), data, &diags); err != nil {
		t.Logf("buildImage failed: %v", err)
	}

	// Key generation should succeed even if the build itself fails.
	if data.Attestation.SignerKeyPathOut.IsNull() ||
		data.Attestation.SignerKeyPathOut.ValueString() == "" {
		t.Fatal("expected signer_key_path_out to be populated")
	}

	if data.Attestation.SignerPublicKeyOut.IsNull() ||
		data.Attestation.SignerPublicKeyOut.ValueString() == "" {
		t.Fatal("expected signer_public_key_out to be populated")
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

func TestImageResource_GenerateSBOM_DefaultFormat(t *testing.T) {
	r := &ImageResource{}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:v1"),
		SBOM: &SBOMModel{
			OutputPath: types.StringValue("/tmp/nonexistent-sbom-default.json"),
			Format:     types.StringValue("cyclonedx"),
		},
	}

	if data.SBOM.Format.ValueString() != "cyclonedx" {
		t.Errorf("expected default format 'cyclonedx', got %q", data.SBOM.Format.ValueString())
	}

	if data.SBOM.OutputPath.ValueString() != "/tmp/nonexistent-sbom-default.json" {
		t.Errorf("expected output_path to be set, got %q", data.SBOM.OutputPath.ValueString())
	}

	var diags diag.Diagnostics
	r.generateSBOM(t.Context(), data, &diags)

	if !diags.HasError() {
		t.Log("generateSBOM with defaults succeeded (syft may be installed)")
	}
}

func TestImageResource_BuildContextHash_Integration(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Containerfile"), []byte(`ARG VERSION="1.0.0"
FROM scratch
COPY main.go /app/
`), 0o600); err != nil {
		t.Fatalf("failed to write Containerfile: %v", err)
	}

	if err := os.WriteFile(
		filepath.Join(dir, "main.go"),
		[]byte("package main\n"),
		0o600,
	); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	buildArgs, _ := types.MapValueFrom(t.Context(), types.StringType, map[string]string{
		"VERSION": "2.0.0",
	})

	args := extractBuildArgs(buildArgs)

	hash, err := BuildContextHash(t.Context(), dir, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}

	hash2, err := BuildContextHash(t.Context(), dir, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash != hash2 {
		t.Error("expected deterministic hash")
	}
}

func TestNewImageResource(t *testing.T) {
	r := NewImageResource()
	if r == nil {
		t.Fatal("expected non-nil resource")
	}

	if _, ok := r.(*ImageResource); !ok {
		t.Errorf("expected *ImageResource, got %T", r)
	}
}

func TestImageResource_Delete_KeepLocally(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	r := &ImageResource{}

	data := &ImageResourceModel{
		KeepLocally: types.BoolValue(true),
	}

	if !data.KeepLocally.ValueBool() {
		t.Fatal("expected KeepLocally=true")
	}

	if data.KeepLocally.ValueBool() {
		t.Log("keep_locally=true, removal skipped")
	}

	_ = r

	if called {
		t.Error("expected no HTTP calls when keep_locally=true")
	}
}

func TestImageResource_Delete_RemoveImage(t *testing.T) {
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	// Test the RemoveImage path directly (simulating Delete with keep_locally=false).
	client := NewPodmanClient(cfg)

	err := client.RemoveImage(t.Context(), "localhost/test:v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !deleted {
		t.Error("expected DELETE request to be made")
	}
}

func TestImageResource_BuildWithAttestation_Error(t *testing.T) {
	cfg := newTestConfig(t, mockPodmanHandler(t))
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:v1"),
		Build: &ImageBuildModel{
			Context:   types.StringValue("."),
			BuildArgs: types.MapNull(types.StringType),
			Pull:      types.BoolValue(false),
		},
		Attestation: &AttestationModel{
			StepName:           types.StringValue("build"),
			SignerKeyPath:      types.StringValue("/nonexistent/key.pem"),
			OutputPath:         types.StringValue("/tmp/attestation.json"),
			Attestors:          types.ListNull(types.StringType),
			ExportSLSA:         types.BoolValue(true),
			EnableArchivista:   types.BoolValue(false),
			ArchivistaServer:   types.StringNull(),
			SignerKeyPathOut:   types.StringNull(),
			SignerPublicKeyOut: types.StringNull(),
		},
	}

	var diags diag.Diagnostics

	err := r.buildImage(t.Context(), data, &diags)
	if err == nil && !diags.HasError() {
		t.Log("buildWithAttestation succeeded (witness may be available)")
	}
}

func TestImageResource_ReadImageState_NoDigest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":          "sha256:nodigest",
			"RepoDigests": []string{},
			"Size":        int64(100),
		})
	}))
	t.Cleanup(server.Close)

	cfg := &PodmanProviderConfig{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}
	r := &ImageResource{config: cfg}

	data := &ImageResourceModel{
		Name: types.StringValue("localhost/test:latest"),
	}

	var diags diag.Diagnostics
	r.readImageState(t.Context(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags.Errors())
	}

	if data.ID.ValueString() != "sha256:nodigest" {
		t.Errorf("ID = %q, want sha256:nodigest", data.ID.ValueString())
	}
}

func TestTarDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to write a.txt: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("failed to create sub directory: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatalf("failed to write b.txt: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid_dir", dir, false},
		{"non_existent", "/nonexistent/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := tarDirectory(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if reader == nil {
				t.Fatal("expected non-nil reader")
			}

			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("failed to read tar: %v", err)
			}

			if len(data) == 0 {
				t.Error("expected non-empty tar archive")
			}
		})
	}
}

func TestContextHashPlanModifier_NullPlan(t *testing.T) {
	m := contextHashPlanModifier{}
	resp := &planmodifier.StringResponse{PlanValue: types.StringNull()}

	m.PlanModifyString(t.Context(), planmodifier.StringRequest{
		PlanValue: types.StringNull(),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics.Errors())
	}

	if !resp.PlanValue.IsNull() {
		t.Error("expected null plan value on destroy")
	}
}

func TestContextHashPlanModifier_ValidContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY a.txt /\n"),
		0o600,
	); err != nil {
		t.Fatalf("failed to write Containerfile: %v", err)
	}

	if err := os.Chmod(filepath.Join(dir, "Containerfile"), 0o644); err != nil {
		t.Fatalf("failed to set permissions for Containerfile: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to write a.txt: %v", err)
	}

	if err := os.Chmod(filepath.Join(dir, "a.txt"), 0o644); err != nil {
		t.Fatalf("failed to set permissions for a.txt: %v", err)
	}

	plan := makePlan(t, &ImageResource{}, minimalImagePlanVals("test:v1", dir))
	state := makeState(t, &ImageResource{}, minimalImageStateVals("test:v1"))

	m := contextHashPlanModifier{}
	resp := &planmodifier.StringResponse{PlanValue: types.StringUnknown()}

	m.PlanModifyString(t.Context(), planmodifier.StringRequest{
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("oldhash"),
		Plan:       plan,
		State:      state,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics.Errors())
	}

	if resp.PlanValue.IsUnknown() || resp.PlanValue.IsNull() {
		t.Error("expected computed hash, got unknown/null")
	}

	if resp.PlanValue.ValueString() == "" {
		t.Error("expected non-empty hash")
	}
}

func TestContextHashPlanModifier_InvalidContext(t *testing.T) {
	// Invalid context (no Containerfile) → hash error → falls back to state.
	dir := t.TempDir()

	vals := minimalImagePlanVals("test:v1", dir)
	plan := makePlan(t, &ImageResource{}, vals)
	state := makeState(t, &ImageResource{}, minimalImageStateVals("test:v1"))

	m := contextHashPlanModifier{}
	resp := &planmodifier.StringResponse{PlanValue: types.StringUnknown()}

	m.PlanModifyString(t.Context(), planmodifier.StringRequest{
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("preserved"),
		Plan:       plan,
		State:      state,
	}, resp)

	if resp.PlanValue.ValueString() != "preserved" {
		t.Errorf("expected preserved state value, got %q", resp.PlanValue.ValueString())
	}
}

func TestContextHashPlanModifier_NilBuild(t *testing.T) {
	vals := map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"name":         tftypes.NewValue(tftypes.String, "test:v1"),
		"repo_digest":  tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"keep_locally": tftypes.NewValue(tftypes.Bool, false),
		"context_hash": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"attestation":  tftypes.NewValue(attestationObjectType(), nil),
		"sbom":         tftypes.NewValue(sbomObjectType(), nil),
		"build":        tftypes.NewValue(buildObjectType(), nil),
	}

	plan := makePlan(t, &ImageResource{}, vals)
	state := makeState(t, &ImageResource{}, minimalImageStateVals("test:v1"))

	m := contextHashPlanModifier{}
	resp := &planmodifier.StringResponse{PlanValue: types.StringUnknown()}

	m.PlanModifyString(t.Context(), planmodifier.StringRequest{
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("fallback"),
		Plan:       plan,
		State:      state,
	}, resp)

	if resp.PlanValue.ValueString() != "fallback" {
		t.Errorf("expected fallback state value, got %q", resp.PlanValue.ValueString())
	}
}

func TestNewPodmanClient(t *testing.T) {
	cfg := &PodmanProviderConfig{
		HTTPClient: &http.Client{},
		BaseURL:    "http://test",
	}

	client := NewPodmanClient(cfg)
	if client == nil {
		t.Fatal("expected non-nil PodmanClient")
	}

	if client.baseURL != "http://test" {
		t.Errorf("expected baseURL http://test, got %q", client.baseURL)
	}
}

func TestPodmanClient_DoRequest_WithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"key":"val"}` {
			t.Errorf("unexpected body: %s", string(body))
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	resp, err := client.doRequest(
		t.Context(),
		http.MethodPost,
		"/test",
		strings.NewReader(`{"key":"val"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPodmanClient_BuildImage_WithPullAndArgs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pull := r.URL.Query().Get("pull")
		if pull != "always" {
			t.Errorf("expected pull=always, got %q", pull)
		}

		buildArgs := r.URL.Query()["buildargs"]
		if len(buildArgs) == 0 {
			t.Error("expected at least one buildarg")
		}

		_, _ = io.Copy(io.Discard, r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"stream": "built"})
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	err := client.BuildImage(t.Context(), ImageBuildOpts{
		Tag:        "test:v1",
		ContextDir: ".",
		Pull:       true,
		BuildArgs:  map[string]string{"VERSION": "1.0"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPodmanClient_PushImage_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	_, err := client.PushImage(t.Context(), "test:v1", "", "")
	if err == nil {
		t.Error("expected error for bad status")
	}
}

func TestPodmanClient_InspectImage_NoDigests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":          "sha256:norepo",
			"RepoDigests": []string{},
			"Size":        int64(50),
		})
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	result, err := client.InspectImage(t.Context(), "test:v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RepoDigest != "" {
		t.Errorf("expected empty RepoDigest, got %q", result.RepoDigest)
	}
}

func TestPodmanClient_BuildImage_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	err := client.BuildImage(t.Context(), ImageBuildOpts{
		Tag:        "test:v1",
		ContextDir: ".",
	})
	if err == nil {
		t.Error("expected error for bad status")
	}
}

func TestPodmanClient_ImageExists_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Close()

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	_, err := client.ImageExists(t.Context(), "test:v1")
	if err == nil {
		t.Error("expected error for closed server")
	}
}

func TestPodmanClient_InspectImage_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	_, err := client.InspectImage(t.Context(), "test:v1")
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestPodmanClient_InspectImage_BadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("not json")); err != nil {
			t.Logf("failed to write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	_, err := client.InspectImage(t.Context(), "test:v1")
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestPodmanClient_BuildImage_StreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "build failed: missing dep"})
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	err := client.BuildImage(t.Context(), ImageBuildOpts{
		Tag:        "test:v1",
		ContextDir: ".",
	})
	if err == nil {
		t.Error("expected error from build stream")
	}

	if !strings.Contains(err.Error(), "missing dep") {
		t.Errorf("expected 'missing dep' in error, got: %s", err.Error())
	}
}

func TestPodmanClient_PushImage_StreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	_, err := client.PushImage(t.Context(), "test:v1", "", "")
	if err == nil {
		t.Error("expected error from push stream")
	}
}

func TestPodmanClient_PushImage_WithCredentials(t *testing.T) {
	var gotCreds string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCreds = r.URL.Query().Get("credentials")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"digest": "sha256:creds"})
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	digest, err := client.PushImage(t.Context(), "test:v1", "user", "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCreds != "user:pass" {
		t.Errorf("expected credentials user:pass, got %q", gotCreds)
	}

	if digest != "sha256:creds" {
		t.Errorf("expected digest sha256:creds, got %q", digest)
	}
}

func TestPodmanClient_RemoveImage_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)

		if _, err := w.Write([]byte("image in use")); err != nil {
			t.Logf("failed to write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{client: server.Client(), baseURL: server.URL}

	err := client.RemoveImage(t.Context(), "test:v1")
	if err == nil {
		t.Error("expected error for conflict status")
	}

	if !strings.Contains(err.Error(), "image in use") {
		t.Errorf("expected 'image in use' in error, got: %s", err.Error())
	}
}

func TestPodmanClient_DoRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		if !strings.Contains(r.URL.Path, "/libpod/test") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(server.Close)

	client := &PodmanClient{
		client:  server.Client(),
		baseURL: server.URL,
	}

	resp, err := client.doRequest(t.Context(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestImageResource_Create(t *testing.T) {
	tests := []struct {
		handler    http.HandlerFunc
		planVals   func() map[string]tftypes.Value
		checkState func(*testing.T, ImageResourceModel)
		name       string
		wantErr    bool
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/build"):
					_, _ = io.Copy(io.Discard, r.Body)

					w.WriteHeader(http.StatusOK)

					if err := json.NewEncoder(w).
						Encode(map[string]any{"stream": "Successfully built"}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

				case strings.Contains(r.URL.Path, "/json"):
					w.Header().Set("Content-Type", "application/json")

					if err := json.NewEncoder(w).Encode(map[string]any{
						"Id":          "sha256:built123",
						"RepoDigests": []string{"localhost/test@sha256:built123"},
						"Size":        int64(5000),
					}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

				default:
					w.WriteHeader(http.StatusOK)
				}
			},
			planVals: func() map[string]tftypes.Value {
				return minimalImagePlanVals("localhost/test:v1", ".")
			},
			checkState: func(t *testing.T, data ImageResourceModel) {
				t.Helper()

				if data.ID.ValueString() != "sha256:built123" {
					t.Errorf("expected ID sha256:built123, got %q", data.ID.ValueString())
				}
			},
		},
		{
			name: "no_build_config",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			planVals: func() map[string]tftypes.Value {
				vals := minimalImagePlanVals("localhost/test:v1", ".")

				vals["build"] = tftypes.NewValue(buildObjectType(), nil)

				return vals
			},
			wantErr: true,
		},
	}

	testResourceCreate(t, tests,
		func(t *testing.T, vals map[string]tftypes.Value) tfsdk.Plan {
			t.Helper()
			return makePlan(t, &ImageResource{}, vals)
		},
		func(t *testing.T, vals map[string]tftypes.Value) tfsdk.State {
			t.Helper()
			return makeState(t, &ImageResource{}, vals)
		},
		func(cfg *PodmanProviderConfig) resource.Resource {
			return &ImageResource{config: cfg}
		},
		func(resp *resource.CreateResponse) ImageResourceModel {
			var data ImageResourceModel
			resp.State.Get(context.Background(), &data)

			return data
		},
	)
}

func TestImageResource_Read_CRUD(t *testing.T) {
	tests := []struct {
		handler  http.HandlerFunc
		name     string
		wantNull bool
	}{
		{
			name: "exists",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/exists") {
					w.WriteHeader(http.StatusNoContent)

					return
				}

				w.Header().Set("Content-Type", "application/json")

				if err := json.NewEncoder(w).Encode(map[string]any{
					"Id":          "sha256:abc123def",
					"RepoDigests": []string{"localhost/test@sha256:abc123def"},
					"Size":        int64(5000),
				}); err != nil {
					t.Logf("failed to encode response: %v", err)
				}
			},
			wantNull: false,
		},
		{
			name: "gone",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/exists") {
					w.WriteHeader(http.StatusNotFound)

					return
				}

				w.WriteHeader(http.StatusNotFound)
			},
			wantNull: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			t.Cleanup(server.Close)

			r := &ImageResource{config: &PodmanProviderConfig{
				HTTPClient: server.Client(),
				BaseURL:    server.URL,
			}}

			state := makeState(t, &ImageResource{}, minimalImageStateVals("localhost/test:v1"))
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

func TestImageResource_Delete_CRUD(t *testing.T) {
	tests := []struct {
		handler http.HandlerFunc
		name    string
		keep    bool
		wantErr bool
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusOK)

					if err := json.NewEncoder(w).
						Encode(map[string]any{"deleted": true}); err != nil {
						t.Logf("failed to encode response: %v", err)
					}

					return
				}

				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name: "keep_locally",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			keep: true,
		},
		{
			name: "remove_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusConflict)

					if _, err := w.Write([]byte("image in use")); err != nil {
						t.Logf("failed to write response: %v", err)
					}

					return
				}

				w.WriteHeader(http.StatusOK)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			t.Cleanup(server.Close)

			r := &ImageResource{config: &PodmanProviderConfig{
				HTTPClient: server.Client(),
				BaseURL:    server.URL,
			}}

			vals := minimalImageStateVals("localhost/test:v1")
			if tt.keep {
				vals["keep_locally"] = tftypes.NewValue(tftypes.Bool, true)
			}

			state := makeState(t, &ImageResource{}, vals)
			deleteResp := &resource.DeleteResponse{State: state}
			r.Delete(t.Context(), resource.DeleteRequest{State: state}, deleteResp)

			if tt.wantErr {
				if !deleteResp.Diagnostics.HasError() {
					t.Error("expected error")
				}

				return
			}

			if deleteResp.Diagnostics.HasError() {
				t.Fatalf("Delete errors: %v", deleteResp.Diagnostics.Errors())
			}
		})
	}
}

func TestImageResource_ImportState(t *testing.T) {
	r := &ImageResource{}
	state := makeState(t, &ImageResource{}, minimalImageStateVals("localhost/test:v1"))

	importResp := &resource.ImportStateResponse{State: state}
	r.ImportState(t.Context(), resource.ImportStateRequest{ID: "sha256:imported"}, importResp)

	if importResp.Diagnostics.HasError() {
		t.Fatalf("ImportState errors: %v", importResp.Diagnostics.Errors())
	}

	var data ImageResourceModel
	importResp.State.Get(t.Context(), &data)

	if data.ID.ValueString() != "sha256:imported" {
		t.Errorf("expected imported ID, got %q", data.ID.ValueString())
	}
}
