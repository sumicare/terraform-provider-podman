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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &ImageResource{}
	_ resource.ResourceWithConfigure   = &ImageResource{}
	_ resource.ResourceWithImportState = &ImageResource{}
)

//nolint:ireturn // false positive
func NewImageResource() resource.Resource {
	return &ImageResource{}
}

type ImageResource struct {
	config *PodmanProviderConfig
}

type ImageBuildModel struct {
	Context   types.String `tfsdk:"context"`
	BuildArgs types.Map    `tfsdk:"build_args"`
	Pull      types.Bool   `tfsdk:"pull"`
}

type ImageResourceModel struct {
	Build              *ImageBuildModel `tfsdk:"build"`
	ID                 types.String     `tfsdk:"id"`
	Name               types.String     `tfsdk:"name"`
	RepoDigest         types.String     `tfsdk:"repo_digest"`
	ContextHash        types.String     `tfsdk:"context_hash"`
	SBOMPath           types.String     `tfsdk:"sbom_path"`
	SBOMContent        types.String     `tfsdk:"sbom_content"`
	AttestationPath    types.String     `tfsdk:"attestation_path"`
	AttestationContent types.String     `tfsdk:"attestation_content"`
	CosignPublicKey    types.String     `tfsdk:"cosign_public_key"`
	KeepLocally        types.Bool       `tfsdk:"keep_locally"`
}

// imageBaseName extracts a short base name from a full image reference for
// use in deterministic file naming (e.g. SBOM and attestation output paths).
// "repo.example.com/org/myimage:v1" → "myimage"
func imageBaseName(ref string) string {
	// Strip tag or digest
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		if !strings.Contains(ref[idx:], "/") {
			ref = ref[:idx]
		}
	}

	if idx := strings.LastIndex(ref, "@"); idx > 0 {
		ref = ref[:idx]
	}

	return filepath.Base(ref)
}

func extractBuildArgs(m types.Map) map[string]string {
	if m.IsNull() || m.IsUnknown() {
		return nil
	}

	result := make(map[string]string, len(m.Elements()))

	for k, v := range m.Elements() {
		if sv, ok := v.(types.String); ok && !sv.IsNull() && !sv.IsUnknown() {
			result[k] = sv.ValueString()
		}
	}

	return result
}

// contextHashPlanModifier computes a SHA256 hash of the build context during
// planning so that file changes (COPY/ADD sources, Containerfile edits, git
// ref updates) are detected and trigger an image rebuild.
type contextHashPlanModifier struct{}

func (m contextHashPlanModifier) Description(_ context.Context) string {
	return "Computes a hash of the build context to detect Containerfile, source file, and git ref changes."
}

func (m contextHashPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m contextHashPlanModifier) PlanModifyString(
	ctx context.Context,
	req planmodifier.StringRequest,
	resp *planmodifier.StringResponse,
) {
	// On destroy the plan value is null; preserve it.
	if req.PlanValue.IsNull() {
		return
	}

	var plan ImageResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Build == nil || plan.Build.Context.IsNull() {
		if !req.StateValue.IsNull() {
			resp.PlanValue = req.StateValue
		}

		return
	}

	hash, err := BuildContextHash(
		ctx,
		plan.Build.Context.ValueString(),
		extractBuildArgs(plan.Build.BuildArgs),
	)
	if err != nil {
		tflog.Warn(ctx, "Could not compute build context hash, skipping change detection",
			map[string]any{"error": err.Error()})

		if !req.StateValue.IsNull() {
			resp.PlanValue = req.StateValue
		}

		return
	}

	resp.PlanValue = types.StringValue(hash)
}

func (r *ImageResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*PodmanProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *PodmanProviderConfig, got: %T", req.ProviderData),
		)

		return
	}

	r.config = config
}

func (r *ImageResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data ImageResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Build == nil {
		resp.Diagnostics.AddError(
			"Build configuration required",
			"The build block is required. This provider only supports building images from Containerfiles.",
		)

		return
	}

	if err := r.buildImage(ctx, &data, &resp.Diagnostics); err != nil {
		return
	}

	hash, err := BuildContextHash(
		ctx,
		data.Build.Context.ValueString(),
		extractBuildArgs(data.Build.BuildArgs),
	)
	if err != nil {
		tflog.Warn(
			ctx,
			"Could not compute build context hash",
			map[string]any{"error": err.Error()},
		)

		data.ContextHash = types.StringValue("unknown")
	} else {
		data.ContextHash = types.StringValue(hash)
	}

	r.readImageState(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	// Always generate SBOM for provenance.
	baseName := imageBaseName(data.Name.ValueString())
	sbomPath := filepath.Join(".sbom", baseName+".cyclonedx.json")
	data.SBOMPath = types.StringValue(sbomPath)

	var sbomDiags diag.Diagnostics
	r.generateSBOM(ctx, &data, &sbomDiags)

	if sbomDiags.HasError() {
		for _, d := range sbomDiags.Errors() {
			tflog.Warn(ctx, "SBOM provenance generation failed (non-fatal)",
				map[string]any{"summary": d.Summary(), "detail": d.Detail()})
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail()+
				" Install syft to enable automatic SBOM generation.")
		}
	}

	// Persist file contents in state so they can be restored if deleted.
	r.captureFileContents(ctx, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (*ImageResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_image"
}

func (r *ImageResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data ImageResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If the image was removed outside Terraform, drop it from state.
	name := data.Name.ValueString()
	client := NewPodmanClient(r.config)

	exists, err := client.ImageExists(ctx, name)
	if err != nil || !exists {
		tflog.Warn(ctx, "Image no longer exists, removing from state", map[string]any{
			"name": name,
		})

		resp.State.RemoveResource(ctx)

		return
	}

	r.readImageState(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	// Backfill SBOM if the file is missing on disk.
	r.ensureSBOM(ctx, &data, &resp.Diagnostics)

	// Backfill attestation if the file is missing on disk.
	r.ensureAttestation(ctx, &data, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (*ImageResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Manages the lifecycle of a Podman image built from a Containerfile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for this resource (the image ID).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the image, including any tags (e.g., registry.example.com/org/myimage:v1).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"keep_locally": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "If true, the image will not be deleted on destroy.",
			},
			"repo_digest": schema.StringAttribute{
				Computed:    true,
				Description: "The first repo digest of the image (e.g., registry.example.com/org/myimage@sha256:abc123).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"context_hash": schema.StringAttribute{
				Computed: true,
				Description: "SHA256 hash of the build context (Containerfile content, COPY/ADD " +
					"referenced files, resolved git commit hashes for ADD git refs). " +
					"Changes to this value automatically trigger an image rebuild.",
				PlanModifiers: []planmodifier.String{
					contextHashPlanModifier{},
					stringplanmodifier.RequiresReplace(),
				},
			},
			"sbom_path": schema.StringAttribute{
				Computed:    true,
				Description: "Path where the CycloneDX SBOM was written. Always generated under .sbom/ directory.",
			},
			"sbom_content": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "CycloneDX SBOM content stored in state for restore.",
			},
			"attestation_path": schema.StringAttribute{
				Computed:    true,
				Description: "Path where the in-toto witness attestation envelope was written. Always generated under .sbom/ directory.",
			},
			"attestation_content": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "In-toto witness attestation envelope stored in state for restore.",
			},
			"cosign_public_key": schema.StringAttribute{
				Computed:    true,
				Description: "PEM-encoded cosign public key used for signing. Auto-generated in .cosign/ if not provided.",
			},
			"build": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Configuration for building the image from a Containerfile.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
				Attributes: map[string]schema.Attribute{
					"context": schema.StringAttribute{
						Required:    true,
						Description: "Path to the build context directory.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"build_args": schema.MapAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Build-time variables passed as key=value pairs.",
					},
					"pull": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "If true, always pull newer versions of base images.",
					},
				},
			},
		},
	}
}

func (*ImageResource) Update(
	_ context.Context,
	_ resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"Image resources do not support in-place updates. "+
			"All changes require replacement. This should be handled automatically by Terraform.",
	)
}

func (r *ImageResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data ImageResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.KeepLocally.ValueBool() {
		tflog.Debug(ctx, "Keep locally enabled, skipping image removal", map[string]any{
			"name": data.Name.ValueString(),
		})

		return
	}

	name := data.Name.ValueString()
	client := NewPodmanClient(r.config)

	err := client.RemoveImage(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error removing image",
			fmt.Sprintf("Could not remove image %s: %s", name, err.Error()),
		)
	}
}

func (*ImageResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *ImageResource) toBuildOpts(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) (ImageBuildOpts, error) {
	build := data.Build

	opts := ImageBuildOpts{
		Tag:  data.Name.ValueString(),
		Pull: build.Pull.ValueBool(),
	}

	if !build.Context.IsNull() && build.Context.ValueString() != "" {
		opts.ContextDir = build.Context.ValueString()
	} else {
		opts.ContextDir = "."
	}

	if !build.BuildArgs.IsNull() {
		buildArgs := make(map[string]string)
		diags.Append(build.BuildArgs.ElementsAs(ctx, &buildArgs, false)...)

		if diags.HasError() {
			return opts, errors.New("failed to parse build_args")
		}

		opts.BuildArgs = buildArgs
	}

	return opts, nil
}

func (r *ImageResource) buildImage(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) error {
	opts, err := r.toBuildOpts(ctx, data, diags)
	if err != nil {
		return err
	}

	if diags.HasError() {
		return errors.New("diagnostics error during build option assembly")
	}

	client := NewPodmanClient(r.config)

	// Always build with witness attestation for supply chain provenance.
	return r.buildWithAttestation(ctx, data, client, opts, diags)
}

// buildWithAttestation wraps the build with go-witness to produce a signed DSSE envelope.
func (r *ImageResource) buildWithAttestation(
	ctx context.Context,
	data *ImageResourceModel,
	client *PodmanClient,
	buildOpts ImageBuildOpts,
	diags *diag.Diagnostics,
) error {
	cosignClient := NewCosignClient()

	result, err := cosignClient.EnsureKeyPair(ctx, ".cosign")
	if err != nil {
		diags.AddError(
			"Error generating signer key pair",
			"Could not generate signer key pair for attestation: "+err.Error(),
		)

		return err
	}

	if result.Reused {
		diags.AddWarning(
			"Reusing auto-generated cosign key pair",
			fmt.Sprintf("Reusing existing key pair at %s. "+
				"Provide cosign_key_path in the provider config to use your own key.", result.PrivateKeyPath),
		)
	} else {
		diags.AddWarning(
			"Auto-generated cosign key pair",
			fmt.Sprintf(
				"A new cosign key pair was generated at %s. "+
					"Provide cosign_key_path in the provider config to use your own key.",
				result.PrivateKeyPath,
			),
		)
	}

	data.CosignPublicKey = types.StringValue(string(result.PublicKeyPEM))

	baseName := imageBaseName(data.Name.ValueString())
	attestationPath := filepath.Join(".sbom", baseName+".intoto.json")
	data.AttestationPath = types.StringValue(attestationPath)

	witness := NewWitnessClient()

	err = witness.AttestBuild(ctx, WitnessRunOpts{
		StepName:      "build",
		SignerKeyPath: result.PrivateKeyPath,
		Passphrase:    result.Passphrase,
		OutputPath:    attestationPath,
		WorkingDir:    buildOpts.ContextDir,
	}, func() error {
		return client.BuildImage(ctx, buildOpts)
	})
	if err != nil {
		diags.AddError(
			"Error building image with witness attestation",
			fmt.Sprintf("witness attestation failed for image %s: %s", buildOpts.Tag, err.Error()),
		)

		return err
	}

	return nil
}

func (r *ImageResource) generateSBOM(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) {
	name := data.Name.ValueString()
	sbomPath := data.SBOMPath.ValueString()

	sbomClient := NewSBOMClient()

	err := sbomClient.GenerateSBOM(ctx, SBOMOpts{
		ImageRef:   name,
		OutputPath: sbomPath,
		Format:     "cyclonedx",
	})
	if err != nil {
		diags.AddError(
			"Error generating SBOM",
			fmt.Sprintf("SBOM generation failed for %s: %s", name, err.Error()),
		)
	}
}

// ensureSBOM restores the CycloneDX SBOM from state when the file is missing
// on disk. Falls back to regeneration if state content is empty (backward compat).
func (r *ImageResource) ensureSBOM(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) {
	baseName := imageBaseName(data.Name.ValueString())
	sbomPath := filepath.Join(".sbom", baseName+".cyclonedx.json")

	// Always ensure sbom_path is populated in state.
	if data.SBOMPath.IsNull() || data.SBOMPath.ValueString() == "" {
		data.SBOMPath = types.StringValue(sbomPath)
	} else {
		sbomPath = data.SBOMPath.ValueString()
	}

	// If the file already exists, nothing to do.
	if _, err := os.Stat(sbomPath); err == nil {
		return
	}

	// Restore from state if available.
	if !data.SBOMContent.IsNull() && data.SBOMContent.ValueString() != "" {
		tflog.Info(ctx, "SBOM file missing, restoring from state", map[string]any{
			"image": data.Name.ValueString(),
			"path":  sbomPath,
		})

		if dir := filepath.Dir(sbomPath); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
		}

		if err := os.WriteFile(sbomPath, []byte(data.SBOMContent.ValueString()), 0o644); err != nil {
			tflog.Warn(ctx, "SBOM restore from state failed",
				map[string]any{"error": err.Error()})
		}

		return
	}

	// Fallback: regenerate if state content is empty (pre-existing resources).
	tflog.Info(ctx, "SBOM file missing, regenerating (no state content)", map[string]any{
		"image": data.Name.ValueString(),
		"path":  sbomPath,
	})

	var sbomDiags diag.Diagnostics
	r.generateSBOM(ctx, data, &sbomDiags)

	if sbomDiags.HasError() {
		for _, d := range sbomDiags.Errors() {
			tflog.Warn(ctx, "SBOM backfill failed (non-fatal)",
				map[string]any{"summary": d.Summary(), "detail": d.Detail()})
			diags.AddWarning(d.Summary(), d.Detail()+
				" Install syft to enable automatic SBOM generation.")
		}
	}
}

// ensureAttestation restores the in-toto witness attestation from state when
// the file is missing on disk. The original build attestation bytes are stored
// in state so they can be restored byte-for-byte.
func (r *ImageResource) ensureAttestation(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) {
	baseName := imageBaseName(data.Name.ValueString())
	attestPath := filepath.Join(".sbom", baseName+".intoto.json")

	// Always ensure attestation_path is populated in state.
	if data.AttestationPath.IsNull() || data.AttestationPath.ValueString() == "" {
		data.AttestationPath = types.StringValue(attestPath)
	} else {
		attestPath = data.AttestationPath.ValueString()
	}

	// If the file already exists, nothing to do.
	if _, err := os.Stat(attestPath); err == nil {
		return
	}

	// Restore from state if available.
	if !data.AttestationContent.IsNull() && data.AttestationContent.ValueString() != "" {
		tflog.Info(ctx, "Attestation file missing, restoring from state", map[string]any{
			"image": data.Name.ValueString(),
			"path":  attestPath,
		})

		if dir := filepath.Dir(attestPath); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
		}

		if err := os.WriteFile(attestPath, []byte(data.AttestationContent.ValueString()), 0o600); err != nil {
			tflog.Warn(ctx, "Attestation restore from state failed",
				map[string]any{"error": err.Error()})
		}

		return
	}

	tflog.Warn(ctx, "Attestation file missing and no state content available",
		map[string]any{"image": data.Name.ValueString(), "path": attestPath})
	diags.AddWarning(
		"Attestation file missing",
		fmt.Sprintf("Attestation for %s is missing and cannot be restored. "+
			"It will be recreated on the next image rebuild.", data.Name.ValueString()),
	)
}

// captureFileContents reads the SBOM and attestation files from disk and
// stores their content in state so they can be restored if deleted.
func (*ImageResource) captureFileContents(ctx context.Context, data *ImageResourceModel) {
	if path := data.SBOMPath.ValueString(); path != "" {
		if content, err := os.ReadFile(path); err == nil {
			data.SBOMContent = types.StringValue(string(content))
		} else {
			tflog.Warn(ctx, "Could not read SBOM for state capture",
				map[string]any{"path": path, "error": err.Error()})
		}
	}

	if path := data.AttestationPath.ValueString(); path != "" {
		if content, err := os.ReadFile(path); err == nil {
			data.AttestationContent = types.StringValue(string(content))
		} else {
			tflog.Warn(ctx, "Could not read attestation for state capture",
				map[string]any{"path": path, "error": err.Error()})
		}
	}
}

func (r *ImageResource) readImageState(
	ctx context.Context,
	data *ImageResourceModel,
	diags *diag.Diagnostics,
) {
	name := data.Name.ValueString()
	client := NewPodmanClient(r.config)

	result, err := client.InspectImage(ctx, name)
	if err != nil {
		diags.AddError(
			"Error reading image",
			fmt.Sprintf("Could not inspect image %s: %s", name, err.Error()),
		)

		return
	}

	data.ID = types.StringValue(result.ID)

	if result.RepoDigest != "" {
		data.RepoDigest = types.StringValue(result.RepoDigest)
	} else {
		data.RepoDigest = types.StringValue("")
	}
}
