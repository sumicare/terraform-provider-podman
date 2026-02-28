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

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
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

type AttestationModel struct {
	Attestors          types.List   `tfsdk:"attestors"`
	StepName           types.String `tfsdk:"step_name"`
	SignerKeyPath      types.String `tfsdk:"signer_key_path"`
	OutputPath         types.String `tfsdk:"output_path"`
	ArchivistaServer   types.String `tfsdk:"archivista_server"`
	SignerKeyPathOut   types.String `tfsdk:"signer_key_path_out"`
	SignerPublicKeyOut types.String `tfsdk:"signer_public_key_out"`
	ExportSLSA         types.Bool   `tfsdk:"export_slsa"`
	EnableArchivista   types.Bool   `tfsdk:"enable_archivista"`
}

type SBOMModel struct {
	OutputPath types.String `tfsdk:"output_path"`
	Format     types.String `tfsdk:"format"`
}

type ImageResourceModel struct {
	Build       *ImageBuildModel  `tfsdk:"build"`
	Attestation *AttestationModel `tfsdk:"attestation"`
	SBOM        *SBOMModel        `tfsdk:"sbom"`
	ID          types.String      `tfsdk:"id"`
	Name        types.String      `tfsdk:"name"`
	RepoDigest  types.String      `tfsdk:"repo_digest"`
	ContextHash types.String      `tfsdk:"context_hash"`
	KeepLocally types.Bool        `tfsdk:"keep_locally"`
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

	// Always generate SBOM for provenance. If the user did not configure the
	// sbom block, populate it with sensible defaults so that provenance is
	// never silently disabled.
	sbomExplicit := data.SBOM != nil
	if !sbomExplicit {
		tflog.Info(ctx, "No SBOM block configured; applying default SBOM provenance settings")

		data.SBOM = &SBOMModel{
			OutputPath: types.StringValue("sbom.cyclonedx.json"),
			Format:     types.StringValue("cyclonedx"),
		}
	}

	var sbomDiags diag.Diagnostics
	r.generateSBOM(ctx, &data, &sbomDiags)

	if sbomDiags.HasError() {
		if sbomExplicit {
			// User explicitly requested SBOM — propagate as hard error.
			resp.Diagnostics.Append(sbomDiags...)

			return
		}
		// Default provenance SBOM failed (e.g. syft not installed) — warn
		// but do not block the build.
		for _, d := range sbomDiags.Errors() {
			tflog.Warn(ctx, "Default SBOM provenance generation failed (non-fatal)",
				map[string]any{"summary": d.Summary(), "detail": d.Detail()})
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail()+
				" To suppress this warning, install syft or explicitly configure the sbom block.")
		}
	}

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
			"sbom": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Description: "SBOM generation configuration. Syft scans the built image to produce " +
					"a software bill of materials in CycloneDX or SPDX format. " +
					"Enabled by default for provenance; omit or set to null to use defaults.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
				Attributes: map[string]schema.Attribute{
					"output_path": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("sbom.cyclonedx.json"),
						Description: "File path where the SBOM will be written. Defaults to 'sbom.cyclonedx.json'.",
					},
					"format": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("cyclonedx"),
						Description: "SBOM output format ('cyclonedx' or 'spdx-json'). Defaults to 'cyclonedx'.",
					},
				},
			},
			"attestation": schema.SingleNestedAttribute{
				Optional: true,
				Description: "In-toto Witness attestation configuration. When set, the build command is " +
					"wrapped with `witness run` to produce a signed DSSE envelope containing " +
					"supply chain attestations (materials, products, SLSA provenance). " +
					"A signer_key_path is required to enable attestation.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
				Attributes: map[string]schema.Attribute{
					"step_name": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("build"),
						Description: "The witness step name (e.g., 'build'). Used in policy evaluation. Defaults to 'build'.",
					},
					"signer_key_path": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						Description: "Path to the PEM-encoded private key used by witness to sign the attestation envelope. " +
							"If omitted, a new cosign key pair is auto-generated.",
					},
					"output_path": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("attestation.json"),
						Description: "File path where the signed DSSE attestation envelope will be written. Defaults to 'attestation.json'.",
					},
					"attestors": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Additional witness attestors to enable (e.g., 'slsa', 'gcp', 'gitlab'). " +
							"Default attestors (material, product, command-run) are always active.",
					},
					"export_slsa": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
						Description: "Export SLSA provenance predicate (--attestor-slsa-export). Defaults to true.",
					},
					"enable_archivista": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Store attestations in an Archivista server for remote retrieval.",
					},
					"archivista_server": schema.StringAttribute{
						Optional:    true,
						Description: "Archivista server URL. Required when enable_archivista is true.",
					},
					"signer_key_path_out": schema.StringAttribute{
						Computed: true,
						Description: "The signer private key path used for attestation. Reflects the input signer_key_path " +
							"or the path to the auto-generated key.",
					},
					"signer_public_key_out": schema.StringAttribute{
						Computed: true,
						Description: "The signer public key path. Set when a key pair was auto-generated. " +
							"Empty when an existing key was provided.",
					},
				},
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

	if data.Attestation != nil {
		return r.buildWithAttestation(ctx, data, client, opts, diags)
	}

	tflog.Warn(ctx, "No attestation block configured; building without witness attestation. "+
		"Set the attestation block with a signer_key_path to enable supply chain provenance signing.")

	if buildErr := client.BuildImage(ctx, opts); buildErr != nil {
		diags.AddError(
			"Error building image",
			fmt.Sprintf("Could not build image %s: %s", opts.Tag, buildErr.Error()),
		)

		return buildErr
	}

	return nil
}

// buildWithAttestation wraps the build with go-witness to produce a signed DSSE envelope.
func (r *ImageResource) buildWithAttestation(
	ctx context.Context,
	data *ImageResourceModel,
	client *PodmanClient,
	buildOpts ImageBuildOpts,
	diags *diag.Diagnostics,
) error {
	att := data.Attestation

	var attestors []string
	if !att.Attestors.IsNull() {
		diags.Append(att.Attestors.ElementsAs(ctx, &attestors, false)...)

		if diags.HasError() {
			return errors.New("failed to parse attestors")
		}
	}

	archivistaServer := ""
	if !att.ArchivistaServer.IsNull() {
		archivistaServer = att.ArchivistaServer.ValueString()
	}

	var signerKeyPath string
	if !att.SignerKeyPath.IsNull() && att.SignerKeyPath.ValueString() != "" {
		signerKeyPath = att.SignerKeyPath.ValueString()
		att.SignerKeyPathOut = types.StringValue(signerKeyPath)
		att.SignerPublicKeyOut = types.StringValue("")
	} else {
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
				fmt.Sprintf("No signer_key_path was provided. Reusing existing key pair at %s. "+
					"Set signer_key_path explicitly to use your own key.", result.PrivateKeyPath),
			)
		} else {
			diags.AddWarning(
				"Auto-generated cosign key pair",
				fmt.Sprintf(
					"No signer_key_path was provided. A new cosign key pair was generated at %s. "+
						"Set signer_key_path explicitly to use your own key.",
					result.PrivateKeyPath,
				),
			)
		}

		signerKeyPath = result.PrivateKeyPath
		att.SignerKeyPathOut = types.StringValue(result.PrivateKeyPath)
		att.SignerPublicKeyOut = types.StringValue(result.PublicKeyPath)
	}

	witness := NewWitnessClient()

	err := witness.AttestBuild(ctx, WitnessRunOpts{
		StepName:         att.StepName.ValueString(),
		SignerKeyPath:    signerKeyPath,
		OutputPath:       att.OutputPath.ValueString(),
		Attestors:        attestors,
		ExportSLSA:       att.ExportSLSA.ValueBool(),
		EnableArchivista: att.EnableArchivista.ValueBool(),
		ArchivistaServer: archivistaServer,
		WorkingDir:       buildOpts.ContextDir,
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
	sbom := data.SBOM

	sbomClient := NewSBOMClient()

	err := sbomClient.GenerateSBOM(ctx, SBOMOpts{
		ImageRef:   name,
		OutputPath: sbom.OutputPath.ValueString(),
		Format:     sbom.Format.ValueString(),
	})
	if err != nil {
		diags.AddError(
			"Error generating SBOM",
			fmt.Sprintf("SBOM generation failed for %s: %s", name, err.Error()),
		)
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
