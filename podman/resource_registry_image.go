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
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &RegistryImageResource{}
	_ resource.ResourceWithConfigure   = &RegistryImageResource{}
	_ resource.ResourceWithImportState = &RegistryImageResource{}
)

// NewRegistryImageResource is a helper function to simplify the provider implementation.
//
//nolint:ireturn // false positive
func NewRegistryImageResource() resource.Resource {
	return &RegistryImageResource{}
}

// RegistryImageResource is the resource implementation.
// RegistryImageResourceModel describes the resource data model.
type (
	RegistryImageResource struct {
		config *PodmanProviderConfig
	}

	RegistryImageResourceModel struct {
		AuthConfig   *AuthConfigModel `tfsdk:"auth_config"`
		Signing      *SigningModel    `tfsdk:"signing"`
		ID           types.String     `tfsdk:"id"`
		Name         types.String     `tfsdk:"name"`
		Digest       types.String     `tfsdk:"digest"`
		KeepRemotely types.Bool       `tfsdk:"keep_remotely"`
	}

	// SigningModel describes sigstore/cosign signing configuration.
	SigningModel struct {
		CosignKeyPath      types.String `tfsdk:"cosign_key_path"`
		CosignPassword     types.String `tfsdk:"cosign_password"`
		FulcioURL          types.String `tfsdk:"fulcio_url"`
		RekorURL           types.String `tfsdk:"rekor_url"`
		AttestationPath    types.String `tfsdk:"attestation_path"`
		PredicateType      types.String `tfsdk:"predicate_type"`
		SBOMPath           types.String `tfsdk:"sbom_path"`
		CosignKeyPathOut   types.String `tfsdk:"cosign_key_path_out"`
		CosignPublicKeyOut types.String `tfsdk:"cosign_public_key_out"`
		Keyless            types.Bool   `tfsdk:"keyless"`
	}

	// AuthConfigModel represents authentication configuration for registry operations.
	AuthConfigModel struct {
		Address  types.String `tfsdk:"address"`
		Username types.String `tfsdk:"username"`
		Password types.String `tfsdk:"password"`
	}
)

// Configure adds the provider configured client to the resource.
func (r *RegistryImageResource) Configure(
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
			"Expected *PodmanProviderConfig",
		)

		return
	}

	r.config = config
}

// Create creates the resource and sets the initial Terraform state.
//

func (r *RegistryImageResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data RegistryImageResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()
	client := NewPodmanClient(r.config)

	username, password := "", ""
	if data.AuthConfig != nil && !data.AuthConfig.Username.IsNull() &&
		!data.AuthConfig.Password.IsNull() {
		username = data.AuthConfig.Username.ValueString()
		password = data.AuthConfig.Password.ValueString()
	}

	digest, err := client.PushImage(ctx, name, username, password)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error pushing image to registry",
			fmt.Sprintf("Could not push image %s: %s", name, err.Error()),
		)

		return
	}

	data.ID = types.StringValue(name)

	if digest != "" {
		data.Digest = types.StringValue(digest)
	} else {
		// Fallback: get digest via inspect
		result, inspectErr := client.InspectImage(ctx, name)
		if inspectErr == nil && result.RepoDigest != "" {
			data.Digest = types.StringValue(result.RepoDigest)
		}
	}

	// Sign the pushed image with cosign if signing is configured
	if data.Signing != nil {
		r.signImage(ctx, &data, &resp.Diagnostics)

		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Metadata returns the resource type name.
func (*RegistryImageResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_registry_image"
}

// Read refreshes the Terraform state with the latest data.
//

func (r *RegistryImageResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data RegistryImageResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Registry images are remote; we just verify the local image still exists
	client := NewPodmanClient(r.config)

	exists, err := client.ImageExists(ctx, data.Name.ValueString())
	if err != nil || !exists {
		resp.State.RemoveResource(ctx)

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Schema defines the schema for the resource.
func (*RegistryImageResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Pushes a Podman image to a container registry.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the registry image resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The full image name including registry and tag (e.g., registry.example.com/myimage:v1.0).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"keep_remotely": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "If true, the image will not be deleted from the registry on destroy.",
			},
			"digest": schema.StringAttribute{
				Computed:    true,
				Description: "The digest of the pushed image.",
			},
			"auth_config": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Authentication configuration for the registry.",
				Attributes: map[string]schema.Attribute{
					"address": schema.StringAttribute{
						Required:    true,
						Description: "The registry address (e.g., registry.example.com).",
					},
					"username": schema.StringAttribute{
						Required:    true,
						Description: "The username for registry authentication.",
					},
					"password": schema.StringAttribute{
						Required:    true,
						Sensitive:   true,
						Description: "The password for registry authentication.",
					},
				},
			},
			"signing": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Sigstore/cosign signing configuration. When set, the pushed image is signed " +
					"using cosign after a successful push. Supports both key-based and keyless (Fulcio/Rekor) signing.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
				Attributes: map[string]schema.Attribute{
					"cosign_key_path": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Path to the cosign private key for signing. Mutually exclusive with keyless.",
					},
					"cosign_password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Password for the cosign private key. Set via COSIGN_PASSWORD env var if omitted.",
					},
					"keyless": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Use keyless signing via Sigstore Fulcio and Rekor (OIDC-based).",
					},
					"fulcio_url": schema.StringAttribute{
						Optional:    true,
						Description: "Custom Fulcio server URL for keyless signing.",
					},
					"rekor_url": schema.StringAttribute{
						Optional:    true,
						Description: "Custom Rekor transparency log URL.",
					},
					"attestation_path": schema.StringAttribute{
						Optional: true,
						Description: "Path to a witness attestation envelope (DSSE JSON) to attach to the image " +
							"via `cosign attest`. Typically produced by the podman_image attestation block.",
					},
					"predicate_type": schema.StringAttribute{
						Optional: true,
						Description: "The in-toto predicate type for the attestation (e.g., 'slsaprovenance', 'custom'). " +
							"Defaults to cosign's auto-detection if omitted.",
					},
					"sbom_path": schema.StringAttribute{
						Optional: true,
						Description: "Path to a CycloneDX/SPDX SBOM file to attach to the image " +
							"via `cosign attest --type cyclonedx`. Typically produced by the podman_image sbom block.",
					},
					"cosign_key_path_out": schema.StringAttribute{
						Computed: true,
						Description: "The cosign private key path used for signing. If cosign_key_path was provided, " +
							"this reflects that input. Otherwise, it is the path to the auto-generated key.",
					},
					"cosign_public_key_out": schema.StringAttribute{
						Computed: true,
						Description: "The cosign public key path. If a key pair was auto-generated, this is " +
							"the path to the public key. Empty when an existing key was provided.",
					},
				},
			},
		},
	}
}

// Update updates the resource and sets the updated Terraform state on success.
//

func (*RegistryImageResource) Update(
	_ context.Context,
	_ resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"Registry images do not support updates. All changes require replacement.",
	)
}

// Delete deletes the resource and removes the Terraform state on success.
//

func (r *RegistryImageResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data RegistryImageResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

// ImportState imports the resource state.
func (*RegistryImageResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// signImage signs the pushed image using cosign and optionally attaches attestations.
func (r *RegistryImageResource) signImage(
	ctx context.Context,
	data *RegistryImageResourceModel,
	diags *diag.Diagnostics,
) {
	signing := data.Signing
	name := data.Name.ValueString()

	// Build the image reference for cosign (use digest if available for immutability)
	imageRef := name

	if !data.Digest.IsNull() && data.Digest.ValueString() != "" {
		digest := data.Digest.ValueString()
		if strings.Contains(digest, "@") {
			imageRef = digest
		} else if strings.HasPrefix(digest, "sha256:") {
			if idx := strings.LastIndex(name, ":"); idx > 0 {
				imageRef = name[:idx] + "@" + digest
			} else {
				imageRef = name + "@" + digest
			}
		}
	}

	keyPath := ""
	if !signing.CosignKeyPath.IsNull() {
		keyPath = signing.CosignKeyPath.ValueString()
	}

	password := ""
	if !signing.CosignPassword.IsNull() {
		password = signing.CosignPassword.ValueString()
	}

	keyless := signing.Keyless.ValueBool()

	fulcioURL := ""
	if !signing.FulcioURL.IsNull() {
		fulcioURL = signing.FulcioURL.ValueString()
	}

	rekorURL := ""
	if !signing.RekorURL.IsNull() {
		rekorURL = signing.RekorURL.ValueString()
	}

	cosignClient := NewCosignClient()

	// Auto-generate a cosign key pair when no key is provided and not using keyless signing.
	switch {
	case keyPath == "" && !keyless:
		result, err := cosignClient.EnsureKeyPair(ctx, ".cosign")
		if err != nil {
			diags.AddError(
				"Error generating cosign key pair",
				"Could not generate cosign key pair: "+err.Error(),
			)

			return
		}

		if result.Reused {
			diags.AddWarning(
				"Reusing auto-generated cosign key pair",
				fmt.Sprintf("No cosign_key_path was provided. Reusing existing key pair at %s. "+
					"Set cosign_key_path explicitly to use your own key.", result.PrivateKeyPath),
			)
		} else {
			diags.AddWarning(
				"Auto-generated cosign key pair",
				fmt.Sprintf(
					"No cosign_key_path was provided. A new cosign key pair was generated at %s. "+
						"Set cosign_key_path explicitly to use your own key.",
					result.PrivateKeyPath,
				),
			)
		}

		keyPath = result.PrivateKeyPath
		signing.CosignKeyPathOut = types.StringValue(result.PrivateKeyPath)
		signing.CosignPublicKeyOut = types.StringValue(result.PublicKeyPath)
	case keyPath != "":
		// User provided a key — output it so it is visible in state.
		signing.CosignKeyPathOut = types.StringValue(keyPath)
		signing.CosignPublicKeyOut = types.StringValue("")
	default:
		// Keyless mode — no key files involved.
		signing.CosignKeyPathOut = types.StringValue("")
		signing.CosignPublicKeyOut = types.StringValue("")
	}

	err := cosignClient.SignImage(ctx, SignOpts{
		ImageRef:  imageRef,
		KeyPath:   keyPath,
		Password:  password,
		Keyless:   keyless,
		FulcioURL: fulcioURL,
		RekorURL:  rekorURL,
	})
	if err != nil {
		diags.AddError(
			"Error signing image with cosign",
			fmt.Sprintf("cosign sign failed for %s: %s", imageRef, err.Error()),
		)

		return
	}

	// Attach witness attestation if provided
	if !signing.AttestationPath.IsNull() && signing.AttestationPath.ValueString() != "" {
		predicateType := ""
		if !signing.PredicateType.IsNull() {
			predicateType = signing.PredicateType.ValueString()
		}

		err = cosignClient.AttestImage(ctx, AttestOpts{
			ImageRef:      imageRef,
			KeyPath:       keyPath,
			Password:      password,
			Keyless:       keyless,
			FulcioURL:     fulcioURL,
			RekorURL:      rekorURL,
			PredicatePath: signing.AttestationPath.ValueString(),
			PredicateType: predicateType,
		})
		if err != nil {
			diags.AddError(
				"Error attaching attestation to image",
				fmt.Sprintf("cosign attest failed for %s: %s", imageRef, err.Error()),
			)

			return
		}
	}

	// Attach SBOM if provided
	if !signing.SBOMPath.IsNull() && signing.SBOMPath.ValueString() != "" {
		err = cosignClient.AttestImage(ctx, AttestOpts{
			ImageRef:      imageRef,
			KeyPath:       keyPath,
			Password:      password,
			Keyless:       keyless,
			FulcioURL:     fulcioURL,
			RekorURL:      rekorURL,
			PredicatePath: signing.SBOMPath.ValueString(),
			PredicateType: "cyclonedx",
		})
		if err != nil {
			diags.AddError(
				"Error attaching SBOM to image",
				fmt.Sprintf("cosign attest (SBOM) failed for %s: %s", imageRef, err.Error()),
			)

			return
		}
	}
}
