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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &RegistryImageResource{}
	_ resource.ResourceWithConfigure   = &RegistryImageResource{}
	_ resource.ResourceWithImportState = &RegistryImageResource{}
)

//nolint:ireturn // false positive
func NewRegistryImageResource() resource.Resource {
	return &RegistryImageResource{}
}

type (
	RegistryImageResource struct {
		config *PodmanProviderConfig
	}

	RegistryImageResourceModel struct {
		AuthConfig      *AuthConfigModel `tfsdk:"auth_config"`
		ID              types.String     `tfsdk:"id"`
		Name            types.String     `tfsdk:"name"`
		Digest          types.String     `tfsdk:"digest"`
		SBOMPath        types.String     `tfsdk:"sbom_path"`
		AttestationPath types.String     `tfsdk:"attestation_path"`
		CosignPublicKey types.String     `tfsdk:"cosign_public_key"`
		KeepRemotely    types.Bool       `tfsdk:"keep_remotely"`
	}

	AuthConfigModel struct {
		Address  types.String `tfsdk:"address"`
		Username types.String `tfsdk:"username"`
		Password types.String `tfsdk:"password"`
	}
)

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

	// Always sign, attach SBOM and attestation.
	r.signImage(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (*RegistryImageResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_registry_image"
}

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

	client := NewPodmanClient(r.config)

	exists, err := client.ImageExists(ctx, data.Name.ValueString())
	if err != nil || !exists {
		resp.State.RemoveResource(ctx)

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

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
			"sbom_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to the CycloneDX SBOM file to attach. Typically from podman_image.sbom_path.",
			},
			"attestation_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to the witness attestation envelope to attach. Typically from podman_image.attestation_path.",
			},
			"cosign_public_key": schema.StringAttribute{
				Computed:    true,
				Description: "PEM-encoded cosign public key used for signing. Auto-generated in .cosign/ if not provided.",
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
		},
	}
}

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

	tflog.Info(ctx, "Registry image delete is a no-op (registry deletion not supported by Podman API)", map[string]any{
		"name":          data.Name.ValueString(),
		"keep_remotely": data.KeepRemotely.ValueBool(),
	})
}

func (*RegistryImageResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *RegistryImageResource) signImage(
	ctx context.Context,
	data *RegistryImageResourceModel,
	diags *diag.Diagnostics,
) {
	name := data.Name.ValueString()

	// Prefer digest reference for immutability.
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

	cosignClient := NewCosignClient()

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
			fmt.Sprintf("Reusing existing key pair at %s.", result.PrivateKeyPath),
		)
	} else {
		diags.AddWarning(
			"Auto-generated cosign key pair",
			fmt.Sprintf(
				"A new cosign key pair was generated at %s.",
				result.PrivateKeyPath,
			),
		)
	}

	keyPath := result.PrivateKeyPath
	passphrase := result.Passphrase
	data.CosignPublicKey = types.StringValue(string(result.PublicKeyPEM))

	err = cosignClient.SignImage(ctx, SignOpts{
		ImageRef: imageRef,
		KeyPath:  keyPath,
		Password: passphrase,
	})
	if err != nil {
		diags.AddError(
			"Error signing image with cosign",
			fmt.Sprintf("cosign sign failed for %s: %s", imageRef, err.Error()),
		)

		return
	}

	// Post-sign verification to confirm the signature is valid.
	verifyErr := cosignClient.VerifyImage(ctx, VerifyOpts{
		ImageRef: imageRef,
		KeyPath:  result.PublicKeyPath,
		SkipTlog: true,
	})
	if verifyErr != nil {
		diags.AddWarning(
			"Post-sign verification failed",
			fmt.Sprintf("Signature was created but verification failed for %s: %s. "+
				"This may indicate the registry does not support OCI referrers.",
				imageRef, verifyErr.Error()),
		)
	}

	// Attach in-toto attestation if path is provided.
	if !data.AttestationPath.IsNull() && data.AttestationPath.ValueString() != "" {
		err = cosignClient.AttestImage(ctx, AttestOpts{
			ImageRef:      imageRef,
			KeyPath:       keyPath,
			Password:      passphrase,
			PredicatePath: data.AttestationPath.ValueString(),
			PredicateType: "custom",
		})
		if err != nil {
			diags.AddError(
				"Error attaching attestation to image",
				fmt.Sprintf("cosign attest failed for %s: %s", imageRef, err.Error()),
			)

			return
		}
	}

	// Attach SBOM if path is provided.
	if !data.SBOMPath.IsNull() && data.SBOMPath.ValueString() != "" {
		err = cosignClient.AttestImage(ctx, AttestOpts{
			ImageRef:      imageRef,
			KeyPath:       keyPath,
			Password:      passphrase,
			PredicatePath: data.SBOMPath.ValueString(),
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
