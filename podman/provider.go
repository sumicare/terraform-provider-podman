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
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ provider.Provider = &PodmanProvider{}

type PodmanProvider struct {
	version string
}

type PodmanProviderModel struct {
	URI types.String `tfsdk:"uri"`
}

type PodmanProviderConfig struct {
	URI        string
	HTTPClient *http.Client
	BaseURL    string
}

func (p *PodmanProvider) Configure(
	ctx context.Context,
	req provider.ConfigureRequest,
	resp *provider.ConfigureResponse,
) {
	var data PodmanProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	config := &PodmanProviderConfig{}

	if !data.URI.IsNull() && !data.URI.IsUnknown() {
		config.URI = data.URI.ValueString()
	} else if uri := os.Getenv("PODMAN_HOST"); uri != "" {
		config.URI = uri
	} else {
		config.URI = fmt.Sprintf("unix:///run/user/%d/podman/podman.sock", os.Getuid())
	}

	httpClient, baseURL, err := newPodmanHTTPClient(config.URI)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to connect to Podman",
			fmt.Sprintf("Could not connect to Podman at %s: %s", config.URI, err.Error()),
		)

		return
	}

	config.HTTPClient = httpClient
	config.BaseURL = baseURL

	tflog.Debug(ctx, "Configured Podman provider", map[string]any{
		"uri": config.URI,
	})

	resp.ResourceData = config
}

func (*PodmanProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *PodmanProvider) Metadata(
	_ context.Context,
	_ provider.MetadataRequest,
	resp *provider.MetadataResponse,
) {
	resp.TypeName = "podman"
	resp.Version = p.version
}

func (*PodmanProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewImageResource,
		NewRegistryImageResource,
	}
}

func (*PodmanProvider) Schema(
	_ context.Context,
	_ provider.SchemaRequest,
	resp *provider.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "The Podman provider manages container image builds and registry pushes via the Podman socket API.",
		Attributes: map[string]schema.Attribute{
			"uri": schema.StringAttribute{
				Optional: true,
				Description: "Podman socket URI (e.g. unix:///run/user/1000/podman/podman.sock or ssh://user@host/run/podman/podman.sock). " +
					"Defaults to the rootless user socket. Can be set via PODMAN_HOST env var.",
			},
		},
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &PodmanProvider{
			version: version,
		}
	}
}
