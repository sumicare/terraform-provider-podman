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

// Compile-time check to ensure PodmanProvider satisfies the provider.Provider interface.
var (
	_ provider.Provider = &PodmanProvider{}
)

// PodmanProvider is the provider implementation using Plugin Framework.
type PodmanProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance tests
	version string
}

// PodmanProviderModel describes the provider data model.
type PodmanProviderModel struct {
	URI types.String `tfsdk:"uri"`
}

// PodmanProviderConfig holds the resolved provider configuration.
type PodmanProviderConfig struct {
	// URI is the podman socket URI (e.g. unix:///run/podman/podman.sock).
	URI string
	// HTTPClient is the HTTP client configured to talk to the podman socket.
	HTTPClient *http.Client
	// BaseURL is the base URL for podman REST API requests.
	BaseURL string
}

// Configure prepares the provider for data sources and resources.
//

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

	// Resolve URI from config or environment
	if !data.URI.IsNull() && !data.URI.IsUnknown() {
		config.URI = data.URI.ValueString()
	} else if uri := os.Getenv("PODMAN_HOST"); uri != "" {
		config.URI = uri
	} else {
		// Default to the rootless user socket
		config.URI = fmt.Sprintf("unix:///run/user/%d/podman/podman.sock", os.Getuid())
	}

	// Create HTTP client for the podman socket
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

// DataSources defines the data sources implemented in the provider.
func (*PodmanProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Metadata returns the provider type name.
func (p *PodmanProvider) Metadata(
	_ context.Context,
	_ provider.MetadataRequest,
	resp *provider.MetadataResponse,
) {
	resp.TypeName = "podman"
	resp.Version = p.version
}

// Resources defines the resources implemented in the provider.
func (*PodmanProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewImageResource,
		NewRegistryImageResource,
	}
}

// Schema defines the provider-level schema for configuration data.
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

// New returns a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &PodmanProvider{
			version: version,
		}
	}
}
