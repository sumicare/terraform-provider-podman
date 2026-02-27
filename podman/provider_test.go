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
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNew(t *testing.T) {
	providerFactory := New("test")
	p := providerFactory()

	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestProviderMetadata(t *testing.T) {
	p := &PodmanProvider{version: "1.2.3"}

	req := provider.MetadataRequest{}
	resp := &provider.MetadataResponse{}

	p.Metadata(t.Context(), req, resp)

	if resp.TypeName != "podman" {
		t.Errorf("expected TypeName 'podman', got %q", resp.TypeName)
	}

	if resp.Version != "1.2.3" {
		t.Errorf("expected Version '1.2.3', got %q", resp.Version)
	}
}

func TestProviderSchema(t *testing.T) {
	p := &PodmanProvider{version: "test"}

	req := provider.SchemaRequest{}
	resp := &provider.SchemaResponse{}

	p.Schema(t.Context(), req, resp)

	if resp.Schema.Attributes == nil {
		t.Fatal("expected non-nil schema attributes")
	}

	if _, ok := resp.Schema.Attributes["uri"]; !ok {
		t.Error("expected 'uri' attribute in schema")
	}
}

func TestProviderDataSources_Empty(t *testing.T) {
	p := &PodmanProvider{version: "test"}

	dataSources := p.DataSources(t.Context())
	if dataSources != nil {
		t.Errorf("expected nil data sources, got %d", len(dataSources))
	}
}

func TestProviderResources(t *testing.T) {
	p := &PodmanProvider{version: "test"}

	resources := p.Resources(t.Context())
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	// Verify each factory returns a non-nil resource
	for i, factory := range resources {
		r := factory()
		if r == nil {
			t.Errorf("resource factory %d returned nil", i)
		}
	}
}

func TestProviderResources_Types(t *testing.T) {
	p := &PodmanProvider{version: "test"}

	resources := p.Resources(t.Context())

	expectedTypes := map[string]bool{
		"podman_image":          false,
		"podman_registry_image": false,
	}

	for _, factory := range resources {
		r := factory()

		metaReq := resource.MetadataRequest{ProviderTypeName: "podman"}
		metaResp := &resource.MetadataResponse{}
		r.Metadata(t.Context(), metaReq, metaResp)

		if _, ok := expectedTypes[metaResp.TypeName]; !ok {
			t.Errorf("unexpected resource type %q", metaResp.TypeName)
		}

		expectedTypes[metaResp.TypeName] = true
	}

	for typeName, found := range expectedTypes {
		if !found {
			t.Errorf("expected resource type %q not found", typeName)
		}
	}
}

// Verify compile-time interface conformance.
var (
	_ provider.Provider = &PodmanProvider{}
)

func TestPodmanProviderConfig(t *testing.T) {
	cfg := &PodmanProviderConfig{
		URI:     "unix:///run/user/1000/podman/podman.sock",
		BaseURL: "http://d",
	}

	if cfg.URI == "" {
		t.Error("expected non-empty URI")
	}

	if cfg.BaseURL != "http://d" {
		t.Errorf("expected BaseURL 'http://d', got %q", cfg.BaseURL)
	}
}

// Ensure datasource and resource interfaces are satisfied by checking function signatures.
var (
	_ func() datasource.DataSource = nil
	_ func() resource.Resource     = NewImageResource
	_ func() resource.Resource     = NewRegistryImageResource
)

// providerSchemaResp returns the provider schema.
func providerSchemaResp(t *testing.T) provider.SchemaResponse {
	t.Helper()

	p := &PodmanProvider{version: "test"}
	resp := &provider.SchemaResponse{}
	p.Schema(t.Context(), provider.SchemaRequest{}, resp)

	return *resp
}

// makeProviderConfig creates a tfsdk.Config for the provider with the given URI.
func makeProviderConfig(t *testing.T, uri *string) tfsdk.Config {
	t.Helper()

	schemaResp := providerSchemaResp(t)
	objType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"uri": tftypes.String,
		},
	}

	var uriVal tftypes.Value
	if uri != nil {
		uriVal = tftypes.NewValue(tftypes.String, *uri)
	} else {
		uriVal = tftypes.NewValue(tftypes.String, nil)
	}

	raw := tftypes.NewValue(objType, map[string]tftypes.Value{
		"uri": uriVal,
	})

	return tfsdk.Config{Raw: raw, Schema: schemaResp.Schema}
}

func TestProviderConfigure(t *testing.T) {
	ptrStr := func(s string) *string { return &s }

	tests := []struct {
		uri      *string
		name     string
		env      string
		wantURI  string
		wantBase string
		wantErr  bool
	}{
		{
			name:    "explicit_unix_uri",
			uri:     ptrStr("unix:///run/podman/podman.sock"),
			wantURI: "unix:///run/podman/podman.sock",
		},
		{
			name:     "explicit_tcp_uri",
			uri:      ptrStr("tcp://localhost:8080"),
			wantURI:  "tcp://localhost:8080",
			wantBase: "tcp://localhost:8080",
		},
		{
			name:    "env_fallback",
			uri:     nil,
			env:     "unix:///tmp/test-podman.sock",
			wantURI: "unix:///tmp/test-podman.sock",
		},
		{
			name: "default_socket",
			uri:  nil,
		},
		{
			name:    "unsupported_scheme",
			uri:     ptrStr("ssh://user@host/run/podman/podman.sock"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("PODMAN_HOST", tt.env)
			} else {
				// Clear PODMAN_HOST to force default/explicit path.
				original := os.Getenv("PODMAN_HOST")

				os.Unsetenv("PODMAN_HOST")
				t.Cleanup(func() {
					if original != "" {
						t.Setenv("PODMAN_HOST", original)
					}
				})
			}

			p := &PodmanProvider{version: "test"}
			req := provider.ConfigureRequest{Config: makeProviderConfig(t, tt.uri)}
			resp := &provider.ConfigureResponse{}

			p.Configure(t.Context(), req, resp)

			if tt.wantErr {
				if !resp.Diagnostics.HasError() {
					t.Error("expected error")
				}

				return
			}

			if resp.Diagnostics.HasError() {
				t.Fatalf("Configure errors: %v", resp.Diagnostics.Errors())
			}

			config, ok := resp.ResourceData.(*PodmanProviderConfig)
			if !ok {
				t.Fatal("expected *PodmanProviderConfig in ResourceData")
			}

			if config.HTTPClient == nil {
				t.Error("expected non-nil HTTPClient")
			}

			if tt.wantURI != "" && config.URI != tt.wantURI {
				t.Errorf("URI = %q, want %q", config.URI, tt.wantURI)
			}

			if tt.wantURI == "" && config.URI == "" {
				t.Error("expected non-empty default URI")
			}

			if tt.wantBase != "" && config.BaseURL != tt.wantBase {
				t.Errorf("BaseURL = %q, want %q", config.BaseURL, tt.wantBase)
			}
		})
	}
}
