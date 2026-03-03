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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func schemaFor(t *testing.T, r resource.Resource) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	return resp.Schema
}

func tfTypeFor(t *testing.T, r resource.Resource) tftypes.Object {
	t.Helper()

	s := schemaFor(t, r)

	if objType, ok := s.Type().TerraformType(t.Context()).(tftypes.Object); ok {
		return objType
	}

	return tftypes.Object{}
}

func makePlan(t *testing.T, r resource.Resource, vals map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()

	s := schemaFor(t, r)
	raw := tftypes.NewValue(tfTypeFor(t, r), vals)

	return tfsdk.Plan{Raw: raw, Schema: s}
}

func makeState(t *testing.T, r resource.Resource, vals map[string]tftypes.Value) tfsdk.State {
	t.Helper()

	s := schemaFor(t, r)
	raw := tftypes.NewValue(tfTypeFor(t, r), vals)

	return tfsdk.State{Raw: raw, Schema: s}
}

type configurableResource interface {
	resource.Resource
	resource.ResourceWithConfigure
}

func testResourceConfigure(
	t *testing.T,
	cfg *PodmanProviderConfig,
	newResource func() configurableResource,
	getConfig func(configurableResource) *PodmanProviderConfig,
) {
	t.Helper()

	tests := []struct {
		data    any
		name    string
		wantErr bool
		wantCfg bool
	}{
		{nil, "nil_provider_data", false, false},
		{cfg, "valid_config", false, true},
		{42, "wrong_type", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newResource()
			resp := &resource.ConfigureResponse{}
			r.Configure(
				context.Background(),
				resource.ConfigureRequest{ProviderData: tt.data},
				resp,
			)

			if tt.wantErr && !resp.Diagnostics.HasError() {
				t.Error("expected error")
			}

			if !tt.wantErr && resp.Diagnostics.HasError() {
				t.Errorf("unexpected errors: %v", resp.Diagnostics.Errors())
			}

			got := getConfig(r)
			if tt.wantCfg && got != cfg {
				t.Error("expected config to be set")
			}

			if !tt.wantCfg && got != nil {
				t.Error("expected nil config")
			}
		})
	}
}

func testResourceCreate[T any](
	t *testing.T,
	tests []struct {
		handler    http.HandlerFunc
		planVals   func() map[string]tftypes.Value
		checkState func(*testing.T, T)
		name       string
		wantErr    bool
	},
	makePlan func(*testing.T, map[string]tftypes.Value) tfsdk.Plan,
	makeState func(*testing.T, map[string]tftypes.Value) tfsdk.State,
	createResource func(*PodmanProviderConfig) resource.Resource,
	getStateData func(*resource.CreateResponse) T,
) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			t.Cleanup(server.Close)

			r := createResource(&PodmanProviderConfig{
				HTTPClient: server.Client(),
				BaseURL:    server.URL,
			})

			vals := tt.planVals()
			plan := makePlan(t, vals)
			state := makeState(t, vals)

			createResp := &resource.CreateResponse{State: state}
			r.Create(context.Background(), resource.CreateRequest{Plan: plan}, createResp)

			if tt.wantErr {
				if !createResp.Diagnostics.HasError() {
					t.Error("expected error")
				}

				return
			}

			if createResp.Diagnostics.HasError() {
				t.Fatalf("Create errors: %v", createResp.Diagnostics.Errors())
			}

			if tt.checkState != nil {
				tt.checkState(t, getStateData(createResp))
			}
		})
	}
}
