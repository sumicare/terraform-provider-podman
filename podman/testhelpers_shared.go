//
// Copyright 2026 Sumicare
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package podman

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// testResourceConfigure is a shared helper for testing resource Configure method.
func testResourceConfigure(t *testing.T, cfg *PodmanProviderConfig, newResource func() any) {
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

			// Use type assertion to call Configure on the appropriate resource type
			switch res := r.(type) {
			case *ImageResource:
				res.Configure(
					context.Background(),
					resource.ConfigureRequest{ProviderData: tt.data},
					resp,
				)
			case *RegistryImageResource:
				res.Configure(
					context.Background(),
					resource.ConfigureRequest{ProviderData: tt.data},
					resp,
				)
			}

			if tt.wantErr && !resp.Diagnostics.HasError() {
				t.Error("expected error")
			}

			if !tt.wantErr && resp.Diagnostics.HasError() {
				t.Errorf("unexpected errors: %v", resp.Diagnostics.Errors())
			}

			// Check config based on resource type
			switch res := r.(type) {
			case *ImageResource:
				if tt.wantCfg && res.config != cfg {
					t.Error("expected config to be set")
				}

				if !tt.wantCfg && res.config != nil {
					t.Error("expected nil config")
				}
			case *RegistryImageResource:
				if tt.wantCfg && res.config != cfg {
					t.Error("expected config to be set")
				}

				if !tt.wantCfg && res.config != nil {
					t.Error("expected nil config")
				}
			}
		})
	}
}

// testResourceCreate is a shared helper for testing resource Create method with test cases.
func testResourceCreate(
	t *testing.T,
	tests []struct {
		handler    http.HandlerFunc
		planVals   func() map[string]tftypes.Value
		checkState func(*testing.T, any)
		name       string
		wantErr    bool
	},
	makePlan func(*testing.T, map[string]tftypes.Value) tfsdk.Plan,
	makeState func(*testing.T, map[string]tftypes.Value) tfsdk.State,
	createResource func(*PodmanProviderConfig) any,
	getStateData func(*resource.CreateResponse) any,
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

			// Use type assertion to call Create on the appropriate resource type
			switch res := r.(type) {
			case *ImageResource:
				res.Create(context.Background(), resource.CreateRequest{Plan: plan}, createResp)
			case *RegistryImageResource:
				res.Create(context.Background(), resource.CreateRequest{Plan: plan}, createResp)
			}

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
				data := getStateData(createResp)
				tt.checkState(t, data)
			}
		})
	}
}
