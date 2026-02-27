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
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// imageSchemaResp returns the cached ImageResource schema.
func imageSchemaResp(t *testing.T) rschema.Schema {
	t.Helper()

	r := &ImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	return resp.Schema
}

// registryImageSchemaResp returns the cached RegistryImageResource schema.
func registryImageSchemaResp(t *testing.T) rschema.Schema {
	t.Helper()

	r := &RegistryImageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)

	return resp.Schema
}

// imageTFType returns the tftypes.Object type matching the ImageResource schema.
func imageTFType(t *testing.T) tftypes.Object {
	t.Helper()

	s := imageSchemaResp(t)

	if objType, ok := s.Type().TerraformType(t.Context()).(tftypes.Object); ok {
		return objType
	}

	return tftypes.Object{}
}

// registryImageTFType returns the tftypes.Object type matching the RegistryImageResource schema.
func registryImageTFType(t *testing.T) tftypes.Object {
	t.Helper()

	s := registryImageSchemaResp(t)

	if objType, ok := s.Type().TerraformType(t.Context()).(tftypes.Object); ok {
		return objType
	}

	return tftypes.Object{}
}

// makeImagePlan creates a tfsdk.Plan for ImageResource with the given values.
func makeImagePlan(t *testing.T, vals map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()

	s := imageSchemaResp(t)
	objType := imageTFType(t)
	raw := tftypes.NewValue(objType, vals)

	return tfsdk.Plan{Raw: raw, Schema: s}
}

// makeImageState creates a tfsdk.State for ImageResource with the given values.
func makeImageState(t *testing.T, vals map[string]tftypes.Value) tfsdk.State {
	t.Helper()

	s := imageSchemaResp(t)
	objType := imageTFType(t)
	raw := tftypes.NewValue(objType, vals)

	return tfsdk.State{Raw: raw, Schema: s}
}

// makeRegistryImagePlan creates a tfsdk.Plan for RegistryImageResource.
func makeRegistryImagePlan(t *testing.T, vals map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()

	s := registryImageSchemaResp(t)
	objType := registryImageTFType(t)
	raw := tftypes.NewValue(objType, vals)

	return tfsdk.Plan{Raw: raw, Schema: s}
}

// makeRegistryImageState creates a tfsdk.State for RegistryImageResource.
func makeRegistryImageState(t *testing.T, vals map[string]tftypes.Value) tfsdk.State {
	t.Helper()

	s := registryImageSchemaResp(t)
	objType := registryImageTFType(t)
	raw := tftypes.NewValue(objType, vals)

	return tfsdk.State{Raw: raw, Schema: s}
}
