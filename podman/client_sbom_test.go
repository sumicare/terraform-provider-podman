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
)

func TestNewSBOMClient(t *testing.T) {
	client := NewSBOMClient()
	if client == nil {
		t.Error("expected non-nil SBOMClient")
	}
}

func TestSBOMOpts_Defaults(t *testing.T) {
	opts := SBOMOpts{}

	if opts.Format != "" {
		t.Errorf("expected empty default Format, got %s", opts.Format)
	}

	if opts.ImageRef != "" {
		t.Errorf("expected empty default ImageRef, got %s", opts.ImageRef)
	}
}

func TestSBOMOpts_FormatSelection(t *testing.T) {
	tests := []struct {
		format   string
		expected string
	}{
		{"cyclonedx", "cyclonedx"},
		{"spdx-json", "spdx-json"},
		{"", ""},
	}

	for _, tt := range tests {
		opts := SBOMOpts{Format: tt.format}
		if opts.Format != tt.expected {
			t.Errorf(
				"SBOMOpts{Format: %q}.Format = %q, want %q",
				tt.format,
				opts.Format,
				tt.expected,
			)
		}
	}
}
