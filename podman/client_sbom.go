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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type SBOMClient struct{}

func NewSBOMClient() *SBOMClient {
	return &SBOMClient{}
}

type SBOMOpts struct {
	ImageRef   string
	OutputPath string
	Format     string // "cyclonedx" or "spdx-json"
}

func (c *SBOMClient) GenerateSBOM(ctx context.Context, opts SBOMOpts) error {
	tflog.Info(ctx, "Generating SBOM with syft", map[string]any{
		"image":       opts.ImageRef,
		"output_path": opts.OutputPath,
		"format":      opts.Format,
	})

	if dir := filepath.Dir(opts.OutputPath); dir != "" {
		err := os.MkdirAll(dir, 0o755)
		if err != nil {
			return fmt.Errorf("failed to create SBOM output directory %s: %w", dir, err)
		}
	}

	src, err := syft.GetSource(ctx, opts.ImageRef, syft.DefaultGetSourceConfig())
	if err != nil {
		return fmt.Errorf("failed to create image source for %s: %w", opts.ImageRef, err)
	}

	sbomResult, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return fmt.Errorf("failed to create SBOM for %s: %w", opts.ImageRef, err)
	}

	format := opts.Format
	if format == "" {
		format = "cyclonedx"
	}

	var encoder sbom.FormatEncoder

	switch format {
	case "cyclonedx":
		encoder, err = cyclonedxjson.NewFormatEncoderWithConfig(
			cyclonedxjson.DefaultEncoderConfig(),
		)
	case "spdx-json":
		encoder, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	default:
		return fmt.Errorf("unsupported SBOM format: %s (use 'cyclonedx' or 'spdx-json')", format)
	}

	if err != nil {
		return fmt.Errorf("failed to create SBOM encoder for format %s: %w", format, err)
	}

	var buf bytes.Buffer
	if encodeErr := encoder.Encode(&buf, *sbomResult); encodeErr != nil {
		return fmt.Errorf("failed to encode SBOM: %w", encodeErr)
	}

	if writeErr := os.WriteFile(opts.OutputPath, buf.Bytes(), 0o600); writeErr != nil {
		return fmt.Errorf("failed to write SBOM to %s: %w", opts.OutputPath, writeErr)
	}

	tflog.Info(ctx, "SBOM generated successfully", map[string]any{
		"output_path": opts.OutputPath,
		"format":      format,
	})

	return nil
}
