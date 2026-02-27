## OpenTofu Provider Podman

A Terraform/OpenTofu provider for building, attesting, and pushing Podman images with built-in supply chain security.

Built on the modern Terraform Plugin Framework.

## Features

- **Image builds** from Containerfiles with automatic change detection (context hashing)
- **SBOM generation** via [syft](https://github.com/anchore/syft) — enabled by default for every build
- **In-toto attestation** via [Witness](https://github.com/in-toto/witness) — signed DSSE envelopes with SLSA provenance
- **Cosign signing** via [Sigstore](https://www.sigstore.dev/) — key-based or keyless (Fulcio/Rekor)
- **Auto-generated signing keys** — when no key is provided, a cosign key pair is generated and shared across all resources in the root module (`.cosign/`)
- **Registry push** with optional signing, attestation attachment, and SBOM attachment
- **Remote Podman** via SSH (URI-based)

## Quick Start

```hcl
terraform {
  required_providers {
    podman = {
      source  = "sumicare/podman"
      version = "~> 0.1.0"
    }
  }
}

provider "podman" {}

# Build an image — SBOM is generated automatically
resource "podman_image" "app" {
  name = "myapp:latest"
  build {
    context = "./app"
  }
}

# Push to registry and sign
resource "podman_registry_image" "app_push" {
  name = "docker.io/myorg/myapp:latest"

  signing {
    # No cosign_key_path needed — a key pair is auto-generated in .cosign/
  }
}
```

> When `signing` or `attestation` blocks are present without a key path, the provider
> auto-generates a cosign key pair at `.cosign/cosign.key` and `.cosign/cosign.pub`
> in your root module directory. A Terraform **warning** is emitted so you are aware.
> Multiple resources reuse the same generated key.

## Resources

### `podman_image`

Builds a Podman image from a Containerfile. Supports SBOM generation and in-toto Witness attestation.

| Attribute | Type | Description |
|---|---|---|
| `name` | string, **required** | Image name including tag |
| `build` | block, **required** | Build configuration (`context`, `build_args`, `pull`) |
| `sbom` | block, optional | SBOM generation — defaults to CycloneDX at `sbom.cyclonedx.json` |
| `attestation` | block, optional | Witness attestation — wraps the build with `witness run` |
| `keep_locally` | bool, optional | Keep image on destroy (default: `false`) |

#### SBOM block

| Attribute | Default | Description |
|---|---|---|
| `output_path` | `sbom.cyclonedx.json` | File path for the SBOM |
| `format` | `cyclonedx` | `cyclonedx` or `spdx-json` |

#### Attestation block

| Attribute | Default | Description |
|---|---|---|
| `step_name` | `build` | Witness step name for policy evaluation |
| `signer_key_path` | *(auto-generated)* | PEM private key for signing; omit to auto-generate |
| `output_path` | `attestation.json` | Output path for the DSSE envelope |
| `attestors` | `[]` | Additional attestors (`slsa`, `gcp`, `gitlab`, etc.) |
| `export_slsa` | `true` | Export SLSA provenance predicate |
| `enable_archivista` | `false` | Store attestations in Archivista |
| `archivista_server` | — | Archivista server URL |

**Computed outputs:**

- `signer_key_path_out` — the private key path actually used (input or generated)
- `signer_public_key_out` — the public key path (set when auto-generated)

### `podman_registry_image`

Pushes a local image to a container registry. Optionally signs the image and attaches attestations/SBOMs with cosign.

| Attribute | Type | Description |
|---|---|---|
| `name` | string, **required** | Full registry image reference |
| `auth_config` | block, optional | Registry credentials (`address`, `username`, `password`) |
| `signing` | block, optional | Cosign signing configuration |

#### Signing block

| Attribute | Default | Description |
|---|---|---|
| `cosign_key_path` | *(auto-generated)* | Cosign private key; omit to auto-generate |
| `cosign_password` | — | Key password (or set `COSIGN_PASSWORD`) |
| `keyless` | `false` | Use Fulcio/Rekor OIDC-based keyless signing |
| `fulcio_url` | — | Custom Fulcio URL |
| `rekor_url` | — | Custom Rekor URL |
| `attestation_path` | — | DSSE envelope to attach (from `podman_image`) |
| `predicate_type` | — | In-toto predicate type |
| `sbom_path` | — | SBOM file to attach |

**Computed outputs:**

- `cosign_key_path_out` — the signing key path actually used (input or generated)
- `cosign_public_key_out` — the public key path (set when auto-generated)

## Examples

### Minimal build (SBOM generated automatically)

```hcl
resource "podman_image" "app" {
  name = "myapp:latest"
  build {
    context = "./app"
  }
}
```

### Build with attestation (auto-generated key)

```hcl
resource "podman_image" "app" {
  name = "myapp:v1.0.0"
  build {
    context    = "./app"
    build_args = { VERSION = "1.0.0" }
  }

  attestation {
    attestors = ["slsa"]
  }

  sbom {
    format = "spdx-json"
  }
}

# The generated key is available for downstream use:
output "signing_public_key" {
  value = podman_image.app.attestation.signer_public_key_out
}
```

### Build with your own key

```hcl
resource "podman_image" "app" {
  name = "myapp:v1.0.0"
  build {
    context = "./app"
  }

  attestation {
    signer_key_path = var.signing_key_path
  }
}
```

### Push, sign, and attach attestation + SBOM

```hcl
resource "podman_registry_image" "app_push" {
  name = "docker.io/myorg/myapp:v1.0.0"

  signing {
    attestation_path = podman_image.app.attestation.output_path
    predicate_type   = "slsaprovenance"
    sbom_path        = podman_image.app.sbom.output_path
  }
}
```

### Multiple images sharing the same auto-generated key

```hcl
resource "podman_image" "frontend" {
  name = "frontend:v1"
  build { context = "./frontend" }
  attestation {}
}

resource "podman_image" "backend" {
  name = "backend:v1"
  build { context = "./backend" }
  attestation {}
}

# Both use the same .cosign/cosign.key — generated once, reused automatically.
```

### Keyless signing (Sigstore)

```hcl
resource "podman_registry_image" "app_push" {
  name = "docker.io/myorg/myapp:v1.0.0"

  signing {
    keyless    = true
    fulcio_url = "https://fulcio.sigstore.dev"
    rekor_url  = "https://rekor.sigstore.dev"
  }
}
```

## Provider Configuration

```hcl
# Local (default) — rootless user socket
provider "podman" {}

# Explicit local socket
provider "podman" {
  uri = "unix:///run/user/1000/podman/podman.sock"
}

# Remote via SSH
provider "podman" {
  uri = "ssh://user@remote-host/run/podman/podman.sock"
}
```

Environment variable: `PODMAN_HOST`

## Auto-Generated Key Behavior

When a `signing` or `attestation` block is present without an explicit key path:

1. The provider looks for an existing key pair at `.cosign/cosign.key` and `.cosign/cosign.pub` in your root module directory.
2. If found, it reuses the existing key pair.
3. If not found, it generates a new cosign ECDSA key pair (with an empty password) and writes it there.
4. A Terraform **warning** is emitted in both cases so you are always aware.
5. The key paths are exposed as computed outputs (`cosign_key_path_out`, `cosign_public_key_out` or `signer_key_path_out`, `signer_public_key_out`) so you can reference them elsewhere.

> **Tip:** Add `.cosign/` to your `.gitignore` to avoid committing auto-generated keys.

## Development

### Building

```bash
go build -o terraform-provider-podman
```

### Local Development with OpenTofu

1. **Build the provider:**
   ```bash
   go build -o terraform-provider-podman
   ```

2. **Set up the dev override:**
   ```bash
   export TF_CLI_CONFIG_FILE=/path/to/.tofurc
   ```

3. **Configure `.tofurc`:**
   ```hcl
   provider_installation {
     dev_overrides {
       "sumicare/podman" = "/path/to/opentofu-provider-podman"
     }
     direct {}
   }
   ```

When using `dev_overrides`, OpenTofu skips provider version checks and uses your local binary directly.

### Testing

```bash
# Unit tests
go test -v -cover -timeout=120s ./...

# Acceptance tests (requires Podman)
TF_ACC=1 go test -v -cover -timeout=20m ./...
```

## License

Licensed under the [Apache License 2.0](LICENSE).
