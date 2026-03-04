## OpenTofu Provider Podman

A Terraform/OpenTofu provider for building, attesting, and pushing Podman images with built-in supply chain security.

Built on the modern Terraform Plugin Framework.

## Features

- **Image builds** from Containerfiles with automatic change detection (context hashing)
- **Always-on SBOM generation** via [syft](https://github.com/anchore/syft) — CycloneDX SBOM for every build
- **Always-on in-toto attestation** via [Witness](https://github.com/in-toto/witness) — signed DSSE envelopes with SLSA provenance
- **Always-on cosign signing** via [Sigstore](https://www.sigstore.dev/) — automatic key-based signing on registry push
- **Auto-generated signing keys** — a cosign key pair is generated with a random passphrase and shared across all resources in the root module (`.cosign/`)
- **Registry push** with automatic signing, attestation attachment, and SBOM attachment
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

# Build an image — SBOM + attestation are generated automatically
resource "podman_image" "app" {
  name = "myapp:latest"
  build {
    context = "./app"
  }
}

# Push to registry — signing + attestation/SBOM attachment happen automatically
resource "podman_registry_image" "app_push" {
  name = podman_image.app.name

  depends_on = [podman_image.app]
}

# The public key and artifact paths are available as computed outputs:
output "cosign_public_key" {
  value = podman_image.app.cosign_public_key
}
```

> No configuration is required for SBOM, attestation, or signing — the provider handles
> everything automatically. A cosign key pair is generated at `.cosign/cosign.key` and
> `.cosign/cosign.pub` with a random passphrase stored at `.cosign/PASSPHRASE` (0600 permissions).
> A Terraform **warning** is emitted so you are always aware. Multiple resources reuse the same key.

## Resources

### `podman_image`

Builds a Podman image from a Containerfile. Automatically generates a CycloneDX SBOM and a signed in-toto attestation for every build.

| Attribute | Type | Description |
|---|---|---|
| `name` | string, **required** | Image name including tag |
| `build` | block, **required** | Build configuration (`context`, `build_args`, `pull`) |
| `keep_locally` | bool, optional | Keep image on destroy (default: `false`) |

**Computed outputs:**

| Output | Description |
|---|---|
| `sbom_path` | Path to the generated CycloneDX SBOM (`.sbom/<image>.cyclonedx.json`) |
| `attestation_path` | Path to the signed DSSE envelope (`.sbom/<image>.intoto.json`) |
| `cosign_public_key` | PEM-encoded cosign public key used for signing |
| `context_hash` | SHA-256 hash of the build context for change detection |
| `repo_digest` | Image digest after build |

### `podman_registry_image`

Pushes a local image to a container registry. Automatically signs the image and attaches the SBOM and in-toto attestation with cosign.

| Attribute | Type | Description |
|---|---|---|
| `name` | string, **required** | Full registry image reference |
| `auth_config` | block, optional | Registry credentials (`address`, `username`, `password`) |
| `keep_remotely` | bool, optional | Keep image in registry on destroy (default: `false`) |

**Computed outputs:**

| Output | Description |
|---|---|
| `digest` | Image digest after push |
| `sbom_path` | Path to the attached SBOM |
| `attestation_path` | Path to the attached attestation |
| `cosign_public_key` | PEM-encoded cosign public key used for signing |

## Examples

### Minimal build

```hcl
resource "podman_image" "app" {
  name = "myapp:latest"
  build {
    context = "./app"
  }
}
```

SBOM is written to `.sbom/myapp.cyclonedx.json` and attestation to `.sbom/myapp.intoto.json` automatically.

### Build and push

```hcl
resource "podman_image" "app" {
  name = "myapp:v1.0.0"
  build {
    context    = "./app"
    build_args = { VERSION = "1.0.0" }
  }
}

resource "podman_registry_image" "app_push" {
  name = podman_image.app.name

  auth_config = {
    address  = "registry.example.com"
    username = var.registry_user
    password = var.registry_pass
  }

  depends_on = [podman_image.app]
}

output "signing_public_key" {
  value = podman_registry_image.app_push[0].cosign_public_key
}
```

### Multiple images sharing the same auto-generated key

```hcl
resource "podman_image" "frontend" {
  name = "frontend:v1"
  build { context = "./frontend" }
}

resource "podman_image" "backend" {
  name = "backend:v1"
  build { context = "./backend" }
}

# Both use the same .cosign/cosign.key — generated once, reused automatically.
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

Every `podman_image` build and `podman_registry_image` push automatically uses a cosign key pair:

1. The provider looks for an existing key pair at `.cosign/cosign.key` and `.cosign/cosign.pub`.
2. If found, it reuses the existing key pair with the passphrase from `.cosign/PASSPHRASE`.
3. If not found, it generates a new cosign ECDSA key pair encrypted with a random 32-character ASCII passphrase, and writes all three files (key, pub, passphrase) to `.cosign/` with `0600` permissions.
4. A Terraform **warning** is emitted in both cases so you are always aware.
5. The public key is exposed as the computed `cosign_public_key` attribute on both resources.

> **Tip:** Add `.cosign/` and `.sbom/` to your `.gitignore` to avoid committing auto-generated keys and artifacts.

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

Copyright 2026 **[Sumicare](https://sumi.care)**

Sumicare OpenTofu Provider Podman is licensed under the terms of [Apache License 2.0](LICENSE).

The **[Political Statement](POLITICAL_STATEMENT.md)** outlines the maintainer’s principles and project policies, it does not modify or supersede the Apache License 2.0 terms.