# SLSA Build Pipeline Guide

**Last Updated:** September 22, 2026

A cloud-agnostic guide for building secure, verifiable container images with SLSA Level 3 compliance using GitHub Actions. This guide includes industry best practices and lessons learned from real-world production implementations.

## Table of Contents

1. [Overview](#1-overview)
   - [SLSA Level 3 Requirements](#slsa-level-3-requirements)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
   - [Secrets to Store in Vault](#secrets-to-store-in-vault)
3. [Pipeline Stages](#3-pipeline-stages)
   - [Stage 1: Base Image and Application Layer Preparation](#stage-1-base-image-and-application-layer-preparation)
   - [Stage 2: Container Image Build](#stage-2-container-image-build)
   - [Stage 3: Vulnerability Patching and Image Compression](#stage-3-vulnerability-patching-and-image-compression)
   - [Stage 4: Application Testing](#stage-4-application-testing)
   - [Stage 5: Security Artifacts Generation and Signing](#stage-5-security-artifacts-generation-and-signing)
   - [Stage 6: Image Signing and Registry Push](#stage-6-image-signing-and-registry-push)
4. [Post-Pipeline Operations](#4-post-pipeline-operations)
   - [Continuous Vulnerability Monitoring](#continuous-vulnerability-monitoring)
   - [Runtime Policy Enforcement with Kubernetes](#runtime-policy-enforcement-with-kubernetes)
   - [SLSA Provenance Verification](#slsa-provenance-verification)
5. [Attack Scenarios Prevented](#5-attack-scenarios-prevented)
6. [References](#6-references)

## 1. Overview

This guide outlines a production-grade container image build pipeline that achieves SLSA (Supply-chain Levels for Software Artifacts) Level 3 compliance. The pipeline is cloud-agnostic and works with any container registry that supports signed images (such as AWS ECR, Google Artifact Registry, Azure ACR, and Harbor) and object storage provider (S3, GCS, Azure Blob Storage).

**Common Use Cases:**

- Container image building and signing for production deployments
- Software artifact generation with provenance attestation
- Dependency vulnerability scanning and automated patching
- SBOM (Software Bill of Materials) generation for compliance
- Supply chain attestation for regulated industries
- Multi-stage CI/CD pipelines with security gates

**Real-World Breaches:**

- **SolarWinds (2020)**: A build-system compromise shipped a signed, trojanized Orion update to ~18,000 customers; about 100 companies and nine US federal agencies were actually breached
- **Codecov (2021)**: A credential extracted from a flaw in Codecov's Docker image build process let attackers modify the Bash Uploader, which exfiltrated CI environment variables from customers' pipelines from January 31 to April 1, 2021
- **xz-utils (2024)**: A maintainer who spent two years earning commit access hid an SSH backdoor in the release tarball's build scripts (CVE-2024-3094); it was caught before it reached stable distributions
- **PyPI/npm attacks (ongoing)**: Malicious packages with typosquatting, dependency confusion

### SLSA Level 3 Requirements

- **Provenance exists**: The build platform generates provenance that identifies the output by digest
- **Hosted**: Builds run on a hosted build platform, never a developer machine
- **Authentic**: Provenance is signed, and consumers can verify it
- **Unforgeable**: Signing material is inaccessible to user-defined build steps
- **Isolated**: Builds cannot influence one another (no shared state or cache poisoning)
- **Not in the Build track**: Source control and code review requirements live in the separate SLSA Source track (v1.2, November 2025)

## 2. Prerequisites

### Required Tools

- **[Docker Buildx](https://github.com/docker/buildx)**: Multi-platform image building with BuildKit
- **[Copacetic](https://github.com/project-copacetic/copacetic)**: Vulnerability patching tool (runs immediately after build)
- **[Trivy](https://github.com/aquasecurity/trivy)**: Vulnerability scanning and SBOM generation (runs after patching)
- **[Cosign](https://github.com/sigstore/cosign)**: Container signing and verification tool for signing images, SBOMs, and attestations
- **[SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)**: Official SLSA Level 3 provenance generator for GitHub Actions (GitHub Artifact Attestations in a reusable workflow also reach Build L3)
- **[Syft](https://github.com/anchore/syft)**: SBOM generation tool (alternative to Trivy)
- **[Grype](https://github.com/anchore/grype)**: Vulnerability scanner (alternative to Trivy)

**Build Platform:**

This guide uses GitHub Actions because it can reach SLSA Build Level 3: hosted, ephemeral runners plus provenance signed in an isolated reusable workflow (the SLSA GitHub Generator, or GitHub Artifact Attestations generated from a reusable workflow) whose signing identity build steps cannot touch. SLSA has no official platform certification (platforms self-attest or use a third-party auditor), and a plain job that attests its own build reaches Build L2. While the security patterns are applicable to other CI/CD platforms, GitHub Actions is specifically recommended for achieving SLSA Level 3.

### External Services

Cloud-agnostic service options for container registries, storage, secrets management, and logging.

| Service Category                                    | AWS                              | GCP                 | Azure                    | Self-Hosted / Open Source                  |
| --------------------------------------------------- | -------------------------------- | ------------------- | ------------------------ | ------------------------------------------ |
| **Container Registry** (must support signed images) | Elastic Container Registry (ECR) | Artifact Registry   | Container Registry (ACR) | Harbor                                     |
| **Object Storage**                                  | S3                               | Cloud Storage (GCS) | Blob Storage             | MinIO or S3-compatible                     |
| **Secrets Management** (required)                   | Secrets Manager                  | Secret Manager      | Key Vault                | HashiCorp Vault, External Secrets Operator |
| **Logging Service** (required)                      | CloudWatch Logs                  | Cloud Logging       | Monitor                  | Splunk, ELK Stack, Loki, Fluentd           |

**Notes:**

- **Container Registry**: Must support OCI artifact storage for Cosign signatures and attestations
- **Object Storage**: Used for storing SBOMs, vulnerability scans, and SLSA provenance attestations
- **Secrets Management**: Required for registry credentials, signing keys, and storage credentials
- **Logging Service**: Essential for audit trails and compliance

### Secrets to Store in Vault

All sensitive credentials must be stored in external vault services:

- **Registry credentials**: URL, username, password/token
- **Cosign signing credentials** (only if you use key-based signing): Private key content, private key password
- **Object storage credentials**: IAM role for GitHub OIDC (no static keys), bucket name, region
- **Logging service credentials**: API keys, service account credentials (if applicable)

## 3. Pipeline Stages

### Stage 1: Base Image and Application Layer Preparation

Prepare and secure application code and dependencies before building the container image. Each build runs independently in an ephemeral GitHub Actions runner with no shared state.

**Base Image**: Use [Docker Hardened Images](https://www.docker.com/products/hardened-images/) (Debian-based with dev tools, not distroless) for battle-tested stability, GNU/glibc support, and ability to install build dependencies. The full DHI catalog (1,000+ Debian- and Alpine-based images) has been free and Apache-2.0 licensed since December 2025; only the paid tiers (DHI Select and DHI Enterprise) add SLA-backed CVE remediation, so free images still need Copacetic patching (Stage 3).

**Application Security**:

- **[Dependabot](https://github.com/dependabot/dependabot-core)**: Automated dependency updates, creates PRs for outdated packages, catches vulnerabilities before build
- **SAST** for source code vulnerabilities (SQL injection, XSS, insecure crypto, hardcoded secrets). Options: [Semgrep Community Edition](https://semgrep.dev/) (free, LGPL 2.1 engine, single-file analysis); Semgrep AppSec Platform (free for up to 10 contributors, then paid; adds cross-file dataflow analysis and AI-assisted triage, so fewer false positives); [Opengrep](https://github.com/opengrep/opengrep) (free LGPL 2.1 fork of Semgrep CE, launched January 2025 by Aikido Security with Endor Labs, Orca and other vendors; more false positives; install from the curl installer or release binaries, not pip); [Aikido Security](https://www.aikido.dev/) (the platform that initiated Opengrep; SAST plus SCA, secrets, IaC and container-image scanning in one tool, free tier available). Start with Opengrep (free) or Aikido's free tier; pay for Semgrep or Aikido when triage noise costs more than the licence.

**Pre-Build Checklist**:

- Pin all versions (application, dependencies, CI tools) - never use `latest`
- GitHub Actions pinned by full commit SHA (the SLSA generator by exact `@vX.Y.Z` tag)
- Dependabot configured and updates merged
- Opengrep scans pass (no critical/high findings)
- Application tests pass
- Code reviewed (minimum one person)
- Secrets removed (use GitHub Secret Protection push protection or [TruffleHog](https://github.com/trufflesecurity/trufflehog))

**Pin GitHub Actions by Commit SHA**:

A tag like `@v4` is a pointer that the action's owner - or whoever steals their token - can move. In March 2025 attackers retroactively moved the version tags of `tj-actions/changed-files` (CVE-2025-30066) to a malicious commit that dumped CI secrets into workflow logs across 23,000+ repositories. In March 2026 an attacker force-pushed 76 of 77 `aquasecurity/trivy-action` tags to credential-stealing code. A full-length commit SHA is the only immutable reference GitHub Actions has.

- Pin every action to its 40-character SHA with the version as a trailing comment - Dependabot updates both
- Enable "Require actions to be pinned to a full-length commit SHA" in the repository or organization Actions policy so unpinned workflows fail
- Exception: the SLSA generator must be called by its exact `@vX.Y.Z` tag, and v2.1.0 calls its internal actions by tag, so the policy breaks it (issue #4440, open) - don't enforce it on repositories that call the generator

```yaml
- name: Checkout code
  uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

### Stage 2: Container Image Build

Build production container image using multi-stage Dockerfile that progressively hardens the image.

**Image Naming Convention**:

- Tag format: `{registry}/{project}:{version}-{arch}`
- Include architecture in tag: `-amd64` or `-arm64`
- Examples: `registry.example.com/nginx:1.25.3-amd64`, `registry.example.com/python:3.14-arm64`
- Never use `latest` tag - always pin specific versions

**Why Explicit Architecture Tags for Private Registries:**

For production deployments, always use explicit architecture tags (`-amd64`, `-arm64`) rather than manifest lists:

**Security note:**

- Cosign signs a digest, and a digest is the SHA-256 of the manifest bytes, so anyone can compute it (BuildKit reports it at build time). A manifest substituted in the registry has a different digest and cannot inherit a signature made over yours
- Single-arch images and manifest lists alike sit unsigned in the registry between push and sign; Kyverno `verifyImages` rejects unsigned digests at admission and rewrites the pod to the verified digest
- For manifest lists, sign the index and every platform manifest: `cosign sign --recursive {image}@sha256:{index-digest}`
- The real risk is signing by tag, which signs whatever the tag points to at that moment

**Operational advantages:**

- Deployment YAML explicitly declares architecture: `image: registry.example.com/app:1.0.0-amd64`
- No ambiguity about which image gets pulled
- Easier troubleshooting (image tag matches actual architecture)
- Kyverno signature verification works on actual image, not manifest reference

**When manifest lists make sense:**

- Public registries (Docker Hub, Quay.io) where end users don't control architecture
- Multi-arch base images for local development (`docker pull nginx` auto-selects)

**For production:** Explicit architecture tags keep image references clear and auditable; signing by digest and verifying at admission is what keeps unsigned images from running.

**Builder Stage**: Start with Docker Hardened Image with dev tools

- Install build dependencies
- **Go projects**: Clone from official source, compile with the latest stable Go release pinned to an exact version (e.g. `GOTOOLCHAIN=go1.X.Y` or a digest-pinned builder image) and bumped on every Go security release, use `CGO_ENABLED=0` for static binaries, `go mod tidy && go mod verify`, build flags `-trimpath` and `-ldflags "-s -w"`. Never use pre-compiled Go binaries.
- **Other languages**: Install language-specific build tools
- Build application binaries and run tests

**Runtime Stage**: Fresh Docker Hardened Image

- Copy compiled artifacts from builder (no build tools)
- Install minimal runtime dependencies only
- Create non-root user with minimal permissions
- Configure as default user (never run as root)

**Hardened Stage**: Attack surface reduction

- Remove package managers: `apt`, `apt-get`, `dpkg`
- Remove unused libraries: run `ldd` on every binary, follow transitive dependencies several levels deep, and keep only the libraries they actually load
- Optionally remove shells if not needed for runtime
- Clean up: documentation, man pages, caches, temp files
- **Result**: Immutable image that cannot install packages

**Logging**: Build started/completed, stage completions, image size

**Reproducible Builds**: Ensure builds are deterministic by pinning all versions (base image, dependencies, toolchains), stripping timestamps from build artifacts, and sorting inputs consistently. This allows independent verification that published images match source code and build configuration.

### Stage 3: Vulnerability Patching and Image Compression

**Important**: Copacetic patching and image compression are **part of the image build process**, not post-build operations. The SLSA provenance attestation should reference the **final patched and compressed image**, as this is what gets deployed to production. Stages 2-3 together constitute the complete image build. Push, sign and attest only the final digest: patching or compression changes the digest, so a signature or provenance made before them does not cover the image you deploy.

**Copacetic Patching** (runs immediately after build, before scanning):

- Analyzes image package manifest, identifies patchable vulnerabilities
- Downloads and applies security patches without rebuild
- Retag patched image, remove unpatched version
- **Why first**: Reduces vulnerabilities before SBOM/scanning, ensures artifacts reflect patched state
- **Scope**: Copacetic patches OS-level packages installed via package managers (apt, yum, apk); its pip/npm/Go library patching is still experimental (`COPA_EXPERIMENTAL=1`). Otherwise language packages need a rebuild: bump application dependencies in the lockfile (Dependabot), and upgrade the package-manager CLIs bundled in the base image, which Trivy also flags:
  - **npm**: Upgrade via `RUN npm install -g npm@12.1.0` (pin a current specific version, not `@latest`)
  - **pip**: Upgrade via `RUN pip install --no-cache-dir pip==26.2.1` (pin a current specific version, not `--upgrade pip`)
  - **Go**: Must compile from source - `go get golang.org/x/net@v0.59.0 && go mod tidy && go build` (pin current specific versions, not `@latest`; check `govulncheck` for the version you pin)
  - These require package managers still present in the image - if removed during hardening, image rebuild is required

**Image Compression** (tar export/import with metadata preservation):

1. Inspect image to extract all metadata (USER, ENV, WORKDIR, CMD, ENTRYPOINT, EXPOSE, VOLUME, STOPSIGNAL, LABEL, HEALTHCHECK)
2. Create temporary container (`docker create`)
3. Export filesystem to tar (`docker export`)
4. Remove temporary container and old image
5. Import tar with `--change` flags to restore all metadata
6. Clean up tar file

- **Benefits**: Single-layer image, significantly smaller, faster pulls, preserves all runtime behavior

**Logging**: Patching started/completed, vulnerabilities patched (count/severity), compression started/completed, size comparison

### Stage 4: Application Testing

Verify the patched and compressed image functions correctly before security scanning. Testing validates the build pipeline produced a working, secure image.

**Test Categories**:

- **Basic**: Binary exists, version check, help commands, startup
- **Runtime**: User ID (non-root), working directory, environment variables, permissions
- **Application-specific**: Web servers (HTTP response), databases (connections), CLI tools (commands), APIs (endpoints)
- **Dependencies**: Required libraries present (`ldd`), no missing dependencies
- **Integration**: Startup/shutdown, port binding, volumes, signal handling

**Implementation**: Create `test.sh` in repository with comprehensive, fast tests using exit codes and clear error messages.

---

**Example Test Script Structure:**

```bash
#!/bin/bash
set -e
IMAGE_NAME=$1

# Test 1: Binary functionality
VERSION=$(docker run --rm --entrypoint /path/to/binary "$IMAGE_NAME" --version)
if [[ ! "$VERSION" =~ expected_pattern ]]; then exit 1; fi

# Test 2: Non-root user verification
USER_ID=$(docker run --rm --entrypoint id "$IMAGE_NAME" -u)
if [ "$USER_ID" = "0" ]; then exit 1; fi

# Test 3: Missing library dependencies
MISSING_LIBS=$(docker run --rm --entrypoint sh "$IMAGE_NAME" -c 'ldd /path/to/binary 2>/dev/null | grep "not found" || true')
if [ -n "$MISSING_LIBS" ]; then exit 1; fi

# Test 4: Container startup and HTTP response (web services)
CONTAINER_ID=$(docker run -d -p 8080:80 "$IMAGE_NAME")
sleep 5
HTTP_CODE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" http://localhost:8080/ || true)
docker rm -f "$CONTAINER_ID"
if [ "$HTTP_CODE" != "200" ]; then exit 1; fi
```

---

**Security-Specific Tests:**

Test that security hardening is properly applied:

- **Package managers removed**: Verify `apt`, `apt-get`, `dpkg`, `yum`, `apk` are absent (exits non-zero if any is found)

  ```bash
  docker run --rm --entrypoint sh "$IMAGE_NAME" -c 'for pm in apt apt-get dpkg yum apk; do command -v "$pm" && exit 1; done; exit 0'
  ```

- **Non-root enforcement**: Verify UID is not 0 using `id -u`

  ```bash
  docker run --rm --entrypoint id "$IMAGE_NAME" -u | grep -v "^0$"
  ```

- **No secrets in environment**: Fail if environment variables match patterns like `password`, `key`, `token`

  ```bash
  if docker run --rm --entrypoint env "$IMAGE_NAME" | grep -qiE "(password|secret|key|token)="; then exit 1; fi
  ```

- **Read-only filesystem**: Verify the service still runs with a read-only root (`touch` under `--read-only` fails for every image, so it proves nothing)

  ```bash
  CONTAINER_ID=$(docker run -d --read-only --tmpfs /tmp "$IMAGE_NAME")
  sleep 5
  RUNNING=$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")
  docker rm -f "$CONTAINER_ID"
  if [ "$RUNNING" != "true" ]; then exit 1; fi
  ```

---

**Test Frameworks by Language:**

- **Shell scripts** (recommended) - Portable, no dependencies, works with any image
- **Python pytest** - Complex validation logic, API testing with `docker-py` and `requests` libraries
- **Go testing** - Fast compiled tests with `testcontainers-go` for container lifecycle
- **Node.js Jest** - JavaScript apps with `dockerode` for Docker interaction

---

**Best Practices:**

- Exit immediately on first failure (fast-fail approach)
- Set 30-60 second timeouts per test to prevent hanging
- Include expected vs actual values in error messages
- Sequential execution is fine (20-30 tests take 2-3 minutes)

---

**Test Coverage Targets:**

| Level             | Tests Included                                | Count       | Duration |
| ----------------- | --------------------------------------------- | ----------- | -------- |
| **Minimum**       | Basic + runtime security + dependencies       | 10-15 tests | ~1 min   |
| **Recommended**   | Above + application-specific + security tests | 20-30 tests | ~2-3 min |
| **Comprehensive** | Above + integration + performance             | 40-50 tests | ~5-8 min |

---

**Failure Handling**: Stop pipeline immediately, log failure details, preserve failed image for debugging, notify team.

**Logging**: Testing started, category completions, failures with details, total test time

### Stage 5: Security Artifacts Generation and Signing

Generate SLSA provenance, SBOMs, vulnerability scan reports, sign all artifacts, and upload to object storage.

**Minimal GitHub Actions Workflow Example** (build, scan, sign, provenance). Insert the Copacetic, compression and test steps from Stages 3-4 before the push so the digest you sign and attest is the final image:

```yaml
# .github/workflows/build-and-sign.yml
name: Build, Scan, and Sign Container Image

on:
  push:
    tags:
      - "v*"

env:
  REGISTRY: registry.example.com
  IMAGE_NAME: myapp

permissions:
  contents: read
  id-token: write
  packages: write

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
      digest: ${{ steps.build.outputs.digest }}

    steps:
      - name: Checkout code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1

      - name: Log in to registry
        uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ vars.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          platforms: linux/amd64
          provenance: false # BuildKit attestations turn the push into an index; SLSA provenance comes from the generator job
          push: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}-amd64

      - name: Install Trivy
        uses: aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567 # v0.3.1
        with:
          version: v0.74.0

      - name: Scan image and generate SBOM
        run: |
          IMAGE="${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}"

          # Vulnerability scan: fail the job (nothing gets signed) on fixable HIGH/CRITICAL
          trivy image --format json --output vulnerability-report.json "$IMAGE"
          trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed "$IMAGE"

          # Generate SBOMs
          trivy image --format cyclonedx --output sbom-cyclonedx.json $IMAGE
          trivy image --format spdx-json --output sbom-spdx.json $IMAGE

      - name: Install Cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
        with:
          cosign-release: "v3.1.3"

      - name: Sign image with Cosign
        run: |
          IMAGE=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
          cosign sign --yes $IMAGE

      - name: Sign artifacts
        run: |
          for file in sbom-cyclonedx.json sbom-spdx.json vulnerability-report.json; do
            cosign sign-blob --yes --bundle ${file}.bundle $file
          done

      - name: Configure AWS credentials (OIDC, no stored keys)
        uses: aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd # v6.3.0
        with:
          role-to-assume: arn:aws:iam::123456789012:role/build-artifacts-upload
          aws-region: us-east-1

      - name: Upload artifacts to S3
        run: |
          VERSION=${{ github.ref_name }}
          for f in sbom-cyclonedx.json sbom-spdx.json; do
            aws s3 cp "$f" "s3://build-artifacts/sboms/${VERSION}/"
            aws s3 cp "$f.bundle" "s3://build-artifacts/sboms/${VERSION}/"
          done
          aws s3 cp vulnerability-report.json "s3://build-artifacts/scans/${VERSION}/"
          aws s3 cp vulnerability-report.json.bundle "s3://build-artifacts/scans/${VERSION}/"

  provenance:
    needs: [build-and-push]
    permissions:
      actions: read # generator reads the workflow run
      id-token: write
      contents: read
      packages: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0
    with:
      image: ${{ needs.build-and-push.outputs.image }} # env context is not allowed here
      digest: ${{ needs.build-and-push.outputs.digest }}
      registry-username: ${{ vars.REGISTRY_USERNAME }} # secrets context is not allowed in with:
      # private-repository: true # required for private repos; publishes repo metadata to public Rekor
    secrets:
      registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

Pin third-party actions to a full commit SHA; Dependabot (`package-ecosystem: github-actions`) keeps the SHAs current. The SLSA generator is the one exception and stays on its exact `@v2.1.0` tag.

**SLSA Provenance Attestation**:

**Use the official [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)** for SLSA Level 3 compliance. The `provenance` job in the workflow above calls it as a reusable workflow once the image is pushed, passing the image name and digest from the build job.

**Why use the official generator:**

- Meets SLSA Level 3 unforgeable provenance requirements
- Generates cryptographically signed attestations in GitHub's secure environment
- Automatically includes: repository, commit SHA, workflow, builder ID, timestamps, dependencies
- Provides verifiable proof the image was built by GitHub Actions (not a local machine)

**Alternative - [GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)** (built into GitHub, no generator to call):

- One step after the build: `actions/attest` signs SLSA v1.0 build provenance with Sigstore and can push it to the registry next to the image
- **SLSA Build L2** on its own; **Build L3** when the build and attest steps live in a reusable workflow that your repositories call
- Available for public repositories on every current plan; private and internal repositories need GitHub Enterprise Cloud
- Verify with `gh attestation verify oci://registry.example.com/myapp@sha256:DIGEST --owner yourorg`, adding `--signer-workflow` to pin the reusable workflow
- Trade-off: the official generator gives L3 with no workflow of your own to maintain, but has not shipped a release since v2.1.0 (February 2025); attestations are maintained by GitHub

```yaml
# Job permissions: id-token: write, attestations: write, artifact-metadata: write, packages: write
- name: Attest build provenance
  uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
  with:
    subject-name: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
    subject-digest: ${{ steps.build.outputs.digest }}
    push-to-registry: true
```

**Alternative - Manual attestation** (if official generator doesn't fit your workflow):

- Generate provenance in SLSA format matching the official specification
- Include build parameters (repository, commit SHA, workflow, builder ID)
- Include timestamps (build start/end times), resolved dependencies, byproducts (SBOMs, vulnerability scans)
- Save as JSON file (e.g., `attestation-{image-name}-{arch}.json`)
- **Note**: Manual attestations don't meet SLSA Level 3's unforgeable-provenance requirement without additional infrastructure

**SBOM Generation** (using [Trivy](https://github.com/aquasecurity/trivy)):

- Generate in **both** CycloneDX and SPDX-JSON formats for maximum compatibility
- CycloneDX: `trivy image --format cyclonedx --output sbom-{image}-cyclonedx.json {image}`
- SPDX: `trivy image --format spdx-json --output sbom-{image}-spdx.json {image}`
- SBOMs catalog all packages, dependencies, and versions in the image

**Vulnerability Scan** (using [Trivy](https://github.com/aquasecurity/trivy)):

- Scan patched image for remaining vulnerabilities
- Generate JSON report: `trivy image --format json --output scan-{image}.json {image}`
- Fail the build on fixable HIGH and CRITICAL findings: `trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed {image}`
- Report should show minimal vulnerabilities after Copacetic patching

**Signing with [Cosign](https://github.com/sigstore/cosign)**:

- Sign each artifact with `cosign sign-blob`, in the same mode as the image signature:
  - `cosign sign-blob --yes --bundle {file}.bundle {file}` (keyless, as in the workflow; add `--key <kms-uri>` only if you sign everything key-based)
- Sign: SLSA attestation, both SBOMs (CycloneDX and SPDX), vulnerability scan report
- Creates a `.bundle` file per artifact (signature, certificate and transparency-log proof); cosign 3.x requires `--bundle` and deprecates `--output-signature`
- Verify with the matching mode: keyless bundles against the workflow identity (`--certificate-identity`, `--certificate-oidc-issuer`), key-based ones against the public key

**Upload to Object Storage**:

- Upload all artifacts to cloud storage (S3/GCS/Azure Blob):
  - `sboms/{arch}/sbom-{image}-cyclonedx.json`
  - `sboms/{arch}/sbom-{image}-cyclonedx.json.bundle`
  - `sboms/{arch}/sbom-{image}-spdx.json`
  - `sboms/{arch}/sbom-{image}-spdx.json.bundle`
  - `attestations/{arch}/attestation-{image}.json`
  - `attestations/{arch}/attestation-{image}.json.bundle`
  - `scans/{arch}/scan-{image}.json`
  - `scans/{arch}/scan-{image}.json.bundle`
- Organize by architecture for multi-platform builds

**Logging**: SBOM generation started/completed (formats), vulnerability scan completed (findings count), attestation generated, signing completed (artifacts signed), upload completed (file count, bucket path)

### Stage 6: Image Signing and Registry Push

**Critical**: Cosign can only sign an image that is already in a registry: it resolves the digest there and stores the signature next to it as an OCI artifact. `docker push` never carries a signature, so you cannot sign first and push second. Push, sign the pushed digest immediately, and let admission control (Kyverno, Section 4) reject any digest without a valid signature.

**Registry Authentication**:

- Login to container registry using credentials from vault
- Authenticate before pushing to ensure proper permissions

**Push to Registry**:

- Push the final (patched and compressed) image and record its digest: `docker push {image}` (or `docker/build-push-action` with `push: true`, which outputs `digest`)

**Image Signing with [Cosign](https://github.com/sigstore/cosign)**:

- Sign by digest, never by tag: `cosign sign --yes {registry}/{image}@{digest}` (keyless, bound to the workflow's GitHub OIDC identity, as in the Stage 5 workflow)
- For a multi-arch index, add `--recursive` to sign the index and every platform manifest
- For key-based signing, keep the key in a KMS instead of a file: `cosign sign --yes --key awskms:///alias/cosign {registry}/{image}@{digest}`
- Signature is stored in the registry as an OCI artifact attached to that digest

**Attach SLSA Attestation**:

- The SLSA generator (Stage 5) signs and uploads its provenance itself; attach a manual attestation only if you do not use it
- Command: `cosign attest --yes --predicate attestation.json --type slsaprovenance {registry}/{image}@{digest}`
- Verifiers can retrieve attestation to validate build provenance

**Keyless Signatures - Verify the Identity, Not Just the Signature**:

The Stage 5 workflow signs keyless (`cosign sign --yes` trades the runner's OIDC token for a short-lived Fulcio certificate), and the SLSA generator always signs provenance keyless. There is no public key to check, and any GitHub Actions workflow in any repository can get a certificate from the same issuer - a valid keyless signature on its own proves nothing. Pin both the identity (the signing workflow's URL and ref) and the issuer; cosign refuses keyless verification without them. Never use `.*` as the identity regexp. In Kyverno, use a `keyless` attestor with `subject` (or `subjectRegExp`) and `issuer` instead of `publicKeys` - a key-based policy rejects every keyless signature.

```bash
# Image signature: must come from your release workflow on a version tag
cosign verify \
  --certificate-identity-regexp '^https://github.com/yourorg/yourapp/.github/workflows/build-and-sign.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  registry.example.com/myapp@sha256:DIGEST

# Provenance: must come from the official generator at an exact release tag
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  registry.example.com/myapp@sha256:DIGEST
```

**Why This Order Matters**:

- **Push → Sign → Attest**: every step targets the same immutable digest, so what you sign is exactly what runs
- A digest is a hash of the manifest, so a swapped image has a different digest and cannot reuse your signature
- Admission control closes the push-to-sign gap: an unsigned digest cannot be deployed

**Logging**: Image signing started/completed, registry authentication successful, image pushed (registry URL, digest), attestation attached, total stage time

## 4. Post-Pipeline Operations

### Continuous Vulnerability Monitoring

**Daily Scanning for New CVEs**:

- Schedule automated scans of published images in registry
- Check for newly disclosed HIGH and CRITICAL vulnerabilities with available fixes
- If patchable vulnerabilities found, trigger automated rebuild
- Copacetic patches OS-level vulnerabilities in rebuild
- Go projects automatically recompile with the current pinned Go toolchain (bumped on each Go security release) to patch vulnerabilities in Go standard library
- Push updated image to registry with new patch version tag
- Update SLSA attestation and SBOMs for new version

**Scanning Options:**

Choose between registry-based scanning or Kubernetes-native continuous scanning based on your deployment environment.

| Approach              | Deployment Location            | Real-Time Monitoring | Setup Complexity | Integration                                   | Best For                                       |
| --------------------- | ------------------------------ | -------------------- | ---------------- | --------------------------------------------- | ---------------------------------------------- |
| **Registry Scanning** | Container registry or cron job | No                   | Low              | Built-in registry scanners or scheduled Trivy | Simple setups, registry-focused                |
| **Trivy Operator**    | Kubernetes cluster             | Yes                  | Medium           | Native K8s custom resources, Fluentd export   | Kubernetes environments, continuous monitoring |

**Registry Scanning:**

- Scan images directly in container registry using built-in scanners (ECR/Artifact Registry/ACR/Harbor)
- Or run Trivy on a cron job to scan registry images periodically
- Generates vulnerability reports accessible via registry UI or API

**Trivy Operator:**

- Kubernetes-native continuous scanning via [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
- Automatically scans running workloads and images
- Generates vulnerability reports as Kubernetes custom resources
- Pair with [Fluentd](https://github.com/fluent/fluentd) to export scan results to external logging/monitoring systems
- Provides real-time security posture visibility

### Runtime Policy Enforcement with Kubernetes

**[Kyverno](https://github.com/kyverno/kyverno)**: Kubernetes-native policy engine for runtime security

**Essential Policies:**

- **Image Signature Verification**: Require signed images
- **SLSA Provenance Verification**: Require authorized source repo and builder
- **Non-Root Enforcement**: Block containers running as root user
- **Resource Limits**: Enforce CPU and memory limits on all pods
- **Privileged Containers**: Block privileged mode and dangerous capabilities
- **Host Namespace Isolation**: Prevent hostNetwork, hostPID, hostIPC usage
- **Read-Only Root Filesystem**: Require read-only root filesystem where possible
- **Image Registry Allowlist**: Only allow images from approved registries

**Additional Runtime Security:**

- **[Istio](https://github.com/istio/istio)**: Service mesh for mutual TLS (mTLS) between workloads (set a mesh-wide `PeerAuthentication` to `STRICT`; the default `PERMISSIVE` mode still accepts plaintext), traffic management, L7 authorization policies, and observability
- **[Falco](https://github.com/falcosecurity/falco)**: Runtime threat detection for unusual container behavior
- **Pod Security Standards**: Enforce baseline/restricted pod security standards

### SLSA Provenance Verification

**Why It's Critical:**

Image signature verification only checks "was this signed?" - it doesn't verify the image was built from the correct source repository or builder. Without provenance verification, an attacker with your signing key can deploy backdoored images built from forked repos.

**Kyverno Policy with Provenance Verification:**

Kyverno 1.17 deprecated `ClusterPolicy`, and its removal is planned for Kyverno 1.20 (targeted for October 2026). Write new policies as an `ImageValidatingPolicy` (`policies.kyverno.io/v1`), starting from Kyverno's [`verify-image-slsa` sample](https://github.com/kyverno/policies/blob/main/other-ivpol/verify-image-slsa/verify-image-slsa.yaml). The `ClusterPolicy` below works until that removal.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-slsa-provenance
spec:
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-provenance
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - failureAction: Enforce
          imageReferences:
            - "registry.example.com/*"

          # Verify signature (keyless, from your release workflow)
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/yourorg/yourapp/.github/workflows/build-and-sign.yml@refs/tags/v*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev

          # Verify provenance claims (keyless, signed by the SLSA generator)
          attestations:
            - predicateType: https://slsa.dev/provenance/v0.2
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v*"
                        issuer: "https://token.actions.githubusercontent.com"
                        rekor:
                          url: https://rekor.sigstore.dev
              conditions:
                - all:
                    # Must be from authorized repo (the URI includes the git ref)
                    - key: "{{ invocation.configSource.uri }}"
                      operator: Equals
                      value: "git+https://github.com/yourorg/yourapp@refs/tags/v*"

                    # Must be built by the SLSA container generator (any release tag)
                    - key: "{{ regex_match('^https://github[.]com/slsa-framework/slsa-github-generator/[.]github/workflows/generator_container_slsa3[.]yml@refs/tags/v[0-9]+[.][0-9]+[.][0-9]+$', '{{ builder.id }}') }}"
                      operator: Equals
                      value: true
```

**What Gets Verified:**

1. Image was built from authorized source repository (not attacker's fork)
2. Image was built by authorized builder (GitHub Actions, not local machine)
3. Signature is valid

**Testing:**

```bash
# Manual verification (the generator signs provenance keyless; verify by digest)
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  registry.example.com/app@sha256:DIGEST

# Or check source repo and tag in one step
slsa-verifier verify-image registry.example.com/app@sha256:DIGEST \
  --source-uri github.com/yourorg/yourapp \
  --source-tag v1.0.0
```

## 5. Attack Scenarios Prevented

This guide's SLSA Level 3 pipeline prevents supply chain attacks targeting the software build and delivery process.

**Build-Time Code Injection**

- Attack: Modified source code or build scripts during CI/CD execution
- Mitigated by: Ephemeral build environments (no shared state), Git commit verification, SLSA provenance tracking source commit, signed attestations

**Build Process Manipulation**

- Attack: Manipulated build flags, dependencies, or compilation to inject vulnerabilities
- Mitigated by: SLSA provenance documenting exact build parameters, reproducible builds with pinned toolchains, ephemeral environments, cryptographic attestations

**Source Code Secret Leakage**

- Attack: Hardcoded credentials, API keys, or tokens accidentally committed to source
- Mitigated by: TruffleHog secret scanning in pre-commit hooks, GitHub push protection blocking pushes that contain secrets (GitHub Secret Protection on private repositories), SAST scanning (Opengrep), secrets in external vaults

**Malicious Dependency Injection**

- Attack: Compromised upstream dependencies (packages, libraries) injecting malicious code
- Mitigated by: Version pinning with committed lockfiles and integrity hashes (never `latest`), Dependabot cooldown before adopting new releases and malware alerts (opt-in), SBOM generation (CycloneDX, SPDX) to find affected images fast once a package is flagged

**Compromised Base Image**

- Attack: Backdoors injected into base container images used for builds
- Mitigated by: Using trusted base images (Docker Hardened Images from verified vendor) pinned by digest, verifying the base image's signature and provenance before building (`cosign verify`), Copacetic patching and Trivy scanning for known CVEs (neither detects a backdoor that has no CVE yet)

**Vulnerability Deployment**

- Attack: Deploying container images with known HIGH/CRITICAL CVEs to production
- Mitigated by: Copacetic patching during build, Trivy scanning failing the build on fixable HIGH/CRITICAL CVEs, Go projects recompiled with the current pinned toolchain, Trivy Operator post-deployment scanning

**Registry Poisoning**

- Attack: Malicious images pushed to registry impersonating legitimate builds
- Mitigated by: Registry authentication required for push/pull, Cosign signing by digest (a substituted image has a different digest and no valid signature), Kyverno signature verification, SLSA attestation proving authentic build, keyless OIDC signing (or signing keys in a KMS/vault if you sign key-based)

**Unsigned Artifact Tampering**

- Attack: Modified SBOMs, vulnerability reports, or attestations after generation
- Mitigated by: All artifacts signed with Cosign, signatures verified before trusting, artifacts stored in secure object storage with access controls, immutable artifact chain

**Compromised Container Registry**

- Attack: Registry access gained to modify or replace images
- Mitigated by: Kyverno + Cosign image signature verification, SLSA attestation verification matching build provenance, registry access controls and audit logging, immutable image tags

**Runtime Package Manager Abuse**

- Attack: Attackers use package managers (apt, yum, apk) in compromised containers to install malicious tools
- Mitigated by: Hardened stage in Dockerfile removes all package managers, non-root user preventing installations, immutable read-only root filesystem where possible

**Unpatched Runtime Vulnerabilities**

- Attack: New CVEs disclosed after image deployment creating exploitable vulnerabilities
- Mitigated by: Daily automated scanning of published images, automated rebuilds when patchable vulnerabilities found, Copacetic re-patching in rebuild, GitOps deployment (e.g. Argo CD) rolling out the rebuilt image

## 6. References

### SLSA Framework

- [SLSA Specification](https://slsa.dev/)
- [SLSA Build Requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [SLSA Source Track](https://slsa.dev/spec/v1.2/source-requirements)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [Achieving SLSA v1 Build Level 3 with Artifact Attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating)

### Tools and Projects

- [Docker Buildx](https://github.com/docker/buildx)
- [Docker Hardened Images](https://www.docker.com/products/hardened-images/)
- [Docker Hardened Images: free and open source (December 2025)](https://www.docker.com/press-release/docker-makes-hardened-images-free-open-and-transparent-for-everyone/)
- [Copacetic](https://github.com/project-copacetic/copacetic)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
- [Cosign](https://github.com/sigstore/cosign)
- [Cosign: Verifying Signatures](https://docs.sigstore.dev/cosign/verifying/verify/)
- [actions/attest](https://github.com/actions/attest)
- [Syft](https://github.com/anchore/syft)
- [Grype](https://github.com/anchore/grype)
- [Dependabot](https://github.com/dependabot/dependabot-core)
- [Semgrep](https://semgrep.dev/)
- [Opengrep](https://github.com/opengrep/opengrep)
- [Aikido Security](https://www.aikido.dev/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Kyverno](https://github.com/kyverno/kyverno)
- [Kyverno: Migrating to CEL Policies](https://kyverno.io/docs/guides/migration-to-cel/)
- [Istio](https://github.com/istio/istio)
- [Falco](https://github.com/falcosecurity/falco)
- [Fluentd](https://github.com/fluent/fluentd)

### Standards and Specifications

- [SPDX Specification](https://spdx.dev/)
- [CycloneDX Specification](https://cyclonedx.org/)
- [in-toto Attestation Framework](https://in-toto.io/)
- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)
- [Sigstore](https://www.sigstore.dev/)
- [GitHub Actions Secure Use Reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Google Container Registry to Artifact Registry transition](https://docs.cloud.google.com/artifact-registry/docs/transition/transition-from-gcr)

### Incident Reports

- [SolarWinds supply chain compromise (CIS)](https://www.cisecurity.org/solarwinds)
- [Codecov Bash Uploader post-mortem](https://about.codecov.io/apr-2021-post-mortem/)
- [CVE-2024-3094: xz-utils backdoor (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
- [GHSA-mrrh-fwg8-r2c3: tj-actions/changed-files compromise (CVE-2025-30066)](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [GHSA-69fq-xp46-6x23: Trivy supply chain compromise (CVE-2026-33634)](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
