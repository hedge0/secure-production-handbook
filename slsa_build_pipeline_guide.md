# SLSA Build Pipeline Guide

A cloud-agnostic guide for building secure, verifiable container images with SLSA Level 3 compliance using GitHub Actions. This guide includes industry best practices and lessons learned from real-world production implementations.

## Table of Contents

1. [Overview](#overview)
   - [SLSA Level 3 Requirements](#slsa-level-3-requirements)
2. [Prerequisites](#prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
   - [Secrets to Store in Vault](#secrets-to-store-in-vault)
3. [Pipeline Stages](#pipeline-stages)
   - [Stage 1: Base Image and Application Layer Preparation](#stage-1-base-image-and-application-layer-preparation)
   - [Stage 2: Container Image Build](#stage-2-container-image-build)
   - [Stage 3: Vulnerability Patching and Image Compression](#stage-3-vulnerability-patching-and-image-compression)
   - [Stage 4: Application Testing](#stage-4-application-testing)
   - [Stage 5: Security Artifacts Generation and Signing](#stage-5-security-artifacts-generation-and-signing)
   - [Stage 6: Image Signing and Registry Push](#stage-6-image-signing-and-registry-push)
4. [Post-Pipeline Operations](#post-pipeline-operations)
   - [Continuous Vulnerability Monitoring](#continuous-vulnerability-monitoring)
   - [Runtime Policy Enforcement with Kubernetes](#runtime-policy-enforcement-with-kubernetes)
5. [Attack Scenarios Prevented](#attack-scenarios-prevented)
6. [References](#references)

## Overview

This guide outlines a production-grade container image build pipeline that achieves SLSA (Supply-chain Levels for Software Artifacts) Level 3 compliance. The pipeline is cloud-agnostic and works with any container registry that supports signed images (such as AWS ECR, Google GCR/Artifact Registry, Azure ACR, and Harbor) and object storage provider (S3, GCS, Azure Blob Storage).

### SLSA Level 3 Requirements

- **Source**: Version-controlled with verified history
- **Review**: At least one-person review recommended
- **Build**: Automated build process in ephemeral, isolated environment
- **Provenance**: Complete, unforgeable build provenance
- **Non-falsifiable**: Strong protections against tampering

## Prerequisites

### Required Tools

- **[Docker Buildx](https://github.com/docker/buildx)**: Multi-platform image building with BuildKit
- **[Copacetic](https://github.com/project-copacetic/copacetic)**: Vulnerability patching tool (runs immediately after build)
- **[Trivy](https://github.com/aquasecurity/trivy)**: Vulnerability scanning and SBOM generation (runs after patching)
- **[Cosign](https://github.com/sigstore/cosign)**: Container signing and verification tool for signing images, SBOMs, and attestations
- **[Syft](https://github.com/anchore/syft)**: SBOM generation tool (alternative to Trivy)
- **[Grype](https://github.com/anchore/grype)**: Vulnerability scanner (alternative to Trivy)

### External Services

**Container Registry** (must support signed images):

- AWS Elastic Container Registry (ECR)
- Google Container Registry (GCR) / Artifact Registry
- Azure Container Registry (ACR)
- Harbor

**Object Storage**:

- AWS S3
- Google Cloud Storage (GCS)
- Azure Blob Storage
- MinIO or S3-compatible storage

**Secrets Management** (required):

- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault
- HashiCorp Vault
- Kubernetes External Secrets Operator

**Logging Service** (required):

- AWS CloudWatch Logs
- GCP Cloud Logging
- Azure Monitor
- Splunk
- Self-hosted solutions (ELK Stack, Loki, Fluentd, etc.)

### Secrets to Store in Vault

All sensitive credentials must be stored in external vault services:

- **Registry credentials**: URL, username, password/token
- **Cosign signing credentials**: Private key content, private key password
- **Object storage credentials**: Access key, secret key, bucket name, region
- **Logging service credentials**: API keys, service account credentials (if applicable)

## Pipeline Stages

### Stage 1: Base Image and Application Layer Preparation

Prepare and secure application code and dependencies before building the container image. Each build runs independently in an ephemeral GitHub Actions runner with no shared state.

**Base Image**: Use [Docker Hardened Images](https://www.docker.com/products/hardened-images/) (Debian-based with dev tools, not distroless) for battle-tested stability, GNU/glibc support, and ability to install build dependencies. Free tier images require Copacetic patching (Stage 3).

**Application Security**:

- **[Dependabot](https://github.com/dependabot/dependabot-core)**: Automated dependency updates, creates PRs for outdated packages, catches vulnerabilities before build
- **[Opengrep](https://github.com/opengrep/opengrep)**: SAST for source code vulnerabilities (SQL injection, XSS, insecure crypto, hardcoded secrets, etc.)

**Pre-Build Checklist**:

- Pin all versions (application, dependencies) - never use `latest`
- Dependabot configured and updates merged
- Opengrep scans pass (no critical/high findings)
- Application tests pass
- Code reviewed (minimum one person)
- Secrets removed (use GitHub Secret Scanning or [TruffleHog](https://github.com/trufflesecurity/trufflehog))

### Stage 2: Container Image Build

Build production container image using multi-stage Dockerfile that progressively hardens the image.

**Image Naming Convention**:

- Tag format: `{registry}/{project}:{version}-{arch}`
- Include architecture in tag: `-amd64` or `-arm64`
- Examples: `registry.example.com/nginx:1.25.3-amd64`, `registry.example.com/python:3.11-arm64`
- Never use `latest` tag - always pin specific versions

**Builder Stage**: Start with Docker Hardened Image with dev tools

- Install build dependencies
- **Go projects**: Clone from official source, compile with latest stable Go toolchain, use `CGO_ENABLED=0` for static binaries, `go mod tidy && go mod verify`, build flags `-trimpath` and `-ldflags "-s -w"`. Never use pre-compiled Go binaries.
- **Other languages**: Install language-specific build tools
- Build application binaries and run tests

**Runtime Stage**: Fresh Docker Hardened Image

- Copy compiled artifacts from builder (no build tools)
- Install minimal runtime dependencies only
- Create non-root user with minimal permissions
- Configure as default user (never run as root)

**Hardened Stage**: Attack surface reduction

- Remove package managers: `apt`, `apt-get`, `dpkg`
- Remove exclusive dependencies: Use `ldd` on binaries, trace transitive dependency chains multiple layers deep, keep only required libraries
- Optionally remove shells if not needed for runtime
- Clean up: documentation, man pages, caches, temp files
- **Result**: Immutable image that cannot install packages

**Logging**: Build started/completed, stage completions, image size

### Stage 3: Vulnerability Patching and Image Compression

**Copacetic Patching** (runs immediately after build, before scanning):

- Analyzes image package manifest, identifies patchable vulnerabilities
- Downloads and applies security patches without rebuild
- Retag patched image, remove unpatched version
- **Why first**: Reduces vulnerabilities before SBOM/scanning, ensures artifacts reflect patched state

**Image Compression** (tar export/import with metadata preservation):

1. Inspect image to extract all metadata (USER, ENV, WORKDIR, CMD, ENTRYPOINT, EXPOSE, VOLUME, STOPSIGNAL, LABEL)
2. Create temporary container (`docker create`)
3. Export filesystem to tar (`docker export`)
4. Remove temporary container and old image
5. Import tar with `--change` flags to restore all metadata
6. Clean up tar file

- **Benefits**: Single-layer image, significantly smaller, faster pulls, preserves all runtime behavior

**Logging**: Patching started/completed, vulnerabilities patched (count/severity), compression started/completed, size comparison

### Stage 4: Application Testing

Verify the patched and compressed image functions correctly before security scanning.

**Test Categories**:

- **Basic**: Binary exists, version check, help commands, startup
- **Runtime**: User ID (non-root), working directory, environment variables, permissions
- **Application-specific**: Web servers (HTTP response), databases (connections), CLI tools (commands), APIs (endpoints)
- **Dependencies**: Required libraries present (`ldd`), no missing dependencies
- **Integration**: Startup/shutdown, port binding, volumes, signal handling

**Implementation**: Create `test.sh` in repository with comprehensive, fast tests using exit codes and clear error messages.

**Failure Handling**: Stop pipeline immediately, log failure details, preserve failed image for debugging, notify team.

**Logging**: Testing started, category completions, failures with details, total test time

### Stage 5: Security Artifacts Generation and Signing

Generate SLSA provenance, SBOMs, vulnerability scan reports, sign all artifacts, and upload to object storage.

**SLSA Provenance Attestation**:

- Generate provenance in SLSA format (meets SLSA Level 3 requirements)
- Include build parameters (repository, commit SHA, workflow, builder ID)
- Include timestamps (build start/end times)
- Include resolved dependencies (source code commit)
- Include byproducts (SBOMs, vulnerability scans)
- Save as JSON file (e.g., `attestation-{image-name}-{arch}.json`)

**SBOM Generation** (using [Trivy](https://github.com/aquasecurity/trivy)):

- Generate in **both** CycloneDX and SPDX-JSON formats for maximum compatibility
- CycloneDX: `trivy image --format cyclonedx --output sbom-{image}-cyclonedx.json {image}`
- SPDX: `trivy image --format spdx-json --output sbom-{image}-spdx.json {image}`
- SBOMs catalog all packages, dependencies, and versions in the image

**Vulnerability Scan** (using [Trivy](https://github.com/aquasecurity/trivy)):

- Scan patched image for remaining vulnerabilities
- Generate JSON report: `trivy image --format json --output scan-{image}.json {image}`
- Filter for HIGH and CRITICAL severities
- Report should show minimal vulnerabilities after Copacetic patching

**Signing with [Cosign](https://github.com/sigstore/cosign)**:

- Sign each artifact using `cosign sign-blob`:
  - `cosign sign-blob --key cosign.key --output-signature {file}.sig {file}`
- Sign: SLSA attestation, both SBOMs (CycloneDX and SPDX), vulnerability scan report
- Creates `.sig` files for each artifact
- Uses private key from vault service

**Upload to Object Storage**:

- Upload all artifacts to cloud storage (S3/GCS/Azure Blob):
  - `sboms/{arch}/sbom-{image}-cyclonedx.json`
  - `sboms/{arch}/sbom-{image}-cyclonedx.json.sig`
  - `sboms/{arch}/sbom-{image}-spdx.json`
  - `sboms/{arch}/sbom-{image}-spdx.json.sig`
  - `attestations/{arch}/attestation-{image}.json`
  - `attestations/{arch}/attestation-{image}.json.sig`
  - `scans/{arch}/scan-{image}.json`
  - `scans/{arch}/scan-{image}.json.sig`
- Organize by architecture for multi-platform builds

**Logging**: SBOM generation started/completed (formats), vulnerability scan completed (findings count), attestation generated, signing completed (artifacts signed), upload completed (file count, bucket path)

### Stage 6: Image Signing and Registry Push

**Critical**: Sign the image BEFORE pushing to registry. Even fractions of a second unsigned is enough for attackers to compromise the image.

**Image Signing with [Cosign](https://github.com/sigstore/cosign)**:

- Sign the local image with private key from vault
- Command: `cosign sign --key cosign.key {image}`
- This creates a signature that will be pushed alongside the image
- Signature is stored in the registry as an OCI artifact

**Registry Authentication**:

- Login to container registry using credentials from vault
- Authenticate before pushing to ensure proper permissions

**Push to Registry**:

- Push the signed image: `docker push {image}`
- The signature is automatically pushed with the image
- Image is now available in registry with cryptographic proof of authenticity

**Attach SLSA Attestation**:

- After push, attach the SLSA provenance attestation to the image in registry
- Command: `cosign attest --key cosign.key --predicate attestation.json --type slsaprovenance {image}`
- Attestation is stored as OCI artifact attached to the image
- Verifiers can retrieve attestation to validate build provenance

**Why This Order Matters**:

- **Sign → Push**: Image is never available unsigned in registry, eliminates window for compromise
- **Push → Attest**: Attestation requires image digest from registry, must happen after push
- Reversing this order creates security vulnerability

**Logging**: Image signing started/completed, registry authentication successful, image pushed (registry URL, digest), attestation attached, total stage time

## Post-Pipeline Operations

### Continuous Vulnerability Monitoring

**Daily Scanning for New CVEs**:

- Schedule automated scans of published images in registry
- Check for newly disclosed HIGH and CRITICAL vulnerabilities with available fixes
- If patchable vulnerabilities found, trigger automated rebuild
- Copacetic patches OS-level vulnerabilities in rebuild
- Go projects automatically recompile with latest toolchain to patch vulnerabilities in Go standard library
- Push updated image to registry with new patch version tag
- Update SLSA attestation and SBOMs for new version

**Scanning Options**:

- **Registry Scanning**: Scan images directly in container registry using built-in scanners (ECR/GCR/ACR/Harbor) or Trivy on a cron job
- **[Trivy Operator](https://github.com/aquasecurity/trivy-operator)**: Kubernetes-native continuous scanning
  - Automatically scans running workloads and images
  - Generates vulnerability reports as Kubernetes custom resources
  - Pair with [Fluentd](https://github.com/fluent/fluentd) to export scan results to external logging/monitoring systems
  - Provides real-time security posture visibility

### Runtime Policy Enforcement with Kubernetes

**[Kyverno](https://github.com/kyverno/kyverno)**: Kubernetes-native policy engine for runtime security

**Essential Policies**:

- **Image Signature Verification**: Require all container images signed with trusted public key (Cosign verification)
- **Non-Root Enforcement**: Block containers running as root user
- **Resource Limits**: Enforce CPU and memory limits on all pods
- **Privileged Containers**: Block privileged mode and dangerous capabilities
- **Host Namespace Isolation**: Prevent hostNetwork, hostPID, hostIPC usage
- **Read-Only Root Filesystem**: Require containers to run with read-only root filesystem where possible
- **Image Registry Allowlist**: Only allow images from approved registries

**Example Kyverno Policy Structure**:

- Validate image signatures on admission
- Mutate pods to add security contexts automatically
- Generate policy reports for non-compliant resources
- Block non-compliant workloads from deployment

**Additional Runtime Security**:

- **[Istio](https://github.com/istio/istio)**: Service mesh for enforcing mutual TLS (mTLS) between containers, traffic management, network policies, and observability
- **[Falco](https://github.com/falcosecurity/falco)**: Runtime threat detection for unusual container behavior
- **Pod Security Standards**: Enforce baseline/restricted pod security standards

## Attack Scenarios Prevented

This guide's SLSA Level 3 pipeline prevents supply chain attacks targeting the software build and delivery process.

### Build-Time Security

**Build-Time Code Injection**

- Attack: Modified source code or build scripts during CI/CD execution
- Mitigated by: Ephemeral build environments (no shared state), Git commit verification, SLSA provenance tracking source commit, signed attestations

**Build Process Manipulation**

- Attack: Manipulated build flags, dependencies, or compilation to inject vulnerabilities
- Mitigated by: SLSA provenance documenting exact build parameters, reproducible builds with pinned toolchains, ephemeral environments, cryptographic attestations

**Source Code Secret Leakage**

- Attack: Hardcoded credentials, API keys, or tokens accidentally committed to source
- Mitigated by: TruffleHog secret scanning in pre-commit hooks, GitHub Secret Scanning blocking commits, SAST scanning (Opengrep), secrets in external vaults

### Dependency & Base Image Security

**Malicious Dependency Injection**

- Attack: Compromised upstream dependencies (packages, libraries) injecting malicious code
- Mitigated by: Dependabot monitoring compromised/vulnerable dependencies, SBOM generation (CycloneDX, SPDX) cataloging all dependencies, version pinning (never `latest`)

**Compromised Base Image**

- Attack: Backdoors injected into base container images used for builds
- Mitigated by: Using trusted base images (Docker Hardened Images from verified vendor), Copacetic patching after build fixing known CVEs, Trivy vulnerability scanning detecting malicious changes

**Vulnerability Deployment**

- Attack: Deploying container images with known HIGH/CRITICAL CVEs to production
- Mitigated by: Copacetic patching during build, Trivy scanning blocking critical unfixed CVEs, Go projects recompiled with latest toolchain, Trivy Operator post-deployment scanning

### Registry & Artifact Security

**Registry Poisoning**

- Attack: Malicious images pushed to registry impersonating legitimate builds
- Mitigated by: Registry authentication required for push/pull, Cosign signing BEFORE registry push (no unsigned window), Kyverno signature verification, SLSA attestation proving authentic build, private signing keys in vault

**Unsigned Artifact Tampering**

- Attack: Modified SBOMs, vulnerability reports, or attestations after generation
- Mitigated by: All artifacts signed with Cosign, signatures verified before trusting, artifacts in object storage (S3/GCS) with versioning/access controls, immutable artifact chain

**Compromised Container Registry**

- Attack: Registry access gained to modify or replace images
- Mitigated by: Kyverno + Cosign image signature verification, SLSA attestation verification matching build provenance, registry access controls and audit logging, immutable image tags

### Runtime Vulnerability Management

**Unpatched Runtime Vulnerabilities**

- Attack: New CVEs disclosed after image deployment creating exploitable vulnerabilities
- Mitigated by: Daily automated scanning of published images, automated rebuilds when patchable vulnerabilities found, Copacetic re-patching in rebuild, GitOps deployment via ArgoCD

## References

### SLSA Framework

- [SLSA Specification](https://slsa.dev/)
- [SLSA Requirements](https://slsa.dev/spec/v1.0/requirements)
- [SLSA Source Track](https://slsa.dev/spec/draft/source-requirements)

### Tools and Projects

- [Docker Buildx](https://github.com/docker/buildx) - Multi-platform image building
- [Docker Hardened Images](https://www.docker.com/products/hardened-images/) - Secure base images
- [Copacetic](https://github.com/project-copacetic/copacetic) - Vulnerability patching
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanning and SBOM generation
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) - Kubernetes security scanning
- [Cosign](https://github.com/sigstore/cosign) - Container signing and verification
- [Syft](https://github.com/anchore/syft) - SBOM generation
- [Grype](https://github.com/anchore/grype) - Vulnerability scanning
- [Dependabot](https://github.com/dependabot/dependabot-core) - Automated dependency updates
- [Opengrep](https://github.com/opengrep/opengrep) - Static application security testing
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning
- [Kyverno](https://github.com/kyverno/kyverno) - Kubernetes policy engine
- [Istio](https://github.com/istio/istio) - Service mesh for mTLS and network policies
- [Falco](https://github.com/falcosecurity/falco) - Runtime security monitoring
- [Fluentd](https://github.com/fluent/fluentd) - Log collection and forwarding

### Standards and Specifications

- [SPDX Specification](https://spdx.dev/) - Software Package Data Exchange
- [CycloneDX Specification](https://cyclonedx.org/) - Software Bill of Materials standard
- [in-toto Attestation Framework](https://in-toto.io/) - Supply chain metadata framework
- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) - Container registry API
- [Sigstore](https://www.sigstore.dev/) - Signing and transparency for software supply chains
