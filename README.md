# Useful Tools

A curated list of useful open-source GitHub projects organized by category

## Operating Systems

- [Alpine Linux](https://github.com/alpinelinux) - Security-oriented, lightweight Linux distribution based on musl libc and busybox, designed for containers and embedded systems with minimal resource footprint.
- [Ubuntu](https://github.com/ubuntu) - Popular Debian-based Linux distribution known for user-friendliness, extensive package repository, and long-term support releases for both desktop and server environments.
- [Debian](https://github.com/debian) - Stable and versatile Linux distribution that serves as the foundation for many other distributions, emphasizing free software principles and community-driven development.

## Programming Languages & Runtimes

- [Git](https://github.com/git/git) - Distributed version control system for tracking changes in source code during software development with support for branching, merging, and collaboration workflows.
- [Go](https://github.com/golang/go) - Statically typed, compiled language designed at Google with built-in concurrency, fast compilation, and efficient garbage collection for building scalable systems.
- [Python (CPython)](https://github.com/python/cpython) - High-level, interpreted programming language with dynamic typing, known for its readability, extensive standard library, and versatility across domains.
- [Rust](https://github.com/rust-lang/rust) - Systems programming language that guarantees memory safety without garbage collection through its ownership model, preventing common bugs at compile time.
- [TypeScript](https://github.com/microsoft/TypeScript) - Statically typed superset of JavaScript that adds optional type annotations, enhanced IDE support, and compile-time error checking.
- [Node.js](https://github.com/nodejs/node) - JavaScript runtime built on Chrome's V8 engine that enables server-side JavaScript execution with an event-driven, non-blocking I/O model.

## Frontend Development

- [React](https://github.com/facebook/react) - JavaScript library for building user interfaces using a component-based architecture with efficient DOM updates through virtual DOM reconciliation.
- [Next.js](https://github.com/vercel/next.js) - React framework that provides server-side rendering, static site generation, API routes, and optimized performance out of the box.
- [Tailwind CSS](https://github.com/tailwindlabs/tailwindcss) - Utility-first CSS framework that provides low-level utility classes for building custom designs without writing custom CSS.
- [Swagger UI](https://github.com/swagger-api/swagger-ui) - Interactive API documentation tool that automatically generates a visual interface for exploring and testing REST APIs from OpenAPI specifications.

## Validation & Schema Libraries

- [Zod](https://github.com/colinhacks/zod) - TypeScript-first schema validation with static type inference and runtime type checking for building type-safe applications.
- [Joi](https://github.com/hapijs/joi) - Powerful schema description and data validation for JavaScript with support for complex validation rules and custom error messages.
- [Pydantic](https://github.com/pydantic/pydantic) - Data validation using Python type annotations with automatic data parsing and serialization for APIs and data models.
- [go-playground/validator](https://github.com/go-playground/validator) - Go struct and field validation with tag-based rules supporting cross-field validation and custom validators.

## Databases & Data Storage

- [PostgreSQL](https://github.com/postgres/postgres) - Advanced open-source relational database system known for reliability, feature robustness, and support for both SQL and JSON querying.
- [Redis](https://github.com/redis/redis) - In-memory data structure store used as a database, cache, message broker, and streaming engine with support for various data types.
- [Elasticsearch](https://github.com/elastic/elasticsearch) - Distributed search and analytics engine built on Apache Lucene, designed for horizontal scalability and real-time search capabilities.

## Web Servers & Proxies

- [Apache HTTP Server](https://github.com/apache/httpd) - Robust, commercial-grade web server that powers a significant portion of the internet with extensive module support and proven reliability.
- [Envoy](https://github.com/envoyproxy/envoy) - High-performance edge and service proxy designed for cloud-native applications with advanced load balancing and observability features.

## Web Application Firewalls

- [Coraza](https://github.com/corazawaf/coraza) - Enterprise-grade web application firewall that provides protection against OWASP Top 10 and other web-based attacks.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) - Open-source web application firewall engine that provides real-time monitoring, logging, and access control.

## Container & Orchestration

- [Kubernetes](https://github.com/kubernetes/kubernetes) - Production-grade container orchestration system for automating deployment, scaling, and management of containerized applications.
- [containerd](https://github.com/containerd/containerd) - Industry-standard container runtime that manages the complete container lifecycle from image transfer to execution and supervision.
- [Docker Buildx](https://github.com/docker/buildx) - Docker CLI plugin that extends build capabilities with support for multi-platform builds, build caching, and advanced build features.
- [Harbor](https://github.com/goharbor/harbor) - Cloud-native container registry that stores, signs, and scans container images for vulnerabilities with role-based access control.
- [Helm](https://github.com/helm/helm) - Package manager for Kubernetes that simplifies deployment and management of applications through templated charts and version control.
- [Istio](https://github.com/istio/istio) - Service mesh that provides traffic management, security, and observability for microservices without requiring code changes.

## Infrastructure as Code

- [Terraform](https://github.com/hashicorp/terraform) - Infrastructure provisioning tool that enables declarative configuration of cloud and on-premises resources across multiple providers.

## CI/CD & GitOps

- [Argo CD](https://github.com/argoproj/argo-cd) - Declarative GitOps continuous delivery tool for Kubernetes that automatically syncs application state from Git repositories.

## Observability & Monitoring

- [Prometheus](https://github.com/prometheus/prometheus) - Time-series database and monitoring system that collects metrics from configured targets at given intervals and evaluates rule expressions.
- [Grafana](https://github.com/grafana/grafana) - Multi-platform analytics and interactive visualization web application that provides charts, graphs, and alerts for supported data sources.
- [Fluentd](https://github.com/fluent/fluentd) - Unified logging layer that collects, transforms, and ships log data from multiple sources to various destinations with a plugin-based architecture.

## Security - Runtime & Policy Enforcement

- [Kyverno](https://github.com/kyverno/kyverno) - Kubernetes-native policy engine that validates, mutates, and generates configurations using admission controls and background scans.
- [Falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security tool that detects unexpected application behavior and alerts on threats at runtime.
- [ClamAV](https://github.com/Cisco-Talos/clamav) - Open-source antivirus engine for detecting trojans, viruses, malware, and other malicious threats.

## Security - Secrets & Certificates

- [Vault](https://github.com/hashicorp/vault) - Tool for securely accessing secrets, providing encryption services, and managing sensitive data with dynamic secrets and fine-grained access controls.
- [cert-manager](https://github.com/cert-manager/cert-manager) - Kubernetes add-on that automates the management and issuance of TLS certificates from various sources including Let's Encrypt.
- [Certbot](https://github.com/certbot/certbot) - EFF's tool for automatically obtaining and renewing Let's Encrypt SSL/TLS certificates with support for various web servers.
- [External Secrets Operator](https://github.com/external-secrets/external-secrets) - Kubernetes operator that synchronizes secrets from external secret management systems (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault) into Kubernetes Secret objects with automatic refresh capabilities.

## Security - Code Analysis

- [Opengrep](https://github.com/opengrep/opengrep) - Fast code scanning tool that finds bugs and enforces code standards using semantic pattern matching across multiple programming languages.
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning tool that detects and prevents hardcoded secrets, API keys, and credentials from being committed to Git repositories.

## Security - Vulnerability & Supply Chain

- [Trivy](https://github.com/aquasecurity/trivy) - Comprehensive security scanner that detects vulnerabilities in container images, file systems, Git repositories, and Kubernetes clusters.
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) - Kubernetes-native security toolkit that continuously scans workloads for vulnerabilities, misconfigurations, and compliance issues using Trivy.
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner that identifies known security issues in container images and file systems by matching against multiple vulnerability databases.
- [Syft](https://github.com/anchore/syft) - Software Bill of Materials (SBOM) generator that catalogs packages and dependencies from container images and file systems.
- [Cosign](https://github.com/sigstore/cosign) - Container signing and verification tool that ensures software supply chain security through cryptographic signatures and transparency logs.
- [Copacetic](https://github.com/project-copacetic/copacetic) - Tool for patching container image vulnerabilities without rebuilding, enabling faster security remediation in production environments.
- [Dependabot](https://github.com/dependabot/dependabot-core) - Automated dependency update tool that checks for outdated dependencies and creates pull requests to keep projects secure and up-to-date.
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator) - Official SLSA Level 3 provenance generator for GitHub Actions that creates non-falsifiable build attestations for supply chain security.

## Backup & Disaster Recovery

- [Velero](https://github.com/vmware-tanzu/velero) - Kubernetes backup and restore tool that provides disaster recovery capabilities for cluster resources and persistent volumes with support for scheduled backups and migration across clusters.
