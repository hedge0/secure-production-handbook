# Kubernetes Security Architecture Guide

A cloud-agnostic guide for building production-ready Kubernetes clusters with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world production implementations.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Network Architecture & Database Layer](#network-architecture--database-layer)
4. [Cluster Architecture & Separation](#cluster-architecture--separation)
5. [Ingress & Traffic Management](#ingress--traffic-management)
6. [Runtime Security & Policy Enforcement](#runtime-security--policy-enforcement)
7. [Secrets Management](#secrets-management)
8. [Infrastructure as Code & GitOps](#infrastructure-as-code--gitops)
9. [Observability & Logging](#observability--logging)
10. [Disaster Recovery](#disaster-recovery)
11. [References](#references)

## Overview

This guide outlines a production-grade Kubernetes architecture that prioritizes security, reliability, and operational excellence. The patterns are cloud-agnostic and work with managed Kubernetes services (AWS EKS, GCP GKE, Azure AKS) and their respective cloud-native services for networking, databases, secrets management, and observability.

**Core Principles:**

- **Defense in Depth**: Multiple security layers from network to runtime
- **Least Privilege**: Minimize blast radius through network isolation and access controls
- **High Availability**: Multi-AZ databases, automatic failover, point-in-time recovery
- **Infrastructure as Code**: Versioned, reproducible infrastructure with Terraform and ArgoCD
- **Separation of Concerns**: Isolated clusters for production workloads vs administrative tooling

## Prerequisites

### Required Tools

**Infrastructure as Code:**

- [Terraform](https://www.terraform.io/) - Infrastructure provisioning and management
- [Helm](https://helm.sh/) - Kubernetes package manager
- [ArgoCD](https://argo-cd.readthedocs.io/) - GitOps continuous delivery for Kubernetes

**Security & Policy:**

- [Kyverno](https://github.com/kyverno/kyverno) - Kubernetes-native policy engine
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) - Continuous vulnerability scanning
- [Istio](https://github.com/istio/istio) - Service mesh for mTLS and traffic management
- [Falco](https://github.com/falcosecurity/falco) - Runtime threat detection

**Observability:**

- [Prometheus](https://prometheus.io/) - Metrics collection and monitoring
- [Grafana](https://grafana.com/) - Visualization and dashboards
- [Fluentd](https://github.com/fluent/fluentd) - Log collection and forwarding

### External Services

**Managed Kubernetes** (strongly recommended):

- AWS Elastic Kubernetes Service (EKS)
- Google Kubernetes Engine (GKE)
- Azure Kubernetes Service (AKS)

**Managed Databases** (required for production):

- AWS RDS (PostgreSQL, MySQL, Aurora)
- GCP Cloud SQL
- Azure Database for PostgreSQL/MySQL

**Secrets Management** (required):

- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault
- HashiCorp Vault

**Logging & SIEM** (required):

- AWS CloudWatch Logs
- GCP Cloud Logging
- Azure Monitor
- Splunk
- Self-hosted (ELK Stack, Loki)

**Load Balancing & WAF**:

- AWS ALB + AWS WAF
- GCP Cloud Load Balancing + Cloud Armor
- Azure Application Gateway + Azure WAF

## Network Architecture & Database Layer

Design secure network topology with proper isolation and managed databases for production resilience.

### Network Design

**Private Subnets** (Recommended):

- Kubernetes worker nodes in private subnets (no direct internet access)
- Egress via NAT Gateway (monthly cost per AZ + data transfer fees)
- Load balancers in public subnets
- Multi-AZ NAT Gateway setup multiplies cost (3 AZs = 3x fees)
- Prevents direct exposure of cluster nodes

**Public Subnets** (Budget Alternative):

- Worker nodes in public subnets with strict security groups
- Allow only: ALB traffic, specific admin IPs/VPN
- Block all other inbound traffic
- No NAT Gateway cost
- **Risk**: Worker nodes have public IPs, requires careful security group configuration

**Recommendation**: Use private subnets with NAT Gateway for production - cost is negligible vs security benefit.

**Multi-AZ Design**:

- Distribute worker nodes across 3 AZs minimum
- Managed Kubernetes control plane automatically multi-AZ
- ALB/NLB automatically span AZs

**Admin Access**:

- VPN (AWS Client VPN, GCP Cloud VPN, Azure VPN Gateway) - recommended
- Bastion host alternative (hardened VM, restricted IPs)
- Admin ALB restricted to VPN range or bastion IP only
- Never expose Kubernetes API or admin tools to 0.0.0.0/0

### Database Layer

**Use Managed Databases** (Required):

Never run databases in Kubernetes for production. Use AWS RDS, GCP Cloud SQL, or Azure Database.

**Configuration**:

- Deploy in private subnets
- Security group allows only Kubernetes worker nodes
- Multi-AZ enabled (automatic failover in 60-120 seconds)
- Automated daily snapshots with 7-30 day retention
- Point-in-time recovery enabled

**Connection from Kubernetes**:

- Store credentials in external secrets manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- Load into Kubernetes via cloud-native integrations:
  - AWS EKS: Secrets Store CSI Driver with AWS Secrets Manager
  - GKE: Workload Identity with Secret Manager
  - AKS: Azure Key Vault Provider for Secrets Store CSI Driver
- Pods retrieve from Kubernetes secrets as environment variables
- Cloud-native solutions are simpler and more secure than third-party operators

## Cluster Architecture & Separation

Isolate production workloads from administrative tooling using separate Kubernetes clusters.

### Two-Cluster Design (Recommended)

**Production Cluster**:

- Customer-facing applications and services
- Istio for mTLS, Kyverno for policy enforcement
- Falco for runtime monitoring, Trivy Operator for vulnerability scanning
- Exposed via customer-facing ALB with WAF

**Admin Cluster**:

- ArgoCD for GitOps deployments to production cluster
- Prometheus for metrics collection, Grafana for dashboards
- Admin ALB restricted to VPN range or bastion IP only
- No public internet access

**Why separate clusters**:

- Production compromise doesn't affect deployment capability or observability
- Production pods cannot access ArgoCD to modify infrastructure
- Clear separation of duties for compliance (SOC2, ISO 27001)
- Limits blast radius - attackers in production can't pivot to admin tools

### Single Cluster Alternative

Use Kubernetes namespaces with strict NetworkPolicies if cost is primary constraint.

**Mitigations required**:

- Isolate admin namespace with NetworkPolicies
- Kyverno policies to prevent production pods from accessing admin resources
- Admin ingress still restricted to VPN/bastion only
- Only recommended for non-critical applications or small teams

**Recommendation**: Use separate clusters for production - minimal overhead with managed Kubernetes, significant security benefit.

## Ingress & Traffic Management

Configure load balancers, WAF, and service mesh to secure and route traffic to appropriate services.

### Load Balancer Architecture

**Customer-Facing ALB**:

- Public-facing load balancer for customer APIs and web services
- TLS termination with managed certificates (ACM, GCP Managed Certificates, Azure Key Vault)
- Routes to Istio ingress gateway in production cluster
- WAF enabled (AWS WAF, GCP Cloud Armor, Azure WAF)

**Admin ALB**:

- Separate load balancer for admin tools (ArgoCD, Grafana)
- Security group restricted to VPN IP range or bastion IP only
- Routes to admin cluster services
- Never accessible from public internet (0.0.0.0/0)

### WAF Configuration

Deploy Web Application Firewall at load balancer to filter malicious traffic:

- Protect against OWASP Top 10 (SQL injection, XSS, etc.)
- Rate limiting for DDoS mitigation
- Block known malicious IPs and bot traffic

### Istio Service Mesh

**Mutual TLS (mTLS)**:

- Automatic mTLS encryption between all pods
- Prevents man-in-the-middle attacks on internal traffic
- Zero application code changes required
- Istio manages certificates automatically (24-hour rotation)

**Traffic Routing**:

- Istio VirtualServices define which services are externally accessible
- Customer-facing APIs route from ALB through Istio ingress gateway
- Internal services (admin APIs, background jobs) remain cluster-internal only
- Services without VirtualService configuration cannot be reached from internet

**Network Policies**:

- Kubernetes NetworkPolicies restrict pod-to-pod communication
- Only allow necessary connections (API → Database, API → Cache)
- Deny all other traffic by default

## Runtime Security & Policy Enforcement

Enforce security policies and monitor runtime behavior to prevent and detect threats.

### Kyverno Policy Engine

Deploy Kyverno for Kubernetes-native policy enforcement at admission time.

**Image Signature Verification**:

- Require all container images signed with Cosign
- Verify signatures against trusted public key before pod creation
- Reject unsigned or invalidly signed images
- Ensures only images from your build pipeline run in cluster

**Container Security Standards**:

- Enforce non-root containers (block UID 0)
- Require read-only root filesystem where possible
- Block privileged containers and dangerous capabilities
- Enforce resource limits (CPU, memory) on all pods
- Require distroless or minimal base images (no package managers)

**Additional Policies**:

- Block hostNetwork, hostPID, hostIPC usage
- Require pod security labels
- Enforce image registry allowlist (only approved registries)
- Validate required security contexts

### Falco Runtime Monitoring

Deploy Falco for real-time threat detection of suspicious container behavior.

**What Falco Detects**:

- Unexpected process execution in containers
- File system modifications in read-only paths
- Network connections to unexpected destinations
- Privilege escalation attempts
- Shell spawned in container (potential compromise)
- Sensitive file access (/etc/shadow, SSH keys, credentials)

**Alert Configuration**:

- Send alerts to external SIEM via Fluentd
- Integrate with Slack/PagerDuty for critical alerts
- Log all events for forensic analysis
- Configure severity levels (info, warning, critical)

### Trivy Operator Vulnerability Scanning

Deploy Trivy Operator for continuous vulnerability scanning of running workloads.

**Scanning Strategy**:

- Daily automated scans of all container images in cluster
- Scan on new pod deployment
- Generate vulnerability reports as Kubernetes custom resources
- Alert on HIGH and CRITICAL vulnerabilities with available fixes

**Reporting**:

- Export scan results to Prometheus for metrics
- Visualize in Grafana dashboards
- Store reports in object storage (S3/GCS/Azure Blob)
- Track vulnerability remediation over time

**Automated Response**:

- Trigger alerts when new CVEs discovered in running images
- Optionally trigger automated image rebuilds via ArgoCD/CI pipeline
- Update deployments with patched images

## Secrets Management

Store and inject secrets securely using cloud-native integrations. Never store secrets in ConfigMaps, environment variables in code, or Git repositories.

### External Secrets Storage

**Use cloud-native secrets managers**:

- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault
- HashiCorp Vault

**Store in secrets manager**:

- Database credentials (username, password, connection strings)
- API keys and tokens for external services
- TLS certificates and private keys
- OAuth client secrets and encryption keys

### Secrets Injection into Pods

Load secrets at runtime using cloud-native Kubernetes integrations:

**AWS EKS**:

- Secrets Store CSI Driver with AWS Secrets Manager
- IAM roles for service accounts (IRSA) for authentication
- Secrets mounted as volumes or environment variables

**GCP GKE**:

- Workload Identity with Secret Manager
- No service account keys required
- Pods access secrets via GCP SDK

**Azure AKS**:

- Azure Key Vault Provider for Secrets Store CSI Driver
- Managed identities for pod authentication
- Secrets mounted as volumes

### Secret Rotation

**Modern best practices** (NIST, CNCF): Routine rotation no longer recommended - focus on preventing exposure.

**Rotate only when**:

- Secrets confirmed or suspected compromised
- Employee with access leaves organization
- Compliance requirements mandate rotation

**Better security approach**:

- Use short-lived credentials (IAM roles, workload identity)
- Implement proper access controls and audit logging
- Monitor for unauthorized access attempts

## Infrastructure as Code & GitOps

Manage infrastructure and applications as versioned code for reproducibility and automation.

### Terraform for Infrastructure

Use Terraform to provision and manage all cloud infrastructure as code.

**What Terraform manages**:

- VPC, subnets, security groups, route tables
- Kubernetes clusters (EKS, GKE, AKS)
- Load balancers (ALB, NLB)
- Databases (RDS, Cloud SQL, Azure Database)
- IAM roles, service accounts, policies
- Secrets managers, logging infrastructure

**Version Control & State**:

- Store Terraform code in Git repository
- Use semantic versioning for infrastructure releases
- Require pull request reviews for infrastructure changes
- Store Terraform state in remote backend (S3, GCS, Azure Blob)
- Enable state locking to prevent concurrent modifications
- Encrypt state at rest and maintain regular backups

### ArgoCD for GitOps

Deploy ArgoCD in admin cluster to manage application deployments to production cluster.

**GitOps Workflow**:

- Application manifests (Kubernetes YAML, Helm charts) stored in Git
- ArgoCD monitors Git repository for changes
- Automatically syncs changes to production cluster
- Git is single source of truth for cluster state

**Benefits**:

- Declarative infrastructure - desired state defined in Git
- Complete audit trail - all changes tracked in Git history
- Easy rollback - revert Git commit to roll back deployment
- Automated deployment - no manual kubectl commands

**Security**:

- ArgoCD runs in separate admin cluster (isolated from production)
- RBAC controls which teams can deploy to which namespaces
- Require signed Git commits for production deployments
- Admin access restricted to VPN/bastion

## Observability & Logging

Collect, aggregate, and export logs and metrics for monitoring, debugging, and compliance.

### Fluentd Log Aggregation

Deploy Fluentd as DaemonSet to collect and export logs from all cluster components.

**Log Sources**:

- Container logs (stdout/stderr from all pods)
- Kubernetes audit logs (API server events)
- Node system logs
- Application logs

**Export Destinations**:

- External SIEM: Splunk, ELK Stack
- Cloud logging: AWS CloudWatch Logs, GCP Cloud Logging, Azure Monitor
- Long-term storage: S3, GCS, Azure Blob for compliance

**Structured Logging**:

- Use JSON format for application logs
- Include correlation IDs, user IDs, timestamps
- Enables easy parsing and filtering in SIEM

### Prometheus & Grafana

Deploy in admin cluster for metrics collection and visualization.

**Prometheus** collects metrics from production cluster:

- Pod resource usage (CPU, memory, network)
- HTTP request rates, latency, error rates
- Database connection pool usage
- Infrastructure health (node status, disk usage)

**Grafana** provides dashboards and alerting:

- Visualize Prometheus metrics
- Alert on threshold violations (high CPU, pod crashes, error rate spikes)
- Track security metrics (Kyverno violations, Falco alerts, Trivy vulnerabilities)
- Accessible only via admin ALB (VPN/bastion restricted)

### Log Retention & Compliance

**Hot Storage** (30 days):

- AWS CloudWatch Logs, GCP Cloud Logging, Azure Monitor
- Fast access for debugging and incident response
- Real-time searching and alerting

**Cold Storage** (Multi-Year for Compliance):

- S3 Glacier, GCS Coldline/Archive, Azure Archive
- Compressed logs for regulatory compliance
- Retention: SOC2 (1-7 years), ISO 27001 (1-3 years), HIPAA (6 years), GDPR (1-3 years)

**Archive Process**:

1. Export from hot storage after 30 days
2. Compress (gzip, zstd)
3. Upload to cold storage with lifecycle policies
4. Delete from hot storage

## Disaster Recovery

Complete environment recovery through infrastructure as code, database backups, and GitOps.

### Recovery Strategy

All critical components can be recreated from code and backups:

**Infrastructure** (Terraform):

- Terraform state stored in remote backend (S3, GCS, Azure Blob)
- Run `terraform apply` to recreate VPC, clusters, load balancers, databases in new region
- Infrastructure recreated from code in 30-60 minutes

**Databases** (Managed Services):

- Restore from automated snapshots or point-in-time recovery
- Manual snapshots before major changes (schema migrations, deployments)
- Cross-region snapshots for regional disaster recovery
- Update Kubernetes secrets with new database endpoint after restore
- Database recovery: 15-30 minutes

**Applications** (ArgoCD):

- Point ArgoCD at Git repository
- ArgoCD automatically deploys all applications to new cluster
- Cluster state matches Git repository in 10-20 minutes

### Recovery Procedure

Complete disaster recovery steps:

1. Provision infrastructure with Terraform (30-60 minutes)
2. Restore databases from snapshots to new instances (15-30 minutes)
3. Deploy ArgoCD to new admin cluster (5 minutes)
4. ArgoCD syncs all applications to new production cluster (10-20 minutes)
5. Update DNS to point to new load balancers (5 minutes + TTL propagation)

**Total RTO**: 60-120 minutes  
**RPO**: 5 minutes (database point-in-time recovery)

### Testing & Validation

**Disaster recovery drills**:

- Perform quarterly in non-production environment
- Test infrastructure recreation with Terraform
- Validate database restore procedures
- Verify ArgoCD can sync complete application state
- Document lessons learned and update procedures

**Key principle**: Infrastructure as code + GitOps + automated database backups = rapid, reproducible disaster recovery.

## References

### Infrastructure & Orchestration

- [Terraform](https://www.terraform.io/) - Infrastructure as code
- [Helm](https://helm.sh/) - Kubernetes package manager
- [ArgoCD](https://argo-cd.readthedocs.io/) - GitOps continuous delivery

### Security & Policy

- [Kyverno](https://github.com/kyverno/kyverno) - Kubernetes-native policy engine
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) - Continuous vulnerability scanning
- [Istio](https://github.com/istio/istio) - Service mesh for mTLS and traffic management
- [Falco](https://github.com/falcosecurity/falco) - Runtime threat detection
- [Cosign](https://github.com/sigstore/cosign) - Container signing and verification

### Observability

- [Prometheus](https://prometheus.io/) - Metrics collection and monitoring
- [Grafana](https://grafana.com/) - Visualization and dashboards
- [Fluentd](https://github.com/fluent/fluentd) - Log collection and forwarding

### Managed Kubernetes Services

- [AWS EKS](https://aws.amazon.com/eks/) - Amazon Elastic Kubernetes Service
- [GCP GKE](https://cloud.google.com/kubernetes-engine) - Google Kubernetes Engine
- [Azure AKS](https://azure.microsoft.com/en-us/services/kubernetes-service/) - Azure Kubernetes Service

### Standards & Documentation

- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
