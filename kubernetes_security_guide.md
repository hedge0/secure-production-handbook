# Kubernetes Security Architecture Guide

**Last Updated:** January 21, 2026

A cloud-agnostic guide for building production-ready Kubernetes clusters with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world production implementations.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Network Architecture & Database Layer](#network-architecture--database-layer)
   - [Network Design](#network-design)
   - [Database Layer](#database-layer)
4. [Cluster Architecture & Separation](#cluster-architecture--separation)
   - [Two-Cluster Design (Recommended)](#two-cluster-design-recommended)
   - [Single Cluster Alternative](#single-cluster-alternative)
   - [Network Policy Implementation](#network-policy-implementation)
5. [Ingress & Traffic Management](#ingress--traffic-management)
   - [Load Balancer Architecture](#load-balancer-architecture)
   - [WAF Configuration](#waf-configuration)
   - [Istio Service Mesh](#istio-service-mesh)
6. [Policy Enforcement with Kyverno](#policy-enforcement-with-kyverno)
   - [Kyverno Policy Engine](#kyverno-policy-engine)
7. [Continuous Vulnerability & Threat Detection](#continuous-vulnerability--threat-detection)
   - [Trivy Operator for Vulnerability Scanning](#trivy-operator-for-vulnerability-scanning)
   - [Falco Runtime Security](#falco-runtime-security)
8. [Secrets Management](#secrets-management)
   - [External Secrets Management](#external-secrets-management)
   - [AWS EKS Integration](#aws-eks-integration)
   - [GCP GKE Integration](#gcp-gke-integration)
   - [Azure AKS Integration](#azure-aks-integration)
   - [Secret Rotation](#secret-rotation)
9. [Infrastructure as Code & GitOps](#infrastructure-as-code--gitops)
   - [Terraform for Infrastructure](#terraform-for-infrastructure)
   - [ArgoCD for GitOps](#argocd-for-gitops)
10. [Observability & Logging](#observability--logging)
    - [Fluentd Log Aggregation](#fluentd-log-aggregation)
    - [Prometheus & Grafana](#prometheus--grafana)
    - [Log Retention & Compliance](#log-retention--compliance)
11. [Identity & Access Management](#identity--access-management)
    - [Kubernetes RBAC (Role-Based Access Control)](#kubernetes-rbac-role-based-access-control)
    - [Workload Identity & Cloud IAM Integration](#workload-identity--cloud-iam-integration)
    - [Cloud IAM Policy Best Practices](#cloud-iam-policy-best-practices)
    - [Access Control Verification](#access-control-verification)
12. [Disaster Recovery](#disaster-recovery)
    - [Recovery Strategy](#recovery-strategy)
    - [Recovery Procedure](#recovery-procedure)
    - [Testing & Validation](#testing--validation)
13. [Incident Response](#incident-response)
    - [Detection & Initial Response](#detection--initial-response)
    - [Containment & Recovery](#containment--recovery)
    - [Post-Incident](#post-incident)
14. [Attack Scenarios Prevented](#attack-scenarios-prevented)
    - [Container & Pod Security](#container--pod-security)
    - [Network & Lateral Movement](#network--lateral-movement)
    - [Supply Chain & Image Security](#supply-chain--image-security)
    - [Secrets & Configuration](#secrets--configuration)
15. [References](#references)
    - [Infrastructure & Orchestration](#infrastructure--orchestration)
    - [Security & Policy](#security--policy)
    - [Observability](#observability)
    - [Managed Kubernetes Services](#managed-kubernetes-services)
    - [Standards & Documentation](#standards--documentation)

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
- Create application database user with least privilege (never use root/admin user for application connections)
- Grant only required permissions (SELECT, INSERT, UPDATE, DELETE on specific tables)

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

### Network Policy Implementation

Without NetworkPolicies, namespace isolation is convention only. Apply these two policies to enforce separation:

**Default deny all ingress (apply to each namespace):**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

**Allow traffic from Istio gateway to your apps:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-gateway
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: istio-system
      ports:
        - protocol: TCP
          port: 8080
```

Apply default-deny first, then explicitly allow required traffic. Test with: `kubectl exec -it pod-name -- curl http://service.namespace.svc.cluster.local`

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
- Zero configuration required after Istio installation
- Automatic certificate rotation

**Traffic Management**:

- Intelligent routing based on headers, weights, or conditions
- Canary deployments: Route 5% of traffic to new version
- A/B testing: Route specific users to experimental features
- Circuit breaking: Fail fast when backend services are unhealthy

**Observability**:

- Distributed tracing with Jaeger or Zipkin
- Service-to-service metrics (latency, error rates)
- Visualize traffic flow with Kiali dashboard

## Policy Enforcement with Kyverno

Enforce security policies at deployment time to prevent misconfigurations and ensure compliance.

### Kyverno Policy Engine

Deploy [Kyverno](https://github.com/kyverno/kyverno) for Kubernetes-native policy enforcement without learning a new language.

**Essential Policies**:

**Require resource limits** (prevent resource exhaustion):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: enforce
  rules:
    - name: check-resources
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "CPU and memory limits required"
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

**Block privileged containers**:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: enforce
  rules:
    - name: check-privileged
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "Privileged mode is not allowed"
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: false
```

**Require non-root containers**:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
spec:
  validationFailureAction: enforce
  rules:
    - name: check-runAsNonRoot
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "Containers must run as non-root user"
        pattern:
          spec:
            securityContext:
              runAsNonRoot: true
```

**Verify image signatures** (requires [Cosign](https://github.com/sigstore/cosign)):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: enforce
  rules:
    - name: check-signature
      match:
        resources:
          kinds:
            - Pod
      verifyImages:
        - imageReferences:
            - "*"
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...your public key...
                      -----END PUBLIC KEY-----
```

**Additional Security Policies**:

- Block hostNetwork, hostPID, hostIPC usage
- Require pod security labels
- Enforce image registry allowlist (only approved registries)
- Validate required security contexts
- Require read-only root filesystem where possible
- Block dangerous capabilities
- Enforce distroless or minimal base images (no package managers)

**Deployment workflow**: Kyverno runs as admission controller, validates policies before pods are created, blocks non-compliant workloads automatically.

## Continuous Vulnerability & Threat Detection

Monitor running workloads for vulnerabilities and detect runtime threats in real-time.

### Trivy Operator for Vulnerability Scanning

Deploy [Trivy Operator](https://github.com/aquasecurity/trivy-operator) for continuous security scanning in Kubernetes.

**What it scans**:

- Container images for OS and application vulnerabilities
- Kubernetes configuration for security misconfigurations
- Infrastructure as Code (IaC) files for compliance issues
- SBOM generation for all running images

**How it works**:

- Runs as Kubernetes operator (continuously scans cluster)
- Scans new images automatically when pods are deployed
- Stores results as Kubernetes custom resources (VulnerabilityReports, ConfigAuditReports)
- Integrates with Prometheus for alerting on critical vulnerabilities

**Scanning Strategy**:

- Daily automated scans of all container images in cluster
- Scan on new pod deployment
- Generate vulnerability reports as Kubernetes custom resources
- Alert on HIGH and CRITICAL vulnerabilities with available fixes

**Reporting & Integration**:

- Export vulnerability reports to Fluentd
- Export scan results to Prometheus for metrics
- Forward to external SIEM (Splunk, ELK Stack, cloud logging)
- Visualize in Grafana dashboards
- Store reports in object storage (S3/GCS/Azure Blob)
- Track vulnerability remediation over time

**Automated Response**:

- Trigger alerts when new CVEs discovered in running images
- Optionally trigger automated image rebuilds via ArgoCD/CI pipeline
- Update deployments with patched images

### Falco Runtime Security

Deploy [Falco](https://github.com/falcosecurity/falco) for real-time threat detection in containers.

**What Falco detects**:

- Shell spawned in container (potential breakout attempt)
- Unexpected process execution in containers
- Sensitive file access (/etc/shadow, SSH keys, credentials)
- File system modifications in read-only paths
- Unexpected network connections
- Network connections to unexpected destinations
- Privilege escalation attempts
- Container processes accessing host filesystem
- Suspicious system calls

**Deployment**:

- Deploy as DaemonSet (runs on every node)
- Uses eBPF or kernel module to intercept system calls
- Zero performance impact on applications
- Rules are customizable for your environment

**Alert Configuration**:

- Forward alerts to Fluentd, then to SIEM
- Send alerts to external SIEM via Fluentd
- Integrate with Slack/PagerDuty for real-time notifications
- Log all events for forensic analysis
- Configure severity levels (info, warning, critical)
- Alert on critical events only (reduce noise)

## Secrets Management

Store secrets in external vault services and inject them into Kubernetes pods securely with modern lifecycle management practices.

### External Secrets Management

**Never store secrets in**:

- Kubernetes Secrets (base64 encoded, not encrypted at rest by default)
- ConfigMaps
- Environment variables in Dockerfiles
- Git repositories

**Always store secrets in**:

- AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
- HashiCorp Vault
- External secrets management with encryption, access control, audit logging

### AWS EKS Integration

- Secrets Store CSI Driver with AWS Secrets Manager provider
- IAM Roles for Service Accounts (IRSA) for authentication
- Secrets mounted as volumes (not environment variables for sensitive data)

### GCP GKE Integration

- Workload Identity for pod authentication to Secret Manager
- GCP Secret Manager CSI Driver
- Secrets mounted as volumes

### Azure AKS Integration

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

## Identity & Access Management

Implement least-privilege access control through Kubernetes RBAC and cloud provider IAM integration to minimize blast radius of compromised credentials.

### Kubernetes RBAC

**ServiceAccount Configuration**:

- Create dedicated ServiceAccount per application (not `default`)
- Set `automountServiceAccountToken: false` unless pod needs Kubernetes API access
- Use namespace-scoped Roles (not ClusterRoles) for applications
- Grant minimal permissions: `get` only, avoid `list`, `watch`, `*` verbs

**RBAC Example**:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-server-sa
  namespace: production
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-server-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-server-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: api-server-sa
roleRef:
  kind: Role
  name: api-server-role
  apiGroup: rbac.authorization.k8s.io
```

**Pod Security Context**:

```yaml
spec:
  serviceAccountName: api-server-sa
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
```

### Workload Identity

Allow pods to assume cloud IAM roles without storing credentials.

**AWS EKS - IRSA (IAM Roles for Service Accounts)**:

```bash
# Enable OIDC provider
eksctl utils associate-iam-oidc-provider --cluster=production-cluster --approve

# Create IAM role with trust policy for ServiceAccount
# Attach least-privilege IAM policy (specific resources only)

# Annotate ServiceAccount
kubectl annotate serviceaccount api-server-sa \
  -n production \
  eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT_ID:role/api-server-role
```

**GCP GKE - Workload Identity**:

```bash
# Enable Workload Identity on cluster
gcloud container clusters update production-cluster \
  --workload-pool=PROJECT_ID.svc.id.goog

# Create GCP service account
gcloud iam service-accounts create api-server-sa

# Grant permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:api-server-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Bind K8s SA to GCP SA
gcloud iam service-accounts add-iam-policy-binding \
  api-server-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:PROJECT_ID.svc.id.goog[production/api-server-sa]"

# Annotate ServiceAccount
kubectl annotate serviceaccount api-server-sa \
  -n production \
  iam.gke.io/gcp-service-account=api-server-sa@PROJECT_ID.iam.gserviceaccount.com
```

**Azure AKS - Workload Identity**:

```bash
# Enable Workload Identity
az aks update \
  --resource-group production-rg \
  --name production-cluster \
  --enable-workload-identity

# Create managed identity
az identity create --name api-server-identity --resource-group production-rg

# Grant permissions
az role assignment create \
  --assignee CLIENT_ID \
  --role "Key Vault Secrets User" \
  --scope /subscriptions/SUB_ID/resourceGroups/production-rg/providers/Microsoft.KeyVault/vaults/prod-keyvault

# Create federated credential
az identity federated-credential create \
  --name api-server-federated \
  --identity-name api-server-identity \
  --resource-group production-rg \
  --issuer OIDC_ISSUER_URL \
  --subject system:serviceaccount:production:api-server-sa

# Annotate ServiceAccount
kubectl annotate serviceaccount api-server-sa \
  -n production \
  azure.workload.identity/client-id=CLIENT_ID
```

### IAM Policy Best Practices

**Least Privilege**:

- Grant only required actions (avoid `*` wildcards)
- Restrict to specific resources (exact ARNs, paths, buckets)
- One IAM role per application (never share)
- Separate roles for dev/staging/production

**Example AWS Policy**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:region:account:secret:prod/api/*"
    }
  ]
}
```

**Verification**:

```bash
# Test RBAC permissions
kubectl auth can-i get secrets \
  --as=system:serviceaccount:production:api-server-sa -n production

# Audit IAM usage
# AWS: CloudTrail logs for AssumeRoleWithWebIdentity
# GCP: Cloud Audit Logs for service account usage
# Azure: Activity logs for managed identity auth
```

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

## Incident Response

Respond to security incidents in Kubernetes with structured processes for containment and recovery.

### Detection & Initial Response

**Automated Detection**:

- **Falco**: Runtime threats (shell spawns, privilege escalation, suspicious syscalls)
- **Prometheus**: Resource anomalies (CPU spikes, pod crashes, restart loops)
- **Trivy Operator**: New critical vulnerabilities in running workloads
- **Kyverno**: Policy violations

**Immediate Actions for Pod Compromise**:

1. **Isolate**: Apply NetworkPolicy to block all traffic to/from compromised pod
2. **Preserve**: `kubectl logs pod-name > logs.txt` and `kubectl describe pod pod-name > details.txt`
3. **Terminate**: Delete pod (deployment recreates clean instance)
4. **Investigate**: Analyze logs and Falco alerts for attack vector

### Containment & Recovery

**Emergency Network Isolation**:

Apply default-deny NetworkPolicy to prevent lateral movement:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-lockdown
  namespace: compromised-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  # No rules = blocks all traffic
```

**Recovery Steps**:

- Delete compromised pods (clean instances auto-recreate)
- Rotate secrets in external vault (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- Update container images if CVE was exploited
- Deploy patches via ArgoCD (commit to Git, auto-sync)

### Post-Incident

**Investigation**:

- Collect Falco alerts, pod logs, Kubernetes audit logs, Istio service mesh logs
- Review ArgoCD deployment history and Git commits
- Analyze Trivy vulnerability reports for exploited CVEs

**Documentation & Improvements**:

- Document timeline, attack vector, and remediation actions
- Add Kyverno policies to prevent similar attacks
- Update Falco rules to detect similar behaviors earlier
- Notify per compliance requirements (GDPR: 72 hours, HIPAA: 60 days)

## Attack Scenarios Prevented

This guide's security controls prevent real-world Kubernetes attacks commonly seen in production environments.

### Container & Pod Security

**Container Escape / Privilege Escalation**

- Attack: Exploiting privileged containers or dangerous capabilities to break out and access host
- Mitigated by: Kyverno blocking privileged containers/capabilities, non-root enforcement, read-only root filesystem, Falco runtime detection

**Malicious Runtime Behavior**

- Attack: Unexpected processes spawning (crypto miners, reverse shells, data exfiltration tools)
- Mitigated by: Hardened images with package managers removed (no apt/yum/apk), non-root user enforcement, Falco detecting shell spawns/suspicious syscalls/file access, network connection monitoring, automatic NetworkPolicy isolation

**Resource Exhaustion / DoS**

- Attack: Malicious/buggy pods consuming all cluster resources causing outages
- Mitigated by: Kyverno requiring CPU/memory limits, ResourceQuotas per namespace, pod disruption budgets, cluster autoscaling

### Network & Lateral Movement

**Lateral Movement via Network Access**

- Attack: Compromised pod used as pivot to attack other pods/services
- Mitigated by: Default-deny NetworkPolicies, Istio mTLS between pods, namespace isolation with explicit allow rules, micro-segmentation

**Database Compromise via Pod Access**

- Attack: Compromised pod used to access and exfiltrate production databases
- Mitigated by: Databases in private subnets with security groups (worker nodes only), credentials in external vaults, application database user with least privilege (non-root), limited permissions on specific tables only, multi-AZ with backups, NetworkPolicies limiting database access

**Control Plane / API Server Attack**

- Attack: Unauthorized access to Kubernetes API to modify cluster or steal secrets
- Mitigated by: Managed Kubernetes hardened control plane, API access restricted to VPN/bastion, RBAC with least privilege, audit logging

### Supply Chain & Image Security

**Supply Chain Attack via Unsigned Images**

- Attack: Malicious container images pushed to registry and deployed to production
- Mitigated by: Registry authentication required for push/pull, Kyverno image signature verification (Cosign), image registry allowlist, Trivy Operator continuous scanning, SLSA provenance attestation

**Exploiting Known CVEs in Running Containers**

- Attack: Exploiting publicly disclosed vulnerabilities in outdated images
- Mitigated by: Trivy Operator continuous scanning, alerts on HIGH/CRITICAL with patches, automated image rebuilds with Copacetic, GitOps deployment

### Secrets & Configuration

**Secrets Exposure in Pod Configs**

- Attack: Secrets leaked through environment variables, ConfigMaps, or insecure Kubernetes Secrets
- Mitigated by: External secrets management (AWS/GCP/Azure vaults), Secrets Store CSI Driver, secrets never in Git/native Secrets, Workload Identity/IRSA

**Compromised ArgoCD / GitOps Repo**

- Attack: Modified GitOps repository to deploy malicious workloads or steal secrets
- Mitigated by: ArgoCD in separate admin cluster, admin access restricted to VPN/bastion, signed Git commits required, RBAC limiting deployment permissions

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
