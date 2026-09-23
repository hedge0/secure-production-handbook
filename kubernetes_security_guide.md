# Kubernetes Security Guide

**Last Updated:** September 22, 2026

A cloud-agnostic guide for building production-ready Kubernetes clusters with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world production implementations.

## Table of Contents

1. [Overview](#1-overview)
   - [Do You Need Kubernetes?](#do-you-need-kubernetes)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Network Architecture & Database Layer](#3-network-architecture--database-layer)
   - [Network Design](#network-design)
   - [Database Layer](#database-layer)
4. [Cluster Architecture & Separation](#4-cluster-architecture--separation)
   - [Two-Cluster Design (Recommended)](#two-cluster-design-recommended)
   - [Single Cluster Alternative](#single-cluster-alternative)
   - [Network Policy Implementation](#network-policy-implementation)
5. [Ingress & Traffic Management](#5-ingress--traffic-management)
   - [Load Balancer Architecture](#load-balancer-architecture)
   - [WAF Configuration](#waf-configuration)
   - [Ingress Controllers & Gateway API](#ingress-controllers--gateway-api)
   - [Istio Service Mesh](#istio-service-mesh)
   - [Horizontal Pod Autoscaler (HPA)](#horizontal-pod-autoscaler-hpa)
6. [Policy Enforcement with Kyverno](#6-policy-enforcement-with-kyverno)
   - [Kyverno Policy Engine](#kyverno-policy-engine)
7. [Continuous Vulnerability & Threat Detection](#7-continuous-vulnerability--threat-detection)
   - [Trivy Operator for Vulnerability Scanning](#trivy-operator-for-vulnerability-scanning)
   - [Falco Runtime Security (Optional)](#falco-runtime-security-optional)
8. [Secrets Management](#8-secrets-management)
   - [External Secrets Management](#external-secrets-management)
   - [AWS EKS Integration](#aws-eks-integration)
   - [GCP GKE Integration](#gcp-gke-integration)
   - [Azure AKS Integration](#azure-aks-integration)
   - [Secret Rotation](#secret-rotation)
9. [Infrastructure as Code & GitOps](#9-infrastructure-as-code--gitops)
   - [Terraform for Infrastructure](#terraform-for-infrastructure)
   - [ArgoCD for GitOps](#argocd-for-gitops)
10. [Observability & Logging](#10-observability--logging)
    - [Fluentd Log Aggregation](#fluentd-log-aggregation)
    - [Prometheus & Grafana](#prometheus--grafana)
    - [Log Retention & Compliance](#log-retention--compliance)
11. [Identity & Access Management](#11-identity--access-management)
    - [Kubernetes RBAC](#kubernetes-rbac)
    - [Workload Identity & Cloud IAM Integration](#workload-identity--cloud-iam-integration)
    - [IAM Policy Best Practices](#iam-policy-best-practices)
12. [Disaster Recovery](#12-disaster-recovery)
    - [Recovery Strategy](#recovery-strategy)
    - [Recovery Procedure](#recovery-procedure)
    - [Testing & Validation](#testing--validation)
13. [Incident Response](#13-incident-response)
    - [Detection & Initial Response](#detection--initial-response)
    - [Containment & Recovery](#containment--recovery)
    - [Post-Incident](#post-incident)
14. [Attack Scenarios Prevented](#14-attack-scenarios-prevented)
15. [References](#15-references)

## 1. Overview

This guide outlines a production-grade Kubernetes architecture that prioritizes security, reliability, and operational excellence. The patterns are cloud-agnostic and work with managed Kubernetes services (AWS EKS, GCP GKE, Azure AKS) and their respective cloud-native services for networking, databases, secrets management, and observability.

**Common Use Cases:**

- Microservices deployments at scale (20+ services)
- Multi-tenant SaaS platforms
- CI/CD pipeline execution and build environments
- Batch processing and data pipelines
- Stateful applications (databases, message queues via operators)
- Complex service mesh architectures
- High-availability web applications

**Real-World Breaches:**

- **Tesla (2018)**: Exposed Kubernetes dashboard led to cryptomining, AWS credentials stolen
- **Weight Watchers (2018)**: A Kubernetes admin console with no password exposed root AWS keys, 31 IAM users and dozens of S3 buckets
- **Dero and Monero cryptojacking (2023)**: Competing campaigns scanned for Kubernetes API servers exposed to the internet with anonymous auth enabled and deployed miners cluster-wide
- **IngressNightmare (2025)**: CVE-2025-1974 in ingress-nginx's admission webhook gave unauthenticated RCE and access to every Secret in the cluster; Wiz estimated 40%+ of cloud environments were exposed
- **Multiple Organizations**: Shodan regularly finds thousands of publicly exposed Kubernetes dashboards

**Core Principles:**

- **Defense in Depth**: Multiple security layers from network to runtime
- **Least Privilege**: Minimize blast radius through network isolation and access controls
- **High Availability**: Multi-AZ databases, automatic failover, point-in-time recovery
- **Infrastructure as Code**: Versioned, reproducible infrastructure with Terraform and ArgoCD
- **Separation of Concerns**: Isolated clusters for production workloads vs administrative tooling
- **Operational Excellence**: Accept complexity only when scale demands it

### Do You Need Kubernetes?

**You probably DON'T need Kubernetes if:**

- You have <50 engineers
- You run <20 microservices
- Your traffic is <10M requests/day
- You don't have a dedicated platform/DevOps team (3-5 engineers minimum)
- You're trying to look "cloud-native" but haven't validated the operational cost

**What Kubernetes actually requires:**

- 3-5 dedicated platform engineers to manage it properly
- Expertise in: networking, security, storage, observability, GitOps
- Operational complexity: YAML files, Helm charts, kubectl, service meshes, policy engines
- Debugging: pod evictions, OOMKilled errors, image pull failures, DNS issues, network policies
- Cost: $400-660/month for a minimal production setup, $780-1410/month with the full observability/security stack, $1500-3000+/month once real traffic arrives (see breakdown below)

**What to use instead:**

**For Serverless Workloads (Recommended for <50 Engineers)**

- **AWS**: Lambda + API Gateway + RDS Aurora
- **GCP**: Cloud Run + Cloud SQL
- **Azure**: Functions + Azure SQL

**Why serverless is better for small teams:**

- Zero operational overhead (no patching, scaling, YAML)
- Pay only for usage ($0-50/month for most startups, free tier covers <1M requests)
- Infinite scale without configuration
- 1 engineer can manage entire infrastructure
- Deploy in minutes, not weeks

**Trade-offs you should accept:**

- Cold starts (100ms-3s) - acceptable for 95% of APIs
- Stateless only (use managed databases for state)

**For Container Workloads (If You Need WebSockets/Streaming)**

- **AWS**: ECS Fargate + ALB + RDS
- **GCP**: Cloud Run (supports WebSockets) + Cloud SQL
- **Azure**: Container Apps + Azure SQL

**Why Fargate over Kubernetes:**

- No cluster to manage (AWS manages control plane AND workers)
- No Kubernetes complexity (YAML, Helm, kubectl, service mesh)
- Still get containers, load balancing, auto-scaling
- 1/10th the operational complexity of K8s
- $130-315/month vs $400-1400+/month for K8s (see breakdown below)

**You ACTUALLY need Kubernetes when:**

- You have 50+ microservices with complex inter-service networking
- You need sophisticated service mesh (mTLS between hundreds of services)
- You're cost-optimizing at massive scale (spot instances, bin packing, multi-tenancy)
- You have a dedicated platform team (3-5+ engineers)
- You run ML workloads requiring GPU orchestration
- You need multi-tenancy isolation for SaaS products
- You're at "Spotify scale" (not "we watched a KubeCon talk" scale)

**Reality check:** Kubernetes killed more startups than server crashes ever did. A $50/month Fargate container can handle millions of requests. Your startup will run out of runway debugging networking issues long before you need horizontal pod autoscaling.

**Detailed Monthly Cost Breakdown:**

**Serverless Stack (Lambda/Cloud Run):**

- Compute (Lambda/Cloud Run): $0-30 (free tier covers most MVPs, ~$20-30 for 5M requests)
- API Gateway: $3.50 per million requests (~$10-20 for typical usage)
- Managed Database (smallest tier): $15-50
- Secrets Manager: $0.40 per secret (~$2-5)
- **Total: $30-100/month**

**Fargate Stack:**

- Fargate tasks (2-3 for HA, 0.5 vCPU, 1GB RAM each): $30-45
- Application Load Balancer: $16-25
- Managed Database (small): $50-150
- Secrets Manager: $2-5
- NAT Gateway (if private subnets): $32-45
- **Total: $130-270/month (public subnets) or $160-315/month (private subnets)**

**Kubernetes Minimal Production:**

- Control plane: $73 (EKS/GKE at $0.10/hr; EKS jumps to $0.60/hr on extended support, so upgrade on time; AKS Free tier is $0 but has no SLA)
- Worker Nodes (3 t3.medium instances): $150-200
- NAT Gateway (3 AZ): $100-135
- Load Balancer: $25-40
- Managed Database: $50-200
- Secrets Manager: $5-10
- **Total: $400-660/month (before observability stack)**

**Kubernetes Full Production (with this guide's architecture):**

- Above base infrastructure: $400-660
- Istio service mesh overhead: +$50-100 (additional CPU/memory)
- Prometheus + Grafana: +$30-60 (storage, retention)
- Fluentd + centralized logging: +$50-200 (log volume dependent)
- ArgoCD cluster (separate admin cluster): +$200-300
- Trivy Operator scanning: +$20-40
- Additional tooling (Kyverno, external-secrets): +$30-50
- **Total: $780-1410/month for full stack**
- **Realistic production with traffic: $1500-3000+/month**

**If you're still reading, you've validated you actually need Kubernetes. This guide is for you.**

## 2. Prerequisites

### Required Tools

**Infrastructure as Code:**

- [Terraform](https://developer.hashicorp.com/terraform) - Infrastructure provisioning and management
- [Helm](https://helm.sh/) - Kubernetes package manager
- [ArgoCD](https://argo-cd.readthedocs.io/en/stable/) - GitOps continuous delivery for Kubernetes

**Security & Policy:**

- [Kyverno](https://github.com/kyverno/kyverno) - Kubernetes-native policy engine
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) - Continuous vulnerability scanning
- [Istio](https://github.com/istio/istio) - Service mesh for mTLS and traffic management
- [Falco](https://github.com/falcosecurity/falco) - Runtime threat detection (optional - see analysis in Section 7)

**Observability:**

- [Prometheus](https://prometheus.io/) - Metrics collection and monitoring
- [Grafana](https://grafana.com/) - Visualization and dashboards
- [Fluentd](https://github.com/fluent/fluentd) - Log collection and forwarding

### External Services

Cloud-agnostic service options for Kubernetes, databases, secrets, logging, and load balancing.

| Service Category                     | AWS                              | GCP                                | Azure                           | Self-Hosted / Open Source |
| ------------------------------------ | -------------------------------- | ---------------------------------- | ------------------------------- | ------------------------- |
| **Managed Kubernetes** (recommended) | Elastic Kubernetes Service (EKS) | Google Kubernetes Engine (GKE)     | Azure Kubernetes Service (AKS)  | -                         |
| **Managed Databases** (required)     | RDS (PostgreSQL, MySQL, Aurora)  | Cloud SQL                          | Database for PostgreSQL/MySQL   | -                         |
| **Secrets Management** (required)    | Secrets Manager                  | Secret Manager                     | Key Vault                       | HashiCorp Vault           |
| **Logging & SIEM** (required)        | CloudWatch Logs                  | Cloud Logging                      | Monitor                         | Splunk, ELK Stack, Loki   |
| **Load Balancing & WAF**             | ALB + AWS WAF                    | Cloud Load Balancing + Cloud Armor | Application Gateway + Azure WAF | -                         |

**Notes:**

- **Managed Kubernetes**: Strongly recommended over self-hosted - reduces operational burden and improves security
- **Managed Databases**: Required for production - never run databases in Kubernetes for production workloads
- **Secrets Management**: Required for secure credential storage and rotation
- **Load Balancing & WAF**: Essential for edge security and DDoS protection

## 3. Network Architecture & Database Layer

Design secure network topology with proper isolation and managed databases for production resilience.

### Network Design

Choose between private and public subnets based on your security requirements and budget constraints.

| Aspect                 | Private Subnets                               | Public Subnets                          |
| ---------------------- | --------------------------------------------- | --------------------------------------- |
| **Worker Node Access** | No direct internet access                     | Public IP addresses                     |
| **Egress Method**      | NAT Gateway required                          | Direct egress                           |
| **Monthly Cost**       | $32-45 per AZ + data transfer fees            | $0 (no NAT Gateway)                     |
| **Multi-AZ Cost**      | 3 AZs = 3x NAT Gateway fees (~$100-135/month) | $0                                      |
| **Security Level**     | Excellent - nodes fully isolated              | Good - requires strict security groups  |
| **Attack Surface**     | Minimal - no public IPs                       | Higher - nodes have public IPs          |
| **Best For**           | Production environments                       | Budget-constrained or non-critical apps |

**Recommendation:** Use private subnets with NAT Gateway for production - the cost is negligible compared to security benefits.

**Public Subnet Configuration** (if chosen):

- Worker nodes in public subnets with strict security groups
- Allow only: ALB traffic, specific admin IPs/VPN
- Block all other inbound traffic
- **Risk**: Requires careful security group configuration to prevent exposure

**Multi-AZ Design** (applies to both):

- Distribute worker nodes across 3 AZs minimum
- Managed Kubernetes control plane automatically multi-AZ
- ALB/NLB automatically span AZs

**Admin Access**:

- VPN (AWS Client VPN, GCP Cloud VPN, Azure VPN Gateway) - recommended
- Bastion host alternative (hardened VM, restricted IPs)
- Admin ALB restricted to VPN range or bastion IP only
- Never expose Kubernetes API or admin tools to 0.0.0.0/0

### Database Layer

**Never run databases in Kubernetes for production workloads.**

Use managed cloud databases instead:

- AWS RDS (PostgreSQL, Aurora)
- GCP Cloud SQL
- Azure Database for PostgreSQL

**Why managed databases:**

Kubernetes is designed for stateless applications. Running databases in Kubernetes introduces operational complexity:

- Persistent storage management across node failures
- Manual backup and recovery procedures
- Complex replication configuration
- Database lifecycle tightly coupled to cluster lifecycle

Managed database services provide:

- Automated backups with point-in-time recovery
- Multi-AZ deployment with automatic failover (60-120 seconds)
- Automated patching and maintenance windows
- Separation of database operations from Kubernetes operations

**Network Architecture:**

- Deploy databases in **private subnets** (no internet access)
- Security groups allow connections **only from Kubernetes worker nodes**
- All database traffic stays within VPC

**Connection Pattern:**

Applications running in Kubernetes retrieve database credentials from cloud secrets managers using Secrets Store CSI Driver:

| Cloud Provider | Integration                                           |
| -------------- | ----------------------------------------------------- |
| **AWS EKS**    | Secrets Store CSI Driver + AWS Secrets Manager        |
| **GCP GKE**    | Workload Identity + Secret Manager                    |
| **Azure AKS**  | Azure Key Vault Provider for Secrets Store CSI Driver |

The CSI driver mounts credentials into the pod as files on a tmpfs volume. Use its optional `secretObjects` sync to a Kubernetes Secret only when an environment variable is unavoidable, and prefer files (Section 8). Either way the source of truth stays in the cloud provider's secrets manager.

## 4. Cluster Architecture & Separation

Isolate production workloads from administrative tooling using separate Kubernetes clusters.

### Two-Cluster Design (Recommended)

**Production Cluster**:

- Customer-facing applications and services
- Istio for mTLS, Kyverno for policy enforcement
- Trivy Operator for vulnerability scanning, Falco for runtime monitoring (optional - see Section 7)
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

Without NetworkPolicies, namespace isolation is convention only. Apply these policies to enforce separation:

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
              kubernetes.io/metadata.name: istio-system # namespace your ingress gateway runs in (Helm installs use istio-ingress)
      ports:
        - protocol: TCP
          port: 8080
```

**Default deny all egress (apply to each namespace, then allow each dependency explicitly):**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # DNS (adjust if you run NodeLocal DNSCache or GKE Cloud DNS)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Istio sidecars need istiod for config and certificates
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: istio-system
          podSelector:
            matchLabels:
              app: istiod
      ports:
        - protocol: TCP
          port: 15012
```

Add explicit egress rules for the database subnet (`ipBlock`) and any external APIs the service calls.

Apply default-deny first, then explicitly allow required traffic. Test with an ephemeral debug container (distroless app images have no `curl`; it shares the pod's network namespace, so the pod's NetworkPolicy applies; `--profile=restricted` sets `runAsNonRoot`, so the image needs a numeric `USER`): `kubectl debug -it pod-name --image=cgr.dev/chainguard/curl --profile=restricted -- curl -sS http://service.namespace.svc.cluster.local`

## 5. Ingress & Traffic Management

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
- Rate-based rules for application-layer (L7) floods
- Block known malicious IPs and bot traffic
- Volumetric (L3/L4) DDoS is handled by the provider edge, not WAF rules: AWS Shield Standard (automatic on ALB/CloudFront; Shield Advanced for L7 and cost protection), Cloud Armor, Azure DDoS Protection

### Ingress Controllers & Gateway API

Ingress NGINX - critical infrastructure for about half of cloud native environments - was retired in March 2026: no releases, bug fixes, or security patches after that date (IngressNightmare, CVE-2025-1974, showed what an unpatched ingress controller costs). Do not deploy it. This guide's ALB → Istio ingress gateway path already avoids it; for new routing config use [Gateway API](https://gateway-api.sigs.k8s.io/), the Kubernetes-standard successor to Ingress that Istio implements natively, and run `ingress2gateway` to convert any leftover Ingress resources.

### Istio Service Mesh

**Mutual TLS (mTLS)**:

- Automatic mTLS between sidecar-injected pods (label namespaces `istio-injection=enabled`; ambient mode uses ztunnel instead of sidecars)
- Default mode is `PERMISSIVE` (plaintext still accepted), so enforce it mesh-wide:

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

- Prevents man-in-the-middle attacks on internal traffic once STRICT is enforced
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

### Horizontal Pod Autoscaler (HPA)

HPA automatically scales pod replicas based on CPU/memory utilization. The controller is built into Kubernetes, but it reads CPU/memory from Metrics Server: GKE and AKS ship it, EKS does not. On EKS install the `metrics-server` community add-on first (`aws eks create-addon --cluster-name production-cluster --addon-name metrics-server`) or the HPA below reports `<unknown>` and never scales.

**Basic HPA Configuration:**

```bash
# Simple CPU-based autoscaling
kubectl autoscale deployment myapp --cpu=70% --min=3 --max=10
```

```yaml
# Equivalent YAML configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: myapp
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myapp
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

**When to use HPA:**

- ✅ Traffic is unpredictable (global users, viral content, breaking news)
- ✅ Load varies significantly and randomly throughout the day
- ✅ You cannot predict when scaling is needed

**When NOT to use HPA (use scheduled scaling instead):**

- ❌ Traffic follows predictable patterns (business hours 9-5, weekday vs weekend)
- ❌ Small team (<10 engineers) - scheduled scaling is simpler to maintain
- ❌ Database is the bottleneck - scaling application pods won't help

**Scheduled Scaling for Predictable Traffic:**

If your traffic is predictable (most B2B SaaS, internal tools, business-hour applications), scheduled scaling is simpler and more reliable than HPA:

```text
# crontab entries: scale up before business hours (7:55 AM weekdays)
55 7 * * 1-5 kubectl scale deployment myapp --replicas=10

# Scale down after hours (6:05 PM weekdays)
5 18 * * 1-5 kubectl scale deployment myapp --replicas=3
```

Run these from a Kubernetes CronJob whose ServiceAccount can only scale this Deployment, not from a bastion with admin credentials. If ArgoCD manages the Deployment, drop `replicas` from the Git manifest (or add `/spec/replicas` to `ignoreDifferences`), or the next sync resets it.

**Cost:** $0, **Complexity:** 2 cron jobs, **Reliability:** No metrics lag, no autoscaler bugs

**Security considerations:**

- HPA prevents manual over-provisioning that wastes budget
- HPA is not a DDoS control: scaling into a flood turns an availability attack into a bill. Cap `maxReplicas`, alert on scale-out bursts, and absorb floods at the edge (Shield/WAF rate rules, Cloud Armor, Azure DDoS Protection) before they reach pods
- Simple, predictable scaling (scheduled or basic HPA) is more secure than complex reactive systems
- Avoid custom metrics HPA unless proven necessary - adds complexity and potential failure modes

**Limitations:**

- HPA scales horizontally (more pods), not vertically (bigger pods)
- Requires resource requests to be set (when only limits are set, requests default to the limits the Kyverno policy in Section 6 enforces)
- Metrics lag: 30-60 seconds between load spike and scaling action
- For instant scale-up, pre-scale using scheduled scaling or set higher min replicas

## 6. Policy Enforcement with Kyverno

Enforce security policies at deployment time to prevent misconfigurations and ensure compliance.

### Kyverno Policy Engine

Deploy [Kyverno](https://github.com/kyverno/kyverno) for Kubernetes-native policy enforcement: policies are YAML with CEL expressions, the same language as the built-in ValidatingAdmissionPolicy, so there is no Rego to learn.

Turn on the built-in baseline first: label each workload namespace `pod-security.kubernetes.io/enforce=restricted` (Pod Security Admission, GA since Kubernetes 1.25). It rejects privileged containers, host namespaces, root users and missing `seccompProfile` with no extra components. Kyverno then adds what PSA cannot express: image signatures, registry allowlists, resource limits and custom rules.

**Essential Security Policies:**

Kyverno enforces these policies at pod deployment to prevent security misconfigurations:

1. **Require Resource Limits** - Prevents resource exhaustion by requiring CPU/memory limits
2. **Block Privileged Containers** - Prevents privilege escalation attacks
3. **Require Non-Root User** - Ensures containers run as non-root user
4. **Verify Image Signatures** - Validates images are signed with Cosign

**Policy syntax:** The examples use Kyverno's CEL-based types in `policies.kyverno.io/v1` (`ValidatingPolicy` for pod rules, `ImageValidatingPolicy` for signatures), current as of Kyverno v1.19.1. The legacy `kyverno.io/v1` `ClusterPolicy` was deprecated in Kyverno 1.17 and its removal is planned for v1.20 (targeted October 2026), so migrate existing policies now.

---

**Example Policy: Require Resource Limits**

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-resource-limits
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  variables:
    - name: allContainers
      expression: >-
        object.spec.containers + object.spec.?initContainers.orValue([])
  validations:
    - expression: >-
        variables.allContainers.all(c, has(c.resources) && has(c.resources.limits) &&
        has(c.resources.limits.cpu) && has(c.resources.limits.memory))
      message: "CPU and memory limits required"
```

**Why resource limits are security-critical:**

Without limits, a compromised pod can consume all cluster resources, causing denial of service for legitimate workloads. Cryptominers exploit unlimited CPU to mine at full capacity. Resource limits contain the blast radius - a compromised pod's damage is restricted to its allocated resources.

---

**Example Policy: Block Privileged Containers**

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-privileged
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  variables:
    - name: allContainers
      expression: >-
        object.spec.containers +
        object.spec.?initContainers.orValue([]) +
        object.spec.?ephemeralContainers.orValue([])
  validations:
    - expression: >-
        variables.allContainers.all(c,
        c.?securityContext.?privileged.orValue(false) == false)
      message: "Privileged mode is not allowed"
```

---

**Example Policy: Require Non-Root Containers**

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-non-root
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  variables:
    - name: ctnrs
      expression: >-
        object.spec.containers +
        object.spec.?initContainers.orValue([]) +
        object.spec.?ephemeralContainers.orValue([])
  validations:
    # Pod-level true with no container overriding it, or every container sets true
    - expression: >-
        (object.spec.?securityContext.?runAsNonRoot.orValue(false) == true &&
        variables.ctnrs.all(c, c.?securityContext.?runAsNonRoot.orValue(true) == true)) ||
        variables.ctnrs.all(c, c.?securityContext.?runAsNonRoot.orValue(false) == true)
      message: "Containers must run as non-root user"
```

---

**Example Policy: Verify Image Signatures**

Requires [Cosign](https://github.com/sigstore/cosign) for signing container images.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: verify-image-signature
spec:
  validationActions: [Deny]
  webhookConfiguration:
    timeoutSeconds: 15 # signature lookups hit the registry
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  # Your own images only: the Istio sidecar and third-party operators are not signed with your key
  matchImageReferences:
    - glob: "registry.example.com/myorg/*"
  attestors:
    - name: cosign
      cosign:
        key:
          data: |
            -----BEGIN PUBLIC KEY-----
            ...your public key...
            -----END PUBLIC KEY-----
  validations:
    - expression: >-
        images.containers.map(image, verifyImageSignatures(image, [attestors.cosign])).all(e, e > 0)
      message: "Image signature verification failed"
```

---

**Additional Security Policies:**

Implement these additional policies for comprehensive security:

- Block hostNetwork, hostPID, hostIPC usage
- Require pod security labels
- Enforce image registry allowlist (only approved registries)
- Validate required security contexts
- Require read-only root filesystem where possible
- Block dangerous capabilities
- Enforce distroless or minimal base images (no package managers)

**Deployment Workflow:**

Kyverno runs as admission controller, validates policies before pods are created, blocks non-compliant workloads automatically.

## 7. Continuous Vulnerability & Threat Detection

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

### Falco Runtime Security (Optional)

[Falco](https://github.com/falcosecurity/falco) provides real-time runtime threat detection in containers, but should be carefully evaluated based on your security architecture's existing preventive controls.

**What Falco detects**:

- Shell spawned in container (potential breakout attempt)
- Unexpected process execution in containers
- Sensitive file access (/etc/shadow, SSH keys, credentials)
- File system modifications in read-only paths
- Unexpected network connections (unknown destinations, C2 beacons)
- Privilege escalation attempts
- Container processes accessing host filesystem
- Suspicious system calls

**Trade-Off Analysis: When Falco Adds Limited Value**

If your architecture already implements comprehensive preventive controls, Falco becomes largely redundant and may not justify its costs:

**1. Redundancy with Preventive Controls**

When you have all of these in place, an attacker who compromises a container has almost nothing they can execute:

- **Distroless images**: No shell, no package managers (apt/yum/apk), no binaries beyond application code
- **Non-root enforcement**: Attacker cannot write to most filesystem locations or escalate privileges
- **Read-only root filesystem**: Even if attacker finds writable location, filesystem is immutable
- **Restrictive NetworkPolicies**: Default-deny egress blocks data exfiltration and C2 communications
- **Istio STRICT mTLS + AuthorizationPolicy**: every workload has a cryptographic identity and only allow-listed callers are accepted; mTLS alone still lets any mesh workload call any service

**Result**: these controls remove most of what Falco's default rules fire on, but they do not make runtime attacks impossible. An in-process payload (deserialization, SSTI or a Log4Shell-class bug in a Java/Python/Node app) runs with the application's own permissions and needs no shell, `readOnlyRootFilesystem` does not cover `emptyDir` or `/tmp` mounts, and anything your egress policy allows (the database, cloud APIs, DNS) is still a path out.

**2. Attack Surface Expansion**

Falco introduces its own security risks:

- **Privileged access**: Runs as privileged DaemonSet with kernel-level access via eBPF/kernel module
- **High-value target**: Compromise Falco = visibility into ALL containers on the node
- **Supply chain risk**: Another container image to scan, patch, and manage CVEs for
- **Complexity**: Additional failure mode and potential misconfiguration risks

**3. Performance Overhead**

- Intercepts syscalls across all pods on every node
- CPU overhead scales with cluster activity (more pods = more overhead)
- Memory overhead for buffering and processing events
- Though marketed as "zero impact," production clusters report 2-5% CPU overhead at scale

**4. Operational Complexity**

- Requires tuning rules to reduce false positives
- Alert fatigue from noisy detections
- Another system to update, monitor, and maintain
- Team needs expertise to interpret Falco alerts and respond appropriately

**When Falco IS Worth Deploying**

Falco provides valuable detective capabilities in these scenarios:

1. **Weak preventive controls**: If you cannot enforce distroless, non-root, read-only filesystem, or network policies
2. **Zero-day detection**: Catches novel attacks exploiting application logic bugs that don't need external tools
3. **Insider threat**: Malicious code deployed through legitimate CI/CD or by insiders with access
4. **Compliance mandate**: Some frameworks explicitly require runtime monitoring (though alternatives may satisfy this)
5. **"Assume breach" philosophy**: If your threat model assumes preventive controls will fail

**Alternative Approaches Without Falco**

These provide overlapping detection capabilities with lower overhead:

1. **Kubernetes audit logs**: Track suspicious API activity (pod exec attempts, secret access)
2. **Prometheus/Grafana anomalies**: Monitor pod restarts, network patterns, resource spikes
3. **Cloud-native logging**: CloudWatch/Cloud Logging/Azure Monitor for centralized audit trails
4. **Trivy Operator**: Continuous vulnerability scanning catches exploitable CVEs before attackers can use them
5. **Periodic penetration testing**: Red team exercises validate your preventive controls work as intended

**Recommendation**

For architectures with comprehensive preventive controls (distroless, non-root, read-only FS, restrictive NetworkPolicies, Istio mTLS), **Falco is optional and likely not worth the operational/security trade-offs**.

Document your decision with a risk acceptance statement: "We accept the risk of undetected runtime threats because our preventive controls make successful runtime attacks highly improbable, and the operational/security costs of Falco outweigh the marginal detection benefit."

**If deploying Falco despite preventive controls**, recognize you're optimizing for defense-in-depth at the cost of complexity.

**Deployment** (if chosen):

- Deploy as DaemonSet (runs on every node)
- Uses eBPF or kernel module to intercept system calls
- Rules are customizable for your environment

**Alert Configuration** (if chosen):

- Forward alerts to Fluentd, then to SIEM
- Integrate with Slack/PagerDuty for real-time notifications
- Configure severity levels (info, warning, critical)
- Alert on critical events only to reduce noise

## 8. Secrets Management

Store secrets in external vault services and inject them into Kubernetes pods securely with modern lifecycle management practices.

### External Secrets Management

**Never store secrets in**:

- Kubernetes Secrets as the system of record (base64, readable by anyone with `get secrets` RBAC; EKS, GKE and AKS encrypt etcd at rest by default, but that protects the disk, not the API)
- ConfigMaps
- Environment variables in Dockerfiles
- Git repositories

**Always store secrets in**:

- AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
- HashiCorp Vault
- External secrets management with encryption, access control, audit logging

### AWS EKS Integration

- Secrets Store CSI Driver with the AWS Secrets and Configuration Provider (ASCP); set `usePodIdentity: "true"` in the SecretProviderClass
- EKS Pod Identity for authentication (AWS's recommended method); IRSA only where Pod Identity is unsupported (Fargate, Windows nodes, EKS Anywhere, ROSA, self-managed clusters)
- Secrets mounted as volumes (not environment variables for sensitive data)

### GCP GKE Integration

- Workload Identity Federation for GKE for pod authentication to Secret Manager
- Secret Manager add-on for GKE (`gcloud container clusters update ... --enable-secret-manager`; Google-managed Secrets Store CSI Driver + provider)
- Secrets mounted as volumes

### Azure AKS Integration

- Azure Key Vault Provider for Secrets Store CSI Driver
- Managed identities for pod authentication
- Secrets mounted as volumes

### Secret Rotation

**Rotation policy**: Prefer short-lived workload identity so there is nothing static to rotate: EKS Pod Identity (IRSA where Pod Identity is unsupported), Workload Identity Federation for GKE, Microsoft Entra Workload ID, and IAM database authentication. The SDK refreshes these credentials automatically (about an hour for IRSA, GKE and AKS; up to 6 hours for EKS Pod Identity). NIST SP 800-63B-4's rule against forced periodic changes covers user passwords only, never service credentials.

**Static secrets that must exist** (database passwords, third-party API keys):

- Rotate immediately on suspected or confirmed compromise, or when someone with access leaves
- Otherwise rotate on a documented risk-based schedule (90 days is a common choice): AWS Secrets Manager rotates on a schedule via Lambda, GCP Secret Manager rotation schedules notify Pub/Sub
- PCI DSS v4.0.1 Req 8.6.3 requires passwords for application and system accounts to be changed "periodically (at the frequency defined in the entity's targeted risk analysis) and upon suspicion or confirmation of compromise"
- Keep access controls, audit logging and alerts on unauthorized access attempts

## 9. Infrastructure as Code & GitOps

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

**Workspace Strategies:**

**Option 1: Workspace-Per-Environment** (Smaller teams):

- Single codebase with `terraform workspace` for dev/staging/production
- Advantages: Less duplication, shared modules, easy to keep in sync
- Disadvantages: Shared state file, risk of accidental cross-environment changes

**Option 2: Separate State Files** (Recommended for production):

- Separate directories for each environment with independent state files
- Advantages: Complete isolation, environment-specific access controls, no cross-environment risk
- Disadvantages: More code duplication (mitigated by modules)

**Recommendation**: Use separate state files for production (`environments/production/`), workspaces acceptable for dev/staging.

**Module Organization:**

Organize into reusable modules to reduce duplication:

```text
modules/
├── vpc/          # VPC, subnets, NAT gateways
├── eks-cluster/  # EKS cluster, node groups, IRSA
└── rds-postgres/ # RDS instance, subnet group, security group

environments/
├── dev/main.tf
├── staging/main.tf
└── production/main.tf  # References modules
```

**Sensitive Data Handling:**

- Mark sensitive outputs: `sensitive = true` (prevents console display, still in state)
- Encrypt state files at rest in remote backend
- Restrict state access with least-privilege permissions
- Never commit secrets: Use vault references, not hardcoded values

**Drift Detection:**

Infrastructure drift occurs when manual changes bypass Terraform:

```bash
# Detect drift
terraform plan -detailed-exitcode  # 0 = no changes, 1 = error, 2 = drift or unapplied changes
```

```yaml
# Automated daily drift detection in CI/CD (GitHub Actions steps)
- name: Drift Detection
  id: drift
  run: terraform plan -no-color -detailed-exitcode
  continue-on-error: true # keep the job green...
- name: Alert on drift
  if: steps.drift.outcome == 'failure' # ...but alert (conclusion is always success)
  run: ./scripts/notify-drift.sh # Slack/PagerDuty webhook
```

**Remediation**: Import manual changes (`terraform import`), revert with `terraform apply`, or update Terraform to match reality.

**Team Collaboration:**

**Pull Request Workflow:**

1. Developer creates branch and modifies `.tf` files
2. CI/CD runs validation: `terraform fmt -check`, `terraform validate`, `terraform plan`
3. Team reviews plan output in PR comments
4. Approval: 1 for dev/staging, 2 for production (1 from security)
5. Merge triggers `terraform apply` (auto for dev/staging, manual for production)

**RBAC**: Developers can plan (read-only), SRE/DevOps can apply with approval, security team has audit access.

**Cost Estimation:**

Use Infracost to preview cost impact before applying:

```yaml
# Infracost 0.10 CLI; Infracost 2.x (github.com/infracost/cli) replaces these with `infracost scan`
- name: Run Infracost
  run: |
    infracost breakdown --path . --format json --out-file infracost-base.json # on the base branch
    infracost diff --path . --compare-to infracost-base.json # on the PR branch

# Example output: Monthly cost change: +$653 (m5.xlarge + db.r5.2xlarge)
```

**Testing:**

- **Pre-apply**: `terraform validate`, `trivy config .` (security scan; tfsec was folded into Trivy and is maintenance-only), `checkov` (policy-as-code)
- **Preview environments**: Create temporary workspace to test major changes
- **Integration tests**: Terratest for module validation

**Provider Version Management:**

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"  # Allow 6.x, block 7.0 breaking changes (6.0 shipped June 2025)
    }
  }
}
```

Upgrade process: Test in dev → review changelog → staging → production with maintenance window.

**Disaster Recovery:**

**State File Corruption/Deletion:**

1. Enable versioning on state storage backend
2. Automated daily backups to separate storage location
3. Cross-region replication for critical state
4. Recovery: Restore from version history or backup

**Accidental Destroy:**

- Prevention: `lifecycle { prevent_destroy = true }` on critical resources
- Recovery: Restore from backup, re-import resources with `terraform import`

**Backup Automation:**

```bash
#!/bin/bash
# Daily state backup (example for S3 backend)
for ENV in dev staging production; do
  # Copy state file to backup location with timestamp
  aws s3 cp s3://terraform-state/$ENV/terraform.tfstate \
    s3://terraform-state-backup/$ENV/terraform.tfstate.$(date +%Y%m%d)
done
```

**Note:** Backup command varies by backend (S3, GCS, Azure Blob). Adapt for your provider.

**Key Takeaways:**

- Use separate state files for production with strict access controls
- Implement automated drift detection to catch manual changes
- Require code reviews and approvals for all infrastructure changes
- Maintain comprehensive state file backups with version history
- Practice disaster recovery procedures quarterly

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

## 10. Observability & Logging

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
- Track security metrics (Kyverno violations, Falco alerts if deployed, Trivy vulnerabilities)
- Accessible only via admin ALB (VPN/bastion restricted)

### Log Retention & Compliance

**Hot Storage** (30 days):

- AWS CloudWatch Logs, GCP Cloud Logging, Azure Monitor
- Fast access for debugging and incident response
- Real-time searching and alerting

**Cold Storage** (Multi-Year for Compliance):

- S3 Glacier, GCS Coldline/Archive, Azure Archive
- Compressed logs for regulatory compliance

**Retention Requirements by Compliance Standard:**

| Compliance Standard | Retention Period                                   | Scope                                                                      |
| ------------------- | -------------------------------------------------- | -------------------------------------------------------------------------- |
| **PCI DSS v4.0.1**  | 12 months (3 months immediately available)         | Audit logs for in-scope systems (Req 10.5.1)                               |
| **HIPAA**           | 6 years                                            | Security Rule documentation, incl. audit records (45 CFR 164.316(b)(2)(i)) |
| **SOC 2**           | Not prescribed; set and document your own          | Audit logs, access logs, security events                                   |
| **ISO 27001**       | Not prescribed; set and document your own          | Security logs, incident records                                            |
| **GDPR**            | No fixed period; storage limitation (Art. 5(1)(e)) | Personal data kept no longer than necessary                                |

**Archive Process**:

1. Export from hot storage after 30 days
2. Compress (gzip, zstd)
3. Upload to cold storage with lifecycle policies
4. Delete from hot storage

## 11. Identity & Access Management

Implement least-privilege access control through Kubernetes RBAC and cloud provider IAM integration to minimize blast radius of compromised credentials.

### Kubernetes RBAC

**ServiceAccount Configuration**:

- Create dedicated ServiceAccount per application (not `default`)
- Set `automountServiceAccountToken: false` unless pod needs Kubernetes API access
- Use namespace-scoped Roles (not ClusterRoles) for applications
- Grant minimal permissions: `get` only, avoid `list`, `watch`, `*` verbs

**RBAC Example (basic read-only)**:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-server-sa
  namespace: production
# No token by default; a pod that needs this Role opts in with
# spec.automountServiceAccountToken: true (the pod setting wins)
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

**Additional RBAC Example (developer read-only access for debugging)**:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-readonly
  namespace: production
rules:
  # View pods and logs for debugging
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]

  # View deployments for status
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developers-binding
  namespace: production
subjects:
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-readonly
  apiGroup: rbac.authorization.k8s.io
```

**Additional RBAC Example (CI/CD deployer)**:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cicd-deployer
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cicd-deployer-role
  namespace: production
rules:
  # Manage deployments for rolling updates
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "create", "update", "patch"]

  # View pods to verify deployment
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cicd-deployer-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: cicd-deployer
roleRef:
  kind: Role
  name: cicd-deployer-role
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

### Workload Identity & Cloud IAM Integration

Allow pods to assume cloud IAM roles without storing credentials. This eliminates the need for service account keys and provides automatic credential rotation.

**Key Differences by Cloud Provider:**

| Feature                 | AWS EKS (Pod Identity; IRSA legacy)                          | GCP GKE (Workload Identity Federation)                           | Azure AKS (Microsoft Entra Workload ID)                                               |
| ----------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Setup Complexity**    | Low (one association per SA; IRSA: OIDC provider + trust)    | Low (one IAM binding on the KSA principal)                       | Medium (OIDC issuer + federated credential)                                           |
| **Auth Method**         | EKS Auth service + node agent (IRSA: OIDC federation to STS) | Workload identity pool federation                                | Managed identity federation                                                           |
| **Credential Lifetime** | Up to 6 h Pod Identity, 1 h IRSA STS session (auto-refresh)  | 1 h access token (auto-refresh)                                  | Variable (auto-refresh)                                                               |
| **Annotation Required** | None (IRSA: `eks.amazonaws.com/role-arn`)                    | None (impersonation only: `iam.gke.io/gcp-service-account`)      | `azure.workload.identity/client-id` + pod label `azure.workload.identity/use: "true"` |
| **IAM Role Type**       | IAM Role trusting `pods.eks.amazonaws.com`                   | IAM binding on `principal://...svc.id.goog/subject/ns/NS/sa/KSA` | Azure Managed Identity                                                                |

---

**AWS EKS - Pod Identity (recommended):**

AWS now recommends EKS Pod Identity (launched November 2023) over IRSA. No OIDC provider, no ServiceAccount annotation: install the `eks-pod-identity-agent` add-on once per cluster (built into EKS Auto Mode), give the IAM role a trust policy for `pods.eks.amazonaws.com`, and create an association. One trust policy works in every cluster, and the node agent fetches credentials from the EKS Auth API so pods never call STS themselves. IRSA remains the fallback for Fargate, Windows nodes, and non-EKS clusters.

```bash
# Step 1: Install the agent add-on (once per cluster; not needed on EKS Auto Mode)
aws eks create-addon --cluster-name production-cluster --addon-name eks-pod-identity-agent

# Step 2: Create IAM role whose trust policy allows sts:AssumeRole + sts:TagSession
#         for Principal { "Service": "pods.eks.amazonaws.com" }

# Step 3: Map the role to the ServiceAccount (no annotation required)
aws eks create-pod-identity-association \
  --cluster-name production-cluster \
  --namespace production \
  --service-account api-server-sa \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/api-server-role
```

**Key Points:**

- Associations are managed through the EKS API, so granting a role needs `eks:CreatePodIdentityAssociation`, not write access to a ServiceAccount
- Session tags (`eks-cluster-name`, `kubernetes-namespace`, `kubernetes-service-account`) let one role scope access with ABAC conditions such as `aws:PrincipalTag/kubernetes-namespace`
- Not supported on Fargate or Windows nodes - use IRSA there

---

**AWS EKS - IRSA (legacy; still needed for Fargate, Windows nodes and non-EKS clusters):**

Enable pods to assume IAM roles using OIDC federation.

```bash
# Step 1: Enable OIDC provider on cluster
eksctl utils associate-iam-oidc-provider --cluster=production-cluster --approve

# Step 2: Create IAM role with trust policy for ServiceAccount
# (Attach least-privilege IAM policy with specific resources only)

# Step 3: Annotate Kubernetes ServiceAccount
kubectl annotate serviceaccount api-server-sa \
  -n production \
  eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT_ID:role/api-server-role
```

**Key Points:**

- OIDC provider creates trust relationship between EKS and IAM
- Pods automatically receive temporary credentials via AWS STS
- No credentials stored in cluster or environment variables

---

**GCP GKE - Workload Identity Federation for GKE:**

Grant IAM roles directly to the Kubernetes ServiceAccount principal. A Google service account plus the `iam.gke.io/gcp-service-account` annotation is now the fallback (impersonation) for the few APIs that reject federated principals.

```bash
# Step 1: Enable Workload Identity Federation on the cluster (Autopilot: already on)
gcloud container clusters update production-cluster \
  --location=REGION \
  --workload-pool=PROJECT_ID.svc.id.goog

# Step 2: Move existing node pools to the GKE metadata server (only new pools get it automatically)
gcloud container node-pools update NODEPOOL_NAME \
  --cluster=production-cluster \
  --location=REGION \
  --workload-metadata=GKE_METADATA

# Step 3: Grant the Kubernetes ServiceAccount access to one secret (no Google service account needed)
gcloud secrets add-iam-policy-binding SECRET_NAME \
  --role="roles/secretmanager.secretAccessor" \
  --member="principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/production/sa/api-server-sa"
```

**Key Points:**

- Workload pool establishes trust between GKE and Google Cloud IAM
- No Google service account, key or annotation: the Kubernetes SA is the IAM principal
- Pods get short-lived tokens from the GKE metadata server, never a key in the pod environment

---

**Azure AKS - Microsoft Entra Workload ID:**

Use managed identities with federated credentials for pod authentication.

```bash
# Step 1: Enable the OIDC issuer and Workload Identity on the cluster
az aks update \
  --resource-group production-rg \
  --name production-cluster \
  --enable-oidc-issuer \
  --enable-workload-identity

OIDC_ISSUER_URL=$(az aks show --resource-group production-rg --name production-cluster \
  --query "oidcIssuerProfile.issuerUrl" --output tsv)

# Step 2: Create Azure managed identity
az identity create --name api-server-identity --resource-group production-rg
CLIENT_ID=$(az identity show --name api-server-identity --resource-group production-rg \
  --query clientId --output tsv)
PRINCIPAL_ID=$(az identity show --name api-server-identity --resource-group production-rg \
  --query principalId --output tsv)

# Step 3: Grant permissions to managed identity (vault must use Azure RBAC authorization)
az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" \
  --scope /subscriptions/SUB_ID/resourceGroups/production-rg/providers/Microsoft.KeyVault/vaults/prod-keyvault

# Step 4: Create federated credential for K8s ServiceAccount
az identity federated-credential create \
  --name api-server-federated \
  --identity-name api-server-identity \
  --resource-group production-rg \
  --issuer "$OIDC_ISSUER_URL" \
  --subject system:serviceaccount:production:api-server-sa \
  --audience api://AzureADTokenExchange

# Step 5: Annotate Kubernetes ServiceAccount
kubectl annotate serviceaccount api-server-sa \
  -n production \
  azure.workload.identity/client-id="$CLIENT_ID"

# Step 6: Label the pod template (the webhook only injects tokens into labelled pods)
kubectl patch deployment api-server -n production --type merge \
  -p '{"spec":{"template":{"metadata":{"labels":{"azure.workload.identity/use":"true"}}}}}'
```

**Key Points:**

- Federated credential links managed identity to K8s ServiceAccount
- Pods must carry the label `azure.workload.identity/use: "true"` or the webhook never injects the token (the SA annotation alone does nothing)
- Azure automatically handles token exchange and renewal
- Works with Azure AD-integrated resources (Key Vault, Storage, etc.)

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
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
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
# AWS: CloudTrail AssumeRoleWithWebIdentity (IRSA) or AssumeRoleForPodIdentity (Pod Identity)
# GCP: Cloud Audit Logs; enable Data Access logs for Secret Manager (off by default)
# Azure: Entra ID managed identity sign-in logs (Activity Log shows control-plane changes only)
```

## 12. Disaster Recovery

Complete environment recovery through infrastructure as code, database backups, and GitOps.

### Recovery Strategy

All critical components can be recreated from code and backups:

**Infrastructure** (Terraform):

- Terraform state stored in remote backend (S3, GCS, Azure Blob)
- Run `terraform apply` to recreate VPC, clusters, load balancers, databases in new region
- Infrastructure recreated from code in 30-60 minutes

**Databases** (Managed Services):

- Restore from automated snapshots or point-in-time recovery (15-30 minutes)
- Update Kubernetes secrets with new database endpoint after restore

**Applications** (ArgoCD):

- Point ArgoCD at Git repository
- ArgoCD automatically deploys all applications to new cluster
- Cluster state matches Git repository in 10-20 minutes

### Recovery Procedure

Complete disaster recovery steps:

1. Provision infrastructure with Terraform (30-60 minutes)
2. Restore databases from snapshots to new instances (15-30 minutes)
3. **Emergency Secret Rotation** (if compromise suspected): Rotate all secrets in vault (5-10 minutes)
   - Generate new database passwords, API keys, service account credentials
   - Update in external vault (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
   - Secrets Store CSI Driver automatically syncs new secrets to pods on restart
4. Deploy ArgoCD to new admin cluster (5 minutes)
5. ArgoCD syncs all applications to new production cluster (10-20 minutes)
6. Update DNS to point to new load balancers (5 minutes + TTL propagation)

**Validation**: Check pod status (`kubectl get pods`), authentication logs, database connectivity.

**Total RTO**: 60-120 minutes  
**RPO**: 5 minutes (database point-in-time recovery)

### Testing & Validation

**Disaster recovery drills**:

- Perform quarterly in non-production environment
- Test infrastructure recreation with Terraform
- Verify database restore procedures
- Verify ArgoCD can sync complete application state
- Document lessons learned

**Key principle**: Infrastructure as code + GitOps + automated database backups = rapid, reproducible disaster recovery.

## 13. Incident Response

Respond to security incidents in Kubernetes with structured processes for containment and recovery.

### Detection & Initial Response

**Automated Detection**:

- **Prometheus**: Resource anomalies (CPU spikes, pod crashes, restart loops)
- **Trivy Operator**: New critical vulnerabilities in running workloads
- **Kyverno**: Policy violations
- **Kubernetes Audit Logs**: Suspicious API activity (pod exec attempts, secret access)
- **Falco** (if deployed): Runtime threats (shell spawns, privilege escalation, suspicious syscalls)

**Immediate Actions for Pod Compromise**:

1. **Isolate**: Apply NetworkPolicy to block all traffic to/from compromised pod
2. **Preserve**: `kubectl logs pod-name > logs.txt` and `kubectl describe pod pod-name > details.txt`
3. **Terminate**: Delete pod (deployment recreates clean instance)
4. **Investigate**: Analyze logs, Kubernetes audit logs, and runtime alerts for attack vector

### Containment & Recovery

**Emergency Network Isolation**:

Relabel the compromised pod so its Service, ReplicaSet and existing allow policies stop selecting it (the Deployment starts a clean replacement; the pod stays for forensics), then deny all traffic to the quarantine label. NetworkPolicies are additive, so a deny-all policy cannot override allow rules that still select the pod (namespace-wide `podSelector: {}` allows, such as Section 4's DNS and istiod egress, still apply), and `podSelector: {}` would take the whole namespace offline:

```bash
kubectl label pod pod-name -n production app- quarantine=true
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-lockdown
  namespace: production
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
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

- Collect pod logs, Kubernetes audit logs, Istio service mesh logs
- Review runtime alerts (Falco if deployed, Prometheus anomalies, Kubernetes events)
- Review ArgoCD deployment history and Git commits
- Analyze Trivy vulnerability reports for exploited CVEs

**Documentation & Improvements**:

- Document timeline, attack vector, and remediation actions
- Add Kyverno policies to prevent similar attacks
- Update detection rules (Falco if deployed, Prometheus alerts) to detect similar behaviors earlier
- Notify per compliance requirements (GDPR: 72 hours, HIPAA: 60 days)

## 14. Attack Scenarios Prevented

This guide's security controls prevent real-world Kubernetes attacks commonly seen in production environments.

**Container Escape / Privilege Escalation**

- Attack: Exploiting privileged containers or dangerous capabilities to break out and access host
- Mitigated by: Kyverno blocking privileged containers/capabilities, non-root enforcement, read-only root filesystem, Kubernetes audit logs, runtime detection (Falco if deployed)

**Malicious Runtime Behavior**

- Attack: Unexpected processes spawning (crypto miners, reverse shells, data exfiltration tools)
- Mitigated by: Hardened images with package managers removed (no apt/yum/apk), non-root user enforcement, restrictive NetworkPolicies blocking egress, Istio STRICT mTLS plus AuthorizationPolicy allow-lists, Prometheus anomaly detection, runtime monitoring (Falco if deployed)

**Resource Exhaustion / DoS**

- Attack: Malicious/buggy pods consuming all cluster resources causing outages
- Mitigated by: Kyverno requiring CPU/memory limits, ResourceQuotas per namespace, pod disruption budgets, cluster autoscaling

**Lateral Movement via Network Access**

- Attack: Compromised pod used as pivot to attack other pods/services
- Mitigated by: Default-deny NetworkPolicies, Istio STRICT mTLS with `AuthorizationPolicy` allow-lists (mTLS alone does not restrict who may call whom), namespace isolation with explicit allow rules, micro-segmentation

**Database Compromise via Pod Access**

- Attack: Compromised pod used to access and exfiltrate production databases
- Mitigated by: Databases in private subnets with security groups (worker nodes only), credentials in external vaults, application database user with least privilege (non-root), limited permissions on specific tables only, multi-AZ with backups, NetworkPolicies limiting database access

**Control Plane / API Server Attack**

- Attack: Unauthorized access to Kubernetes API to modify cluster or steal secrets
- Mitigated by: Managed Kubernetes hardened control plane, API access restricted to VPN/bastion, RBAC with least privilege, audit logging

**Supply Chain Attack via Unsigned Images**

- Attack: Malicious container images pushed to registry and deployed to production
- Mitigated by: Registry authentication required for push/pull, Kyverno image signature verification (Cosign), image registry allowlist, Trivy Operator continuous scanning, SLSA provenance attestation

**Exploiting Known CVEs in Running Containers**

- Attack: Exploiting publicly disclosed vulnerabilities in outdated images
- Mitigated by: Trivy Operator continuous scanning, alerts on HIGH/CRITICAL with patches, automated image rebuilds with Copacetic, GitOps deployment

**Secrets Exposure in Pod Configs**

- Attack: Secrets leaked through environment variables, ConfigMaps, or insecure Kubernetes Secrets
- Mitigated by: External secrets management (AWS/GCP/Azure vaults), Secrets Store CSI Driver, secrets never in Git/native Secrets, Workload Identity/EKS Pod Identity (IRSA)

**Compromised ArgoCD / GitOps Repo**

- Attack: Modified GitOps repository to deploy malicious workloads or steal secrets
- Mitigated by: ArgoCD in separate admin cluster, admin access restricted to VPN/bastion, signed Git commits required, RBAC limiting deployment permissions

## 15. References

### Infrastructure & Orchestration

- [Terraform](https://developer.hashicorp.com/terraform)
- [Helm](https://helm.sh/)
- [ArgoCD](https://argo-cd.readthedocs.io/en/stable/)

### Security & Policy

- [Kyverno](https://github.com/kyverno/kyverno)
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
- [Istio](https://github.com/istio/istio)
- [Falco](https://github.com/falcosecurity/falco)
- [Cosign](https://github.com/sigstore/cosign)

### Observability

- [Prometheus](https://prometheus.io/)
- [Grafana](https://grafana.com/)
- [Fluentd](https://github.com/fluent/fluentd)

### Managed Kubernetes Services

- [AWS EKS](https://aws.amazon.com/eks/)
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
- [GCP GKE](https://cloud.google.com/kubernetes-engine)
- [Azure AKS](https://azure.microsoft.com/en-us/products/kubernetes-service/)

### Standards & Documentation

- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kyverno: Migrating to CEL Policies](https://kyverno.io/docs/guides/migration-to-cel/)
- [Ingress NGINX Retirement (Kubernetes blog, Nov 2025)](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/)
- [Ingress NGINX Statement (Kubernetes blog, Jan 2026)](https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/)
- [Gateway API](https://gateway-api.sigs.k8s.io/)
- [NIST SP 800-63B-4 Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [PCI DSS v4.0.1 (Req 8.6.3, 10.5.1)](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf)
- [HIPAA 45 CFR 164.316 (Documentation Retention)](https://www.law.cornell.edu/cfr/text/45/164.316)
- [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)

### Incident Reports

- [Weight Watchers Kubernetes Exposure (BleepingComputer, 2018)](https://www.bleepingcomputer.com/news/security/weight-watchers-it-infrastructure-exposed-via-no-password-kubernetes-server/)
- [First Dero Cryptojacking Campaign Targeting Kubernetes (CrowdStrike, 2023)](https://www.crowdstrike.com/en-us/blog/crowdstrike-discovers-first-ever-dero-cryptojacking-campaign-targeting-kubernetes/)
- [IngressNightmare: CVE-2025-1974 in Ingress NGINX (Wiz, 2025)](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
