# API Security Design Guide

**Last Updated:** September 22, 2026

A cloud-agnostic guide for building production-ready APIs with a practical blend of security and performance. This guide includes industry best practices and lessons learned from real-world implementations across serverless and traditional architectures.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Architecture Patterns](#3-architecture-patterns)
   - [Serverless vs Containers/VMs](#serverless-vs-containersvms)
   - [API Gateway Architecture](#api-gateway-architecture)
   - [Serverless Cold Start Mitigation](#serverless-cold-start-mitigation)
   - [Language Selection for Serverless](#language-selection-for-serverless)
4. [Application Security (Pre-Deployment)](#4-application-security-pre-deployment)
   - [Version Control & Branch Protection](#version-control--branch-protection)
   - [Dependency Management](#dependency-management)
   - [Secret Scanning](#secret-scanning)
   - [Static Application Security Testing (SAST)](#static-application-security-testing-sast)
   - [Pre-Deployment Checklist](#pre-deployment-checklist)
5. [Edge Security Layer](#5-edge-security-layer)
   - [WAF & DDoS Protection (Required)](#waf--ddos-protection-required)
   - [Cloudflare vs Cloud-Native WAF](#cloudflare-vs-cloud-native-waf)
   - [Origin IP Restriction (Critical)](#origin-ip-restriction-critical)
   - [Basic Rate Limiting at Edge](#basic-rate-limiting-at-edge)
6. [Authentication & Access Control](#6-authentication--access-control)
   - [Secrets Management Integration](#secrets-management-integration)
   - [CORS Configuration](#cors-configuration)
   - [Authentication & Authorization](#authentication--authorization)
   - [JWT Validation Checklist](#jwt-validation-checklist)
   - [Object-Level Authorization (BOLA)](#object-level-authorization-bola)
   - [Modern Authentication Patterns](#modern-authentication-patterns)
7. [Data Security & Input Validation](#7-data-security--input-validation)
   - [Data Encryption at Rest](#data-encryption-at-rest)
   - [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi)
   - [Encryption in Transit & TLS Requirements](#encryption-in-transit--tls-requirements)
   - [Request Validation](#request-validation)
   - [Input Sanitization](#input-sanitization)
8. [Rate Limiting & Throttling](#8-rate-limiting--throttling)
   - [Two-Layer Approach](#two-layer-approach)
   - [Rate Limit State Storage](#rate-limit-state-storage)
   - [Rate Limiting Patterns](#rate-limiting-patterns)
   - [HTTP 429 Responses](#http-429-responses)
   - [Implementation Libraries](#implementation-libraries)
9. [Error Handling & Responses](#9-error-handling--responses)
   - [Consistent Error Response Structure](#consistent-error-response-structure)
   - [HTTP Status Code Standards](#http-status-code-standards)
   - [Generic External Error Messages](#generic-external-error-messages)
   - [Detailed Internal Logging](#detailed-internal-logging)
   - [Request ID for Traceability](#request-id-for-traceability)
10. [Logging & Monitoring](#10-logging--monitoring)
    - [Audit Logging](#audit-logging)
    - [Structured Logging (JSON Format)](#structured-logging-json-format)
    - [Log Forwarding & Centralization](#log-forwarding--centralization)
    - [Log Correlation with Request IDs](#log-correlation-with-request-ids)
11. [Compliance & Retention](#11-compliance--retention)
    - [Hot Storage (30 Days)](#hot-storage-30-days)
    - [Cold Storage (Multi-Year for Compliance)](#cold-storage-multi-year-for-compliance)
    - [Compliance Considerations](#compliance-considerations)
12. [Performance Optimization](#12-performance-optimization)
    - [Batching Requests](#batching-requests)
    - [Concurrency Patterns](#concurrency-patterns)
    - [Caching Strategies](#caching-strategies)
    - [Database Performance Considerations](#database-performance-considerations)
    - [Cold Start Optimization](#cold-start-optimization)
13. [API Versioning](#13-api-versioning)
    - [Versioning Approaches](#versioning-approaches)
    - [When to Increment Versions](#when-to-increment-versions)
    - [Deprecation Strategy](#deprecation-strategy)
14. [Identity & Access Management](#14-identity--access-management)
    - [Cloud IAM Policies](#cloud-iam-policies)
    - [Service Account Management](#service-account-management)
    - [Secrets Retrieval Patterns](#secrets-retrieval-patterns)
    - [Monitoring and Auditing](#monitoring-and-auditing)
15. [Incident Response](#15-incident-response)
    - [Detection & Initial Response](#detection--initial-response)
    - [Containment & Recovery](#containment--recovery)
    - [Post-Incident](#post-incident)
16. [Attack Scenarios Prevented](#16-attack-scenarios-prevented)
17. [References](#17-references)

## 1. Overview

This guide outlines a production-grade API design approach that balances security, performance, and maintainability. The patterns are cloud-agnostic and work with major cloud providers (AWS, GCP, Azure) and their respective services for serverless functions, container orchestration, secrets management, and logging.

**Common Use Cases:**

- REST APIs for web and mobile applications
- Serverless APIs (Lambda, Cloud Run, Azure Functions)
- Microservices inter-service communication
- Third-party integrations and partner APIs
- Webhook endpoints for event notifications
- Public APIs with rate limiting and authentication

**Real-World Breaches:**

- **Optus (2022)**: An unauthenticated internet-facing API, whose access control had been broken by a coding error since 2018, let an attacker enumerate up to 9.8M customer records, including passport and driver's licence numbers
- **T-Mobile (2023)**: A single API, abused from about November 25, 2022 until it was detected in January 2023, exposed 37M postpaid and prepaid customer accounts
- **Peloton (2021)**: Unauthenticated API leaked private user data and location information
- **LinkedIn (2021)**: Unthrottled API access let scrapers assemble profile data on 700M users; no private data was exposed, but the complete dataset was sold on hacker forums

**Core Principles:**

- **Security First**: Defense in depth from edge to application to data layer
- **Performance Conscious**: Optimize for latency and throughput without compromising security
- **Cloud Agnostic**: Works across AWS, GCP, Azure with equivalent services
- **Production Ready**: Battle-tested patterns from real-world deployments
- **Simplicity Preferred**: The best infrastructure decision is often the simplest one

## 2. Prerequisites

### Required Tools

**Validation Libraries:**

- TypeScript/Node.js: [Zod](https://github.com/colinhacks/zod), [Joi](https://github.com/hapijs/joi)
- Python: [Pydantic](https://github.com/pydantic/pydantic)
- Go: [go-playground/validator](https://github.com/go-playground/validator)

**Rate Limiting Libraries:**

- TypeScript/Node.js: [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- Python: [slowapi](https://github.com/laurentS/slowapi)
- Go: [tollbooth](https://github.com/didip/tollbooth)

**Security Tools:**

- [Dependabot](https://github.com/dependabot/dependabot-core) - Automated dependency updates
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning
- [Semgrep](https://semgrep.dev/), [Opengrep](https://github.com/opengrep/opengrep) or [Aikido Security](https://www.aikido.dev/) - Static application security testing (SAST)

### External Services

Cloud-agnostic service options for secrets management, logging, storage, and edge protection.

| Service Category                  | AWS                               | GCP                                | Azure                                    | Self-Hosted / Open Source              |
| --------------------------------- | --------------------------------- | ---------------------------------- | ---------------------------------------- | -------------------------------------- |
| **Secrets Management** (required) | Secrets Manager                   | Secret Manager                     | Key Vault                                | HashiCorp Vault                        |
| **Logging & SIEM** (required)     | CloudWatch Logs                   | Cloud Logging                      | Monitor                                  | Splunk, ELK Stack, Loki                |
| **Cold Storage** (compliance)     | S3 Glacier / Glacier Deep Archive | Coldline Storage / Archive Storage | Cool Blob Storage / Archive Blob Storage | -                                      |
| **Edge Protection** (required)    | CloudFront + AWS WAF              | Cloud Armor + Cloud CDN            | Front Door + Azure WAF                   | Cloudflare (Free tier with WAF + DDoS) |
| **Rate Limiting State**           | DynamoDB                          | Firestore                          | Cosmos DB                                | Redis (any cloud or self-hosted)       |

**Notes:**

- **Secrets Management**: Required for storing API keys, database credentials, and sensitive configuration
- **Cold Storage**: Needed for long log retention (PCI DSS: 12 months; HIPAA documentation: 6 years); GDPR sets no minimum and limits retention to what is necessary
- **Edge Protection**: Cloudflare works across all cloud providers and offers free tier with basic WAF + DDoS protection
- **Rate Limiting State**: Redis is recommended for fastest performance and works with any cloud provider

## 3. Architecture Patterns

### Serverless vs Containers/VMs

Choose the deployment model that matches your application's latency, traffic patterns, and operational requirements.

| Aspect                   | Serverless (Lambda, Cloud Run functions, Azure Functions)    | Containers/VMs (ECS, GKE, AKS, EC2)                    |
| ------------------------ | ------------------------------------------------------------ | ------------------------------------------------------ |
| **Management**           | Fully managed - no provisioning, patching, or scaling config | Manual provisioning, patching, monitoring, scaling     |
| **Security**             | Ephemeral environments reduce attack surface                 | Requires ongoing security maintenance                  |
| **Latency**              | Cold start: 100ms-3s (depending on language)                 | No cold starts - consistently low latency              |
| **Scaling**              | Automatic, instant scale-to-zero                             | Requires autoscaling configuration                     |
| **Cost Model**           | Pay-per-invocation (cost-effective for sporadic traffic)     | Reserved capacity (better for consistent high traffic) |
| **Workload Support**     | Event-driven, stateless only                                 | Supports stateful services, WebSockets, streaming      |
| **Connection Handling**  | No persistent connections                                    | Connection pooling, long-lived connections             |
| **Operational Overhead** | Minimal (ideal for small teams)                              | Higher (requires DevOps expertise)                     |

**Use Serverless When:**

- Event-driven workloads with sporadic or unpredictable traffic
- Can tolerate 100-500ms cold start latency
- Team lacks dedicated DevOps resources
- Want to minimize operational complexity
- **You have <50 engineers (RECOMMENDED for most teams)**
- **Your traffic is <10M requests/month**
- **You want to focus on product, not infrastructure**

**Use Containers/VMs When:**

- Latency-critical applications requiring <50ms response time
- Stateful services (WebSockets, streaming, persistent connections)
- High, consistent traffic patterns where reserved capacity is cheaper
- Need full control over runtime environment
- You have 50+ engineers with dedicated platform/DevOps team

**Cost Reality Check:**

| Deployment Model                  | Monthly Cost | Operational Team | Best For                      |
| --------------------------------- | ------------ | ---------------- | ----------------------------- |
| **Serverless** (Lambda/Cloud Run) | $0-50        | 0-1 engineers    | Startups, MVPs, <50 engineers |
| **Fargate/Managed Containers**    | $100-500     | 1-2 engineers    | WebSockets, 10-50 engineers   |
| **Kubernetes**                    | $500-2000+   | 3-5 engineers    | 50+ services, 50+ engineers   |

**Reality:** A single Lambda function can handle 10M+ requests/month for ~$50. Your startup will run out of money debugging Kubernetes networking before you need horizontal pod autoscaling.

**Recommendation:** Start with serverless. Migrate to containers only when you have concrete evidence that serverless limitations are blocking your business (persistent connections needed, cold starts impacting UX, costs exceed Fargate at scale).

### API Gateway Architecture

**Why API Gateways are Critical:**

Modern production APIs should use an API Gateway as a centralized control plane rather than implementing cross-cutting concerns in every microservice. Without a gateway, teams duplicate authentication, rate limiting, logging, and circuit breaking logic across services, leading to inconsistencies and security gaps.

**What API Gateways Handle:**

- **Authentication & Authorization**: Centralized JWT validation, OAuth flows, API key management
- **Rate Limiting**: Distributed rate limiting with shared state (per-user, per-endpoint)
- **Request Routing**: Intelligent routing based on headers, paths, or request attributes
- **Circuit Breaking**: Automatic failover when backend services are unhealthy
- **Traffic Management**: Canary deployments, A/B testing, blue-green deployments
- **Observability**: Centralized logging, metrics, distributed tracing
- **Request/Response Transformation**: Header injection, payload mapping, protocol translation
- **Security**: TLS termination, input validation, WAF integration

**Cloud-Native API Gateway Options:**

- **AWS**: API Gateway (serverless), Application Load Balancer (ALB) with Lambda targets
- **GCP**: Cloud Endpoints, API Gateway, Cloud Load Balancing
- **Azure**: API Management, Application Gateway

**Open Source / Self-Hosted:**

- **[Kong](https://github.com/Kong/kong)**: Battle-tested, plugin ecosystem, high performance
- **[Tyk](https://github.com/TykTechnologies/tyk)**: API management with analytics
- **[Envoy](https://github.com/envoyproxy/envoy)**: High-performance proxy (powers Istio)
- **[Traefik](https://github.com/traefik/traefik)**: Modern, dynamic configuration

**Architecture Pattern:**

```
Client Request
    ↓
[Edge Layer: Cloudflare/CloudFront + WAF]
    ↓ (basic DDoS protection, 100-2000 req/min per IP)
[API Gateway Layer]
    ↓ (authentication, fine-grained rate limiting, routing)
[Backend Services: Serverless/Containers]
    ↓ (business logic only)
[Data Layer: Managed databases]
```

**Centralized Authentication Example (Kong):**

```yaml
# Kong declarative config (kong.yml) - top-level plugins are global (all routes)
_format_version: "3.0"
plugins:
  - name: jwt
    config:
      key_claim_name: kid
      secret_is_base64: false
      # jwt plugin verifies only exp/nbf; validate iss and aud
      # in the service (or with an OpenID Connect plugin)
      claims_to_verify:
        - exp
        - nbf
  - name: rate-limiting
    config:
      minute: 100
      policy: redis
      redis:
        host: redis.internal
        port: 6379
```

**Benefits of Gateway Architecture:**

- **Single Point of Enforcement**: Auth and rate limiting rules in one place, not scattered across services
- **Reduced Backend Complexity**: Services focus on business logic, not cross-cutting concerns
- **Centralized Observability**: All API traffic visible in one location
- **Simplified Compliance**: Audit logs and access controls managed centrally
- **Better Performance**: Connection pooling, caching, compression at gateway layer

**When to Use API Gateway:**

- Microservices architecture with 3+ backend services
- Need centralized authentication across multiple APIs
- Multiple teams deploying independent services
- Complex routing or traffic management requirements
- Enterprise compliance and audit requirements

**When Direct Load Balancer Might Suffice:**

- Single monolithic application
- Simple authentication model
- Small team managing one codebase
- Cost-sensitive early-stage product

**Implementation Recommendation:**

For production systems with multiple services, deploy an API Gateway between your edge layer (Cloudflare/WAF) and backend services. This architectural pattern is industry standard and eliminates the anti-pattern of duplicating security logic across every microservice.

### Serverless Cold Start Mitigation

**Provisioned Concurrency**:

- Pre-warm instances (eliminates cold starts, higher cost)
- AWS Lambda Provisioned Concurrency
- GCP Cloud Run functions (formerly Cloud Functions) minimum instances

**Scheduled Invocations**:

- Ping functions every 5-10 minutes to keep warm
- AWS EventBridge Scheduler, GCP Cloud Scheduler, Azure Timer Triggers
- Invoke lightweight health check endpoint

### Language Selection for Serverless

Choose a language that balances cold start performance, developer productivity, and team expertise.

| Language               | Cold Start                         | Key Strengths                                                                      | Best For                                                                       | Ecosystem                                     |
| ---------------------- | ---------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------- |
| **Go** ⭐              | 150-250ms                          | Compiled binaries, built-in concurrency (goroutines), strong dependency management | **Recommended default** - best balance of performance and developer experience | Excellent for APIs, microservices             |
| **Rust**               | 100-200ms                          | Fastest performance, memory safety guarantees, no runtime overhead                 | Ultra-low latency requirements, cost optimization at scale                     | Steep learning curve, smaller ecosystem       |
| **TypeScript/Node.js** | 200-500ms                          | Rapid development, massive npm ecosystem, shared frontend/backend code             | Full-stack JavaScript teams, high developer velocity, I/O-heavy workloads      | Largest ecosystem, familiar to web developers |
| **Python**             | 200-500ms                          | Excellent data/ML libraries (NumPy, Pandas, scikit-learn), simple syntax           | Data processing, ML inference, teams familiar with Python                      | Massive ecosystem for data science            |
| **Java** ⚠️            | 2-3s (or 200-400ms with SnapStart) | Enterprise ecosystem, mature tooling, type safety                                  | **Only use** with SnapStart/GraalVM native images or in containers/VMs         | Large enterprise ecosystem, slow cold starts  |

**Key Considerations:**

- **Cold Start Impact**: Choose Go or Rust if cold starts are critical (real-time APIs, user-facing endpoints)
- **Team Expertise**: Use language team already knows well - productivity matters more than 100ms difference
- **Ecosystem Needs**: Python for data/ML, TypeScript for full-stack teams, Go for general-purpose APIs
- **Avoid Java** in serverless without mitigation (SnapStart) - 2-3 second cold starts harm user experience

**Recommendation**: Start with **Go** for most serverless APIs - excellent cold start times, strong concurrency, and great balance of performance and maintainability.

## 4. Application Security (Pre-Deployment)

Secure your codebase before deployment using automated security tools in CI/CD pipeline.

### Version Control & Branch Protection

- Use prod, staging, dev branches with protection on main
- Require PR reviews (minimum 1 person) before merge
- Prevent direct commits to protected branches
- Require status checks to pass (SAST, secret scanning, tests)
- Platforms: GitHub, GitLab, Bitbucket, Azure DevOps

### Dependency Management

[Dependabot](https://github.com/dependabot/dependabot-core):

- Automated dependency updates via pull requests
- Scans for vulnerable dependencies (npm, pip, go.mod, Maven, etc.)
- Creates PRs with security patches, version bumps, and changelogs
- Catches known vulnerabilities before production
- Available on GitHub (built-in), GitLab, and self-hosted
- Configure for daily or weekly scans, merge PRs promptly

### Secret Scanning

Prevent hardcoded secrets (API keys, passwords, tokens) from being committed.

**TruffleHog**:

- Scans Git history for high-entropy strings and known secret patterns
- Detects 800+ secret types (AWS keys, GCP service accounts, API tokens)
- Run as pre-commit hook or in CI/CD pipeline
- Command: `trufflehog git file://. --results=verified,unknown` (`--results=verified` replaces the hidden legacy flag `--only-verified`; `unknown` keeps hits whose verification call failed)

**GitHub Secret Scanning**:

- Built-in to GitHub: free for public repos (alerts + push protection); private repos need the GitHub Secret Protection add-on ($19/active committer/month, Team and Enterprise Cloud plans since April 2025)
- Automatically scans commits for known secret patterns
- Partners with cloud providers (AWS, GCP, Azure) to revoke leaked credentials

Use [pre-commit](https://pre-commit.com/) framework to run TruffleHog before commits reach remote.

### Static Application Security Testing (SAST)

**Semgrep vs Opengrep vs Aikido:**

- **[Semgrep Community Edition](https://github.com/semgrep/semgrep)** (Free, LGPL-2.1): Open-source engine, single-file analysis, more false positives
- **[Semgrep AppSec Platform](https://semgrep.dev/pricing)** (Free for up to 10 contributors and 10 repos, then Teams from $30/contributor/month): Cross-file dataflow with Pro rules, AI-assisted detection, triage and remediation
- **[Opengrep](https://github.com/opengrep/opengrep)** (Free, LGPL-2.1): Fork of Semgrep CE launched January 2025 by Aikido Security with Endor Labs, Orca and other vendors; runs Semgrep rules unchanged, no hosted registry and no AI; install from the install script or a release binary (not pip)
- **[Aikido Security](https://www.aikido.dev/)** (Free Developer plan: 2 users, 10 repos; paid from $300/month): One platform for SAST (its own engine plus Opengrep, with AI false-positive reduction), dependency scanning (SCA), secrets, IaC, container and cloud scanning. The free plan blocks PRs only on dependency findings; blocking on SAST or IaC findings needs a paid plan

**Recommendation:** Start with Opengrep (free) or Aikido's free tier (SAST plus dependency, secret and IaC scanning in one place). Pay for Semgrep or Aikido when triage noise costs more than the licence.

**All of them:**

- Scan source code for security vulnerabilities
- Detect: SQL injection, XSS, insecure crypto, authentication issues, hardcoded secrets
- Support 30+ languages (JavaScript, Python, Go, Java, C#, etc.)
- Run in CI/CD on every PR: `semgrep scan --config auto` (pulls rules from Semgrep's registry at run time) or `opengrep scan -f ./rules .` against a pinned checkout of [opengrep-rules](https://github.com/opengrep/opengrep-rules) (`--config auto` and `p/...` packs are Semgrep registry features). Aikido gates PRs through its GitHub/GitLab app instead of a CI step

**Common SAST Rules:**

- No hardcoded credentials or API keys
- No insecure cryptographic functions (MD5, SHA1 for passwords)
- Proper input validation and sanitization
- Parameterized SQL queries only
- No dangerous functions (eval, exec, system calls with user input)

### Pre-Deployment Checklist

- ✓ Dependabot enabled and updates merged
- ✓ Secret scanning active (TruffleHog + GitHub Secret Scanning)
- ✓ SAST scans pass (no critical/high findings)
- ✓ Code reviewed (minimum 1 person)
- ✓ All tests pass
- ✓ Branch protection enforced

## 5. Edge Security Layer

Deploy WAF and DDoS protection at the edge to filter malicious traffic before it reaches your API. Never expose origin servers directly to the internet.

### WAF & DDoS Protection (Required)

**Web Application Firewall (WAF)**:

- Protects against OWASP Top 10 (SQL injection, XSS, etc.)
- Blocks common attack patterns and malicious payloads
- Filters bot traffic and credential stuffing

**DDoS Protection**:

- Defends against Layer 3/4 network floods (SYN, UDP)
- Mitigates Layer 7 application-layer attacks
- Handles volumetric attacks

### Cloudflare vs Cloud-Native WAF

Choose between Cloudflare's multi-cloud solution or cloud-native WAF based on your deployment strategy.

| Feature                 | Cloudflare                                      | Cloud-Native (AWS/GCP/Azure)                     |
| ----------------------- | ----------------------------------------------- | ------------------------------------------------ |
| **Cost**                | Free tier available with basic WAF + DDoS       | Pay per rule + per request                       |
| **Multi-Cloud Support** | Works across all cloud providers                | Locked to single provider                        |
| **Failure Dependency**  | Separate service (additional point of failure)  | Single cloud dependency (no dual failure risk)   |
| **Cloud Integration**   | Generic HTTP/DNS integration                    | Native integration with cloud services           |
| **Setup Complexity**    | Simple DNS change                               | Requires cloud-specific configuration            |
| **Best For**            | Multi-cloud deployments, budget-conscious teams | Single cloud commitment, tight integration needs |

**Recommendation:**

- **Use Cloudflare** if you're multi-cloud, need a free tier, or want flexibility to change cloud providers
- **Use Cloud-Native** if you're committed to a single cloud provider and want native service integration

**Key Insight:** Cloud-native WAF means if your cloud provider goes down, your entire stack fails together (not twice the failure risk from having two separate services).

### Origin IP Restriction (Critical)

Configure firewall rules to allow traffic ONLY from edge provider IP ranges:

- Prevents attackers from bypassing edge protection by hitting origin directly
- Attackers can discover origin IPs via DNS history, SSL certificates, etc.
- Cloudflare IPs: https://www.cloudflare.com/ips/
- Cloud-native: Use security groups/firewall rules to allow only load balancer traffic
- IP allowlisting alone isn't enough: any Cloudflare or CloudFront customer can reach your origin through the same IPs. Also authenticate the edge (Cloudflare Authenticated Origin Pulls with your own certificate or Cloudflare Tunnel; a secret origin header or VPC origins on CloudFront)

### Basic Rate Limiting at Edge

Implement aggressive catch-all rate limiting for DDoS mitigation:

- Cloudflare: 1,000 requests per 10 seconds per IP (Free plan: 1 rule, 10-second window only)
- AWS WAF: 2,000 requests per 5 minutes per IP
- GCP Cloud Armor: 1,000 requests/minute per IP
- Azure WAF: 100 requests/minute per IP

Edge rate limiting should be basic and aggressive. Fine-grained, business-logic-aware rate limiting happens at application layer.

## 6. Authentication & Access Control

Secure API access through proper authentication, authorization, and cross-origin resource sharing.

### Secrets Management Integration

Store all sensitive credentials in external secrets manager - never hardcode or use environment variables:

- AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault
- Application retrieves secrets at runtime using IAM roles/service accounts
- Serverless: Fetch on cold start with SDK caching
- Containers: Fetch on startup, rotate periodically

### CORS Configuration

Configure Cross-Origin Resource Sharing for frontend API calls - never use wildcard (`*`):

- Specify exact allowed origins only
- Load the allowlist per environment: production gets production origins only; add `http://localhost:3000` in development only
- Example production allowlist: `https://example.com`

**TypeScript/Node.js example:**

```javascript
const allowedOrigins =
  process.env.NODE_ENV === "production"
    ? ["https://example.com"]
    : ["https://example.com", "http://localhost:3000"];
// Pass the array: cors sets Access-Control-Allow-Origin only for listed origins
// and omits it otherwise. Never reject requests with no Origin header (same-origin
// GETs, curl, mobile apps, health checks) - CORS is a browser policy, not auth.
app.use(cors({ origin: allowedOrigins }));
```

### Authentication & Authorization

Choose the authentication method that matches your API's security requirements and integration needs.

| Method                      | Use Case                          | Pros                                                   | Cons                                             | Implementation Complexity |
| --------------------------- | --------------------------------- | ------------------------------------------------------ | ------------------------------------------------ | ------------------------- |
| **JWT (RS256)**             | User authentication, session mgmt | Stateless, self-contained, widely supported            | Revocation difficult, token size, key management | Medium                    |
| **API Keys**                | Service-to-service, public APIs   | Simple, fast validation, easy rotation                 | No user context, long-lived, theft risk          | Low                       |
| **OAuth 2.0 + OIDC**        | Third-party integrations, SSO     | Industry standard, delegated auth, user consent        | Complex flow, token refresh, requires IdP        | High                      |
| **mTLS (Mutual TLS)**       | Service mesh, internal services   | Strong cryptographic auth, no token theft              | Certificate management, client setup complexity  | High                      |
| **HMAC Signatures**         | Webhooks, API request signing     | Request integrity, replay protection (timestamp/nonce) | Shared secret on both sides, clock sync required | Medium                    |
| **Basic Auth (deprecated)** | Legacy systems only               | Simple                                                 | Credentials in every request, no expiration      | Low (avoid)               |

**OAuth/JWT Token Validation**:

Validate authentication tokens on every protected endpoint:

- Verify Bearer token in `Authorization` header
- Validate signature, expiration (exp), issuer (iss), audience (aud)
- Return 401 Unauthorized if missing, invalid, or expired
- Extract user context (ID, roles, permissions) for authorization
- Use provider SDKs: AWS Cognito, GCP Identity Platform, Auth0, Firebase Auth

### JWT Validation Checklist

JWT auth bypass is common due to incomplete validation. Validate all claims:

**Minimum validation required:**

```javascript
// Node.js example - adapt to your language
const jwt = require("jsonwebtoken");

function validateToken(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"], // Prevent algorithm confusion
    issuer: "https://auth.yourcompany.com", // Must match your auth server
    audience: "your-api-id", // Must match your API
    clockTolerance: 30, // Allow 30s clock skew
  });
  // Library validates exp (expiration) automatically
}
```

**Critical vulnerabilities to prevent:**

1. **Algorithm confusion**: Always specify `algorithms: ['RS256']`, never accept `none`
2. **Missing issuer check**: Token from evil.com shouldn't work on yourapi.com
3. **Missing audience check**: Token for api-a shouldn't work on api-b
4. **No signature verification**: Never use `jwt.decode()` - always `jwt.verify()`

**Best practices:**

- Use RS256 (asymmetric), not HS256 (symmetric) for APIs
- Keep access tokens short-lived (15 minutes)
- Never put sensitive data in JWT payload (it's base64-encoded, not encrypted)
- Cache public keys, don't fetch on every request

**Test your validation:** Try using an expired token, wrong audience, or tampered signature - all should be rejected.

### Object-Level Authorization (BOLA)

Authentication answers "who are you"; it says nothing about which records you may touch. Broken Object Level Authorization has been #1 on the OWASP API Security Top 10 since 2019: the client sends `GET /orders/1234`, the API checks the token and returns the order without checking that the caller owns it. Change the ID, read someone else's data.

**Rules:**

- Every handler that takes an ID from the client scopes the query to the caller (`WHERE id = ? AND owner_id = ?`) or checks ownership before acting - no exceptions for "internal" endpoints
- Return 403 (or 404 when even the object's existence is sensitive) - pick one and be consistent
- Use random IDs (UUIDv4/ULID) so IDs cannot be enumerated - defense in depth, not the control
- Write one test per endpoint that requests another user's object with a valid token and expects rejection

```python
# FastAPI - the ownership check lives in the query, not as an afterthought
@app.get("/orders/{order_id}")
async def get_order(order_id: UUID, user=Depends(current_user)):
    order = await db.fetch_one(
        "SELECT * FROM orders WHERE id = :id AND owner_id = :uid",
        {"id": order_id, "uid": user.id},
    )
    if not order:
        raise HTTPException(status_code=404)
    return order
```

### Modern Authentication Patterns

Implement secure authentication flows beyond basic JWT validation for production-grade systems.

---

**OAuth 2.1 / OIDC Flow** (recommended for APIs):

```
1. Client creates a PKCE code_verifier, redirects to auth server (e.g., Auth0, AWS Cognito) with its S256 code_challenge
2. User authenticates → Auth server issues authorization code
3. Client exchanges code + code_verifier for tokens:
   - Access token (short-lived, 15 min): API access
   - Refresh token (long-lived, capped at the absolute session timeout, e.g. 7 days): Get new access tokens
   - ID token (OIDC): User identity claims
4. Client calls API with access token in Authorization header
5. When access token expires, use refresh token to get new access token
```

---

**Refresh Token Rotation:**

Limits the damage of a stolen refresh token: each token works once, and reuse of a spent token signals theft (RFC 9700 §4.14.2).

```javascript
// Token refresh endpoint
app.post("/auth/refresh", async (req, res) => {
  const { refresh_token } = req.body;

  // Consume atomically (e.g. UPDATE ... SET used = true WHERE token = $1
  // AND used = false RETURNING ...) so concurrent requests can't both redeem it
  const session = await consumeRefreshToken(refresh_token);
  if (!session) {
    // Unknown or already-used token: treat reuse as theft
    await revokeTokenFamily(refresh_token);
    return res.status(401).json({ error: "Invalid token" });
  }

  // Issue new access + refresh tokens (same token family)
  const newAccessToken = generateAccessToken(session.userId);
  const newRefreshToken = generateRefreshToken(
    session.userId,
    session.familyId,
  );

  res.json({
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    expires_in: 900, // 15 minutes
  });
});
```

**Session Management Best Practices:**

| Aspect                  | Implementation                                     | Security Benefit             |
| ----------------------- | -------------------------------------------------- | ---------------------------- |
| **Token storage**       | httpOnly + Secure + SameSite cookies, CSRF defense | XSS can't read/steal tokens  |
| **Session tracking**    | Redis with user ID, device info, IP, last activity | Enables anomaly detection    |
| **Concurrent sessions** | Limit 3-5 active sessions, revoke oldest           | Prevents credential sharing  |
| **Session timeout**     | Absolute (7 days) + idle (30 min)                  | Reduces exposure window      |
| **Logout**              | Revoke access + refresh tokens, clear server state | Complete session termination |

---

**Multi-Factor Authentication (MFA):**

Require second factor after password validation for high-security scenarios.

```javascript
// After password validation, require MFA
if (user.mfa_enabled) {
  // Ask for the TOTP code from the user's authenticator app (generated on-device,
  // not sent). SMS OTP is a weaker, NIST-restricted fallback.
  const mfaToken = generateMFAToken(user.id);

  return res.json({
    requires_mfa: true,
    mfa_token: mfaToken, // Temporary token to validate MFA
  });
}

// MFA verification endpoint
app.post("/auth/verify-mfa", async (req, res) => {
  const { mfa_token, code } = req.body;

  // mfa_token: short-lived (≤5 min), single-use
  const userId = await validateMFAToken(mfa_token);
  if (!userId) return res.status(401).json({ error: "Invalid code" });

  // Cap guesses: a 6-digit code falls to brute force without a limit
  const tries = await redis.incr(`mfa:attempts:${userId}`);
  if (tries === 1) await redis.expire(`mfa:attempts:${userId}`, 900);
  if (tries > 5) return res.status(429).json({ error: "Too many attempts" });

  // Must reject a code already accepted in its time step (RFC 6238 §5.2)
  const isValid = await verifyTOTP(userId, code);

  if (!isValid) return res.status(401).json({ error: "Invalid code" });

  // Issue full access + refresh tokens after MFA
  const tokens = generateTokens(userId);
  res.json(tokens);
});
```

---

**Passwordless Authentication (WebAuthn/FIDO2):**

Modern alternative to passwords using hardware security keys or biometrics.

**Benefits:**

- Phishing-resistant (cryptographic challenge-response)
- No password storage/management required
- Works with browser WebAuthn API or mobile biometrics

**Implementation:**

- Node.js: `SimpleWebAuthn` library
- Python: [py_webauthn](https://github.com/duo-labs/py_webauthn) (`pip install webauthn`)

---

**Account Lockout & Brute Force Protection:**

Prevent credential stuffing and brute force attacks with rate limiting on login attempts.

```javascript
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Refuse while locked (the lock must be checked, not only written)
  if (await redis.exists(`login:locked:${email}`)) {
    return res.status(429).json({
      error: "Too many failed attempts. Try again in 15 minutes.",
    });
  }

  const ok = await verifyPassword(email, password);
  if (!ok) {
    // Count failures in a fixed 10 min window (EXPIRE only on the first hit)
    const attempts = await redis.incr(`login:attempts:${email}`);
    if (attempts === 1) await redis.expire(`login:attempts:${email}`, 600);

    if (attempts >= 5) {
      // Lock for 15 minutes. Pair with the per-IP /login limit so an
      // attacker cannot lock victims out on purpose
      await redis.setex(`login:locked:${email}`, 900, "1");
      return res.status(429).json({
        error: "Too many failed attempts. Try again in 15 minutes.",
      });
    }
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // On successful login, reset attempts
  await redis.del(`login:attempts:${email}`);
  // ...issue tokens
});
```

---

**Token Revocation:**

Implement token blacklist for immediate logout during security incidents.

```javascript
// Revoke token on logout (tokens must be issued with a jti claim)
app.post("/auth/logout", authenticate, async (req, res) => {
  // authenticate ran jwt.verify(); never act on jwt.decode() output
  const { jti, exp } = req.user;

  // Add to blacklist until token would naturally expire
  const ttl = exp - Math.floor(Date.now() / 1000);
  if (ttl > 0) await redis.setex(`blacklist:${jti}`, ttl, "1");

  res.json({ message: "Logged out successfully" });
});

// Middleware to check blacklist (runs after jwt.verify)
async function checkBlacklist(req, res, next) {
  const isBlacklisted = await redis.exists(`blacklist:${req.user.jti}`);

  if (isBlacklisted) {
    return res.status(401).json({ error: "Token revoked" });
  }
  next();
}
```

---

**Defense-in-Depth Strategy:**

Combine multiple patterns for comprehensive authentication security:

✓ Short-lived access tokens (15 min)  
✓ Refresh token rotation (one-time use)  
✓ Multi-factor authentication (TOTP/WebAuthn)  
✓ Session limits (3-5 concurrent)  
✓ Token blacklist capability (immediate revocation)

## 7. Data Security & Input Validation

Protect sensitive data at rest and prevent injection attacks through comprehensive validation and sanitization.

### Data Encryption at Rest

Encrypt sensitive data before storing in databases to protect against database breaches, stolen backups, and insider threats.

**Managed Database Encryption** (baseline protection):

Enable encryption at database creation - protects against physical disk theft and unauthorized disk access:

- AWS RDS: `storage_encrypted = true` with optional KMS key
- GCP Cloud SQL: Enable disk encryption with customer-managed keys
- Azure Database: Transparent Data Encryption (TDE) enabled by default

**Application-Level Encryption** (for sensitive PII/PHI/PCI data):

Encrypt sensitive fields in application code (AES-256-GCM, envelope encryption with cloud KMS) before writing to the database. The pattern, libraries, and schema caveats are in [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi) below.

**Why both layers**:

- Managed DB encryption: Compliance baseline, protects data on disk
- Application-level encryption: Protects against DBAs, SQL injection, credential compromise, stolen backups

**When application-level encryption is required**:

- PCI DSS stored PAN (disk-level encryption alone doesn't satisfy Req 3.5.1 on non-removable media, per 3.5.1.2)
- HIPAA PHI and highly sensitive PII when your risk analysis calls for it (HIPAA treats encryption as addressable)
- Zero-trust requirements (don't trust cloud admins or DBAs)
- Multi-tenant SaaS with customer-managed encryption keys
- Regulatory requirements for end-to-end encryption

### Field-Level Encryption for PII/PHI

For highly sensitive data (PII, PHI, PCI), encrypt specific fields in application code before storing in database using envelope encryption with cloud KMS.

**When to use:**

- PII: SSNs, passport numbers, driver's license numbers
- PHI: Medical records, diagnoses, prescriptions
- PCI: Credit card numbers, CVV codes
- Compliance drivers: PCI DSS requires stored PAN on non-removable media to be protected beyond disk encryption (Req 3.5.1.2); GDPR (Art. 32) and HIPAA treat encryption as a risk-based measure

**Envelope Encryption Pattern:**

```
User Data → Encrypt with Data Encryption Key (DEK)
DEK → Encrypt with Key Encryption Key (KEK) from KMS
Store: Encrypted data + Encrypted DEK in database
```

**Implementation:**

- Use cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault) to generate and manage encryption keys
- Libraries: AWS Encryption SDK, Google Tink, Azure SDK
- Encrypt only necessary fields (SSN, credit cards), not entire records
- Encrypted fields cannot be queried/indexed - plan schema accordingly
- Rotate KEK annually in KMS

**Defense in depth:** Even if attackers gain database access, they cannot decrypt sensitive fields without KMS permissions.

### Encryption in Transit & TLS Requirements

Encrypt all network communication to protect data as it travels between clients, edge services, application servers, and databases.

**TLS Version Requirements**:

- **TLS 1.3** (Recommended): Faster handshake, improved security, removed weak ciphers
- **TLS 1.2** (Acceptable): Use as fallback for legacy client compatibility
- **Disable TLS 1.0/1.1**: Formally deprecated by RFC 8996 (2021) because they depend on SHA-1/MD5 and lack modern AEAD ciphers (POODLE is an SSL 3.0 attack; BEAST targets TLS 1.0 CBC)

Prefer TLS 1.3 for all modern clients (browsers, mobile apps, API clients). Use TLS 1.2 fallback only if analytics show significant traffic from legacy systems.

**Edge-to-Origin TLS Configuration**:

**Cloudflare Setup**:

- **Client → Cloudflare**: Cloudflare's SSL certificate (automatic, managed by Cloudflare)
- **Cloudflare → Origin Server**: Origin server's SSL certificate (Cloudflare Origin CA certificate or a publicly trusted one; self-signed certificates fail Full (strict) validation)
- **SSL Mode**: Set to **Full (strict)** in the Cloudflare dashboard (**Strict (SSL-Only Origin Pull)** is Enterprise-only)
  - Validates origin certificate and prevents man-in-the-middle attacks
  - Never use **Flexible** mode (Cloudflare → Origin uses unencrypted HTTP)
- **Why this matters**: Traffic between Cloudflare edge and origin traverses the internet, encryption is mandatory

**Cloud-Native Load Balancer** (AWS ALB, GCP Load Balancing, Azure Application Gateway):

Two approaches depending on security requirements:

1. **TLS Termination at Load Balancer** (most common):

   - Load balancer has public certificate (AWS ACM, GCP Certificate Manager, Azure certificates)
   - Load balancer terminates TLS, forwards HTTP to origin in private subnet
   - **Acceptable when**: Origin isolated in private VPC, strict security groups, no compliance requirements
   - Simpler configuration, no certificate management on origin

2. **End-to-End TLS** (compliance scenarios):
   - Both load balancer and origin have certificates, HTTPS throughout
   - **Use for**: zero-trust architecture, or where your HIPAA/PCI DSS risk assessment or auditor expects it (PCI DSS 4.2.1 mandates strong crypto only over open, public networks)
   - Defense in depth - traffic encrypted even within VPC

**Database Connection Encryption**:

Always enforce SSL/TLS for database connections to prevent credential exposure:

- **AWS RDS**: PostgreSQL: set `rds.force_ssl = 1` in the parameter group (default on for PostgreSQL 15+); MySQL/MariaDB: set `require_secure_transport = ON`. Connect with `sslmode=verify-full` plus the RDS CA bundle (`sslrootcert=`)
- **GCP Cloud SQL**: `gcloud sql instances patch INSTANCE --ssl-mode=ENCRYPTED_ONLY` (the legacy "Require SSL" / `require-ssl` flag is superseded by `ssl_mode`), download the server CA certificate
- **Azure Database**: Set `require_secure_transport = ON`, use SSL connection string parameter

Example connection strings:

```python
# PostgreSQL: verify-full encrypts AND checks the server certificate + hostname (sslmode=require only encrypts)
DATABASE_URL = "postgresql://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/etc/ssl/certs/provider-ca.pem"

# MySQL (SQLAlchemy + mysqlclient): VERIFY_IDENTITY checks certificate + hostname (REQUIRED only encrypts)
DATABASE_URL = "mysql+mysqldb://user:pass@host:3306/db?ssl_mode=VERIFY_IDENTITY&ssl_ca=/etc/ssl/certs/provider-ca.pem"
```

**Service-to-Service Communication**:

- **Kubernetes deployments**: Use a service mesh such as Istio for mTLS between pods; Istio auto-upgrades mesh traffic but accepts plaintext (PERMISSIVE) until you apply a `PeerAuthentication` with `mode: STRICT` (see Kubernetes Security Guide)
- **Non-Kubernetes**: Internal API calls should use HTTPS or be isolated in private network with strict access controls
- **External third-party APIs**: Always use HTTPS, validate TLS certificates, enforce TLS 1.2+ minimum

**Certificate Management**:

- Use managed certificates with automatic renewal: Let's Encrypt (free), AWS ACM, GCP Certificate Manager, Azure certificates
- Set HSTS header `Strict-Transport-Security: max-age=31536000; includeSubDomains` to force HTTPS in browsers
- Automate rotation for origin certificates (30-90 day validity recommended)
- **Certificate lifetimes are shrinking**: CA/Browser Forum ballot SC-081v3 caps public TLS certificates at 200 days since March 15, 2026, 100 days from March 15, 2027, and 47 days from March 15, 2029. Manual renewal is already dead - anything not on ACME or a managed certificate service (ACM, GCP Certificate Manager, Azure App Service certificates) will expire in production. Inventory every public certificate now, including load balancers, mail and VPN endpoints

### Request Validation

**HTTP Method Validation**:

Validate HTTP method matches endpoint requirements before processing any request. Return **405 Method Not Allowed** for incorrect methods:

- **GET**: Read-only operations, no request body expected
- **POST**: Create new resources, requires request body
- **PUT/PATCH**: Update existing resources, requires request body
- **DELETE**: Remove resources, typically no body

Configure your web framework or API gateway to enforce method restrictions per endpoint. Many frameworks provide decorators or middleware for this:

```python
# Python FastAPI example
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    name: str
    email: str

@app.get("/users/{user_id}")  # Only allows GET; other methods get 405
async def get_user(user_id: int):
    return {"id": user_id}

@app.post("/users", status_code=201)  # Only allows POST
async def create_user(user: User):
    return user
```

This prevents method confusion attacks and ensures endpoints behave as designed. For example, a GET endpoint should never modify data, and attempting a POST to a read-only endpoint should be immediately rejected.

**JSON Schema Validation**:

Validate request bodies against expected schema, return **400 Bad Request** if validation fails.

Validation libraries:

- TypeScript/Node.js: [Zod](https://github.com/colinhacks/zod), [Joi](https://github.com/hapijs/joi)
- Python: [Pydantic](https://github.com/pydantic/pydantic)
- Go: [go-playground/validator](https://github.com/go-playground/validator)

Validate: Required fields, data types, value constraints (length, ranges, patterns), enum values, nested structure

**Request Size & Timeout Limits**:

Unbounded bodies and slow clients are the cheapest DoS there is. Cap both before the parser runs:

- **Body size**: Set an explicit per-route limit and return **413 Content Too Large**. Express `express.json()` defaults to 100 KB - keep it there and raise only on upload routes
- **Gateway caps are not your limit**: Lambda accepts 6 MB synchronous payloads, far more than any JSON API needs - set your own, smaller limit in code
- **Timeouts**: Bound header/body read time and idle keep-alive at the server (slowloris), and keep the function timeout at or below the gateway integration timeout so work doesn't continue after the client got a 504 (API Gateway's default ceiling is 29 s; raisable for Regional/private REST APIs)
- **Depth and count**: Reject deeply nested JSON and arrays over a few thousand elements - schema validators run after the parser has already allocated

```javascript
// Express: small default body limit, larger only where uploads are expected
app.use(express.json({ limit: "100kb" }));
app.post("/uploads", express.raw({ type: "*/*", limit: "5mb" }), uploadHandler);

// Node http.Server: kill slow clients
server.headersTimeout = 10_000; // ms to receive complete headers
server.requestTimeout = 30_000; // ms to receive the whole request
```

### Input Sanitization

Prevent injection attacks through proper input handling:

**SQL Injection**:

- Always use parameterized queries (prepared statements)
- Never concatenate user input into SQL strings

**XSS (Cross-Site Scripting)**:

- Escape HTML special characters
- Use templating engines with auto-escaping
- Set `Content-Type: application/json`

**Command Injection**:

- Never pass user input to shell commands (`exec`, `system`, `eval`)

**Path Traversal**:

- Canonicalize the path (e.g. `realpath`) after decoding and reject it unless it stays under the allowed base directory; `..`/`/`/`\` blocklists miss encoded variants
- Use allowlists for file paths

**General Sanitization**:

- Trim whitespace
- Enforce length limits
- Reject null bytes and control characters

## 8. Rate Limiting & Throttling

Implement two-layer rate limiting: basic protection at edge, sophisticated business logic at application layer.

### Two-Layer Approach

**Edge Layer** (Cloudflare, AWS WAF, GCP Cloud Armor, Azure WAF):

- Basic catch-all rate limiting for DDoS protection
- Aggressive limits: 100-2000 requests/minute per IP
- See Edge Security Layer section for configuration

**Application Layer** (API code):

- Fine-grained, business-logic-aware limits
- Per-user limits based on subscription tier
- Endpoint-specific limits (e.g., `/login`: 5/min, `/search`: 100/min)

### Rate Limit State Storage

Store rate limit counters in distributed storage with atomic increment operations:

- Redis (fastest, any cloud)
- AWS DynamoDB (serverless)
- GCP Firestore
- Azure Cosmos DB

### Rate Limiting Patterns

Implement different rate limiting strategies based on user tier, endpoint sensitivity, and authentication status.

| Pattern Type                   | Limits                | Use Case                               | Enforcement Level  |
| ------------------------------ | --------------------- | -------------------------------------- | ------------------ |
| **Per-User (Free Tier)**       | 100 req/hour          | Rate limit by subscription tier        | Application layer  |
| **Per-User (Pro Tier)**        | 1,000 req/hour        | Paid tier gets higher limits           | Application layer  |
| **Per-User (Enterprise)**      | 10,000+ req/hour      | Custom limits for enterprise customers | Application layer  |
| **Endpoint: /login**           | 5 req/min             | Brute force prevention                 | Application layer  |
| **Endpoint: /password-reset**  | 3 req/hour            | Abuse prevention                       | Application layer  |
| **Endpoint: /search**          | 100 req/min           | Expensive operations protection        | Application layer  |
| **Endpoint: /profile**         | 1,000 req/min         | Cheap read operations                  | Application layer  |
| **IP-Based (Unauthenticated)** | 1,000 req/hour per IP | DDoS mitigation for public endpoints   | Edge + Application |

**Implementation Notes:**

- **Per-User limits**: Enforced after authentication, uses user ID as rate limit key
- **Endpoint-Specific limits**: Stack with per-user limits (e.g., Pro user hitting /login still limited to 5/min)
- **IP-Based limits**: Apply to unauthenticated endpoints as first line of defense
- **State Storage**: Use Redis/DynamoDB for atomic increment operations and TTL support

### HTTP 429 Responses

Return **429 Too Many Requests** with retry information:

```json
{
  "error": "Rate limit exceeded.",
  "retry_after": 60
}
```

**Include headers in all responses:**

- `X-RateLimit-Limit`: Maximum requests in window
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when window resets
- `Retry-After`: Seconds until retry (429 only)

### Implementation Libraries

- TypeScript/Node.js: [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit), [rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible)
- Python: [slowapi](https://github.com/laurentS/slowapi), [flask-limiter](https://github.com/alisaifee/flask-limiter)
- Go: [tollbooth](https://github.com/didip/tollbooth), [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate)

**Rate limiting implementation with Redis (Node.js):**

```typescript
import Redis from "ioredis";
import { Request, Response, NextFunction } from "express";

const redis = new Redis(process.env.REDIS_URL);

async function rateLimitMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
  limit: number,
  window: number, // seconds
) {
  // Behind Cloudflare/ALB, req.ip is the edge's address unless Express trusts
  // the proxy (app.set("trust proxy", <hop count or CIDR list>)); never `true`,
  // or clients can spoof X-Forwarded-For and dodge the limit
  const key = req.user?.id || req.ip || "anonymous";
  // Scope per route so /login and /api/data limits don't share state
  const redisKey = `ratelimit:${req.baseUrl}${req.route?.path}:${key}`;
  const now = Date.now();
  const windowStart = now - window * 1000;

  // Trim, add and count in one MULTI/EXEC: a separate check-then-add is a race
  // that lets a concurrent burst through the limit
  const results = await redis
    .multi()
    .zremrangebyscore(redisKey, 0, windowStart)
    .zadd(redisKey, now, `${now}-${Math.random()}`)
    .zcard(redisKey)
    .expire(redisKey, window)
    .exec();
  const count = results![2][1] as number; // includes this request

  // Set rate limit headers
  res.setHeader("X-RateLimit-Limit", limit);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, limit - count));

  if (count > limit) {
    res.setHeader("Retry-After", window);
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  next();
}

// Usage: Different limits for different endpoints
app.post(
  "/api/login",
  (req, res, next) => rateLimitMiddleware(req, res, next, 5, 60), // 5 per minute
);
app.get(
  "/api/data",
  authenticate,
  (req, res, next) => rateLimitMiddleware(req, res, next, 100, 3600), // 100 per hour
);
```

## 9. Error Handling & Responses

Provide consistent, secure error responses to clients while logging detailed errors internally.

### Consistent Error Response Structure

Standardized JSON format with request ID for traceability:

```json
{
  "error": "Generic error message for client",
  "request_id": "req_abc123xyz"
}
```

Never include stack traces, database queries, file paths, or implementation details in client responses.

### HTTP Status Code Standards

Use appropriate HTTP status codes to clearly communicate request outcomes to clients.

| Code    | Status                | When to Use                                     | Example Scenario                          |
| ------- | --------------------- | ----------------------------------------------- | ----------------------------------------- |
| **200** | OK                    | Successful GET, PUT, PATCH, DELETE              | User profile retrieved successfully       |
| **201** | Created               | Successful POST creating new resource           | New user account created                  |
| **204** | No Content            | Successful DELETE with no response body         | Comment deleted                           |
| **400** | Bad Request           | Invalid request body or validation failure      | Missing required field in JSON            |
| **401** | Unauthorized          | Missing or invalid authentication token         | No JWT token in Authorization header      |
| **403** | Forbidden             | Authenticated but lacks permission for resource | User trying to delete someone else's post |
| **404** | Not Found             | Resource doesn't exist                          | Requested user ID not in database         |
| **405** | Method Not Allowed    | Wrong HTTP method for endpoint                  | POST to read-only endpoint                |
| **409** | Conflict              | Resource conflict (duplicate, state mismatch)   | Email already registered                  |
| **429** | Too Many Requests     | Rate limit exceeded                             | User made >100 requests per minute        |
| **500** | Internal Server Error | Unexpected error (catch-all)                    | Unhandled exception in application        |
| **503** | Service Unavailable   | Service temporarily down or overloaded          | Database connection pool exhausted        |

**Best Practices:**

- Use 4xx for client errors (bad request, auth issues, validation)
- Use 5xx for server errors (unexpected exceptions, service failures)
- Never return 200 with error in body - use appropriate error code
- Include generic error message in response body with request ID

### Generic External Error Messages

Return generic messages to prevent information leakage:

- `400`: "Invalid request parameters."
- `401`: "Authentication required."
- `403`: "Access denied."
- `404`: "Requested resource not found."
- `500`: "An internal error occurred. Please try again later."

Never expose specific details: "User john@example.com not found", "Database connection failed on db-prod-1", "Invalid API key: sk_live_abc123"

### Detailed Internal Logging

Log comprehensive error details internally (never send to clients):

- Request ID, user ID, authentication context
- Full error message and stack trace
- Request parameters (sanitize sensitive data)
- Timestamp, endpoint, method, IP address, user agent

### Request ID for Traceability

Generate unique request ID (UUID, ULID, KSUID) for every API call:

- Include in all log entries
- Return in response header: `X-Request-ID: req_abc123xyz`
- Return in error response body
- Enables correlation between client errors and internal logs

## 10. Logging & Monitoring

Implement comprehensive logging and observability for security, debugging, and operational visibility.

### Audit Logging

Log all API invocations with outcome for security auditing:

- Function/endpoint invoked
- Success or failure status
- User ID or authentication context
- Timestamp, IP address, user agent
- Request ID for correlation

### Structured Logging (JSON Format)

Use JSON format for machine-parseable logs enabling easy parsing, filtering, and aggregation in SIEM tools:

```json
{
  "timestamp": "2025-01-17T10:30:00Z",
  "request_id": "req_abc123xyz",
  "user_id": "user_456",
  "endpoint": "/api/users/123",
  "method": "GET",
  "status": 200,
  "duration_ms": 45,
  "ip_address": "192.0.2.1",
  "user_agent": "Mozilla/5.0..."
}
```

### Log Forwarding & Centralization

Forward logs to centralized logging service for real-time monitoring and analysis:

- AWS CloudWatch Logs, GCP Cloud Logging, Azure Monitor
- Splunk, ELK Stack, Loki
- Enable searching, filtering, real-time alerts
- Serverless: Logs automatically forwarded to cloud provider's logging service
- Containers: Use log shippers (Fluentd, Fluent Bit, Vector)

### Log Correlation with Request IDs

Use request IDs to correlate logs across distributed systems:

- Track request flow through microservices
- Link audit logs, error logs, performance metrics
- Debug issues across service boundaries
- Essential for troubleshooting in distributed architectures

## 11. Compliance & Retention

Implement log retention policies to meet regulatory compliance requirements.

### Hot Storage (30 Days)

Keep active logs in the centralized logging service chosen in [Log Forwarding & Centralization](#log-forwarding--centralization):

- 30-day retention sufficient for active troubleshooting
- Set the retention policy on the log group/bucket itself so expiry is automatic, then archive (below)

### Cold Storage (Multi-Year for Compliance)

Archive logs in compressed, low-cost storage for regulatory compliance:

- AWS S3 Glacier / Glacier Deep Archive
- GCP Coldline Storage / Archive Storage
- Azure Cool Blob Storage / Archive Blob Storage

**Retention Requirements by Compliance Standard:**

| Compliance Standard | Retention Period                                   | Scope                                                                      |
| ------------------- | -------------------------------------------------- | -------------------------------------------------------------------------- |
| **PCI DSS v4.0.1**  | 12 months (3 months immediately available)         | Audit logs for in-scope systems (Req 10.5.1)                               |
| **HIPAA**           | 6 years                                            | Security Rule documentation, incl. audit records (45 CFR 164.316(b)(2)(i)) |
| **SOC 2**           | Not prescribed; set and document your own          | Audit logs, access logs, security events                                   |
| **ISO 27001**       | Not prescribed; set and document your own          | Security logs, incident records                                            |
| **GDPR**            | No fixed period; storage limitation (Art. 5(1)(e)) | Personal data kept no longer than necessary                                |

**Archive Process:**

1. Export from hot storage after 30 days
2. Compress (gzip, zstd)
3. Upload to cold storage with lifecycle policies
4. Delete from hot storage

### Compliance Considerations

**Data Privacy**:

- Never log passwords, tokens, CVVs or full card numbers; mask or tokenize other sensitive PII, and use a keyed hash (HMAC) when you need a joinable value (plain hashes of SSNs are brute-forceable)
- Implement data retention policies compliant with GDPR right to deletion
- Redact or hash sensitive fields in logs

**Access Controls**:

- Restrict log access to authorized personnel only
- Implement audit trails for log access
- Use role-based access control (RBAC) for log viewing

**Data Sovereignty**:

- Store logs in same region as application for GDPR/data residency requirements
- Use region-specific cold storage for compliance

## 12. Performance Optimization

Optimize API performance through batching, concurrency, cold start mitigation, and caching.

### Batching Requests

Combine multiple operations into single requests to reduce round trips:

- Batch database queries instead of N+1 queries (use WHERE IN clauses)
- Batch external API calls to third-party services
- Use database batch inserts/updates for bulk operations

Example: Instead of 100 individual queries, batch into single query with WHERE IN clause.

### Concurrency Patterns

Execute independent operations in parallel to reduce total latency. Don't overwhelm downstream services - respect rate limits and connection pools.

**TypeScript/Node.js (Promise.all)**:

```javascript
// Sequential (slow): 300ms total
const user = await getUser(userId);
const posts = await getPosts(userId);
const comments = await getComments(userId);
```

```javascript
// Parallel (fast): 100ms total
const [user, posts, comments] = await Promise.all([
  getUser(userId),
  getPosts(userId),
  getComments(userId),
]);
```

**Go (goroutines)**:

```go
var wg sync.WaitGroup
wg.Add(2) // or wg.Go(func() { ... }) on Go 1.25+
go func() { defer wg.Done(); user = getUser(userID) }()
go func() { defer wg.Done(); posts = getPosts(userID) }()
wg.Wait()
```

**Python (asyncio)**:

```python
user, posts, comments = await asyncio.gather(
    get_user(user_id), get_posts(user_id), get_comments(user_id)
)
```

**Use cases**: Fetching multiple database records, calling multiple external APIs, independent data transformations.

### Caching Strategies

Implement caching at multiple layers to reduce latency and backend load.

**CDN/Edge Caching** (Cloudflare, CloudFront, Cloud CDN):

- Cache static assets (images, CSS, JavaScript) and GET responses
- `Cache-Control: public, max-age=3600` for cacheable responses
- `Cache-Control: no-store` for sensitive or user-specific data

**API Gateway Caching**:

- AWS API Gateway (REST APIs) caches responses; GCP Cloud Endpoints does not - put Cloud CDN in front of the load balancer instead
- Configure TTL per endpoint (AWS API Gateway: 0 to 3600 seconds)
- Reduces backend invocations for identical requests
- **Critical**: For authenticated endpoints, cache key MUST include authentication context (user ID, auth token) to prevent serving user A's data to user B
- Safe to cache: Public GET endpoints, static reference data
- Dangerous to cache: User-specific data, personalized responses (without proper cache keys)

**Application-Level Caching** (Redis, Memcached):

- Cache database query results and expensive computations
- Session storage for faster lookups
- Set appropriate TTLs based on data staleness tolerance

**Cache Invalidation**:

- Invalidate on data updates (write-through or write-behind)
- Use versioned cache keys for easy invalidation
- Monitor cache hit rates to optimize TTLs

### Database Performance Considerations

For API performance, consider these database patterns:

| Pattern                 | When to Use                        | Security Benefit                       |
| ----------------------- | ---------------------------------- | -------------------------------------- |
| **Connection Pooling**  | Always (serverless and containers) | Prevents connection exhaustion attacks |
| **Read Replicas**       | Read-heavy workloads (>80% reads)  | Protects primary from overload         |
| **Query Timeouts**      | Always                             | Prevents long-running query attacks    |
| **Prepared Statements** | Always                             | Prevents SQL injection                 |

**Implementation:** Use connection pooling libraries (application-level for containers, RDS Proxy for serverless). Route reads to replicas, writes to primary. Set query timeouts (5s). Always use parameterized queries.

### Cold Start Optimization

Beyond provisioned concurrency and scheduled invocations (see [Serverless Cold Start Mitigation](#serverless-cold-start-mitigation) in Architecture Patterns):

**Optimize Package Size**:

- Minimize dependencies in deployment package
- Use tree-shaking and dead code elimination
- Remove dev dependencies from production builds
- Use Lambda layers for shared dependencies (AWS)

**Optimize Initialization**:

- Move expensive initialization outside handler function (runs once per container)
- Cache database connections, HTTP clients globally
- Lazy-load rarely-used dependencies
- Pre-compile regex patterns, load configuration once

## 13. API Versioning

Implement versioning to manage breaking changes without disrupting existing clients.

### Versioning Approaches

**URL Path Versioning** (Recommended):

- Format: `/v1/users`, `/v2/users` or `/api/v1/users`
- Advantages: Explicit, easy to test, simple routing, browser-friendly
- Most widely adopted approach

**Header Versioning**:

- Format: `Accept: application/vnd.api+json; version=1` or `API-Version: 2`
- Advantages: Cleaner URLs, supports content negotiation
- Disadvantages: Less visible, harder to debug, complex caching

### When to Increment Versions

**Breaking changes** (require new version):

- Changing response structure or field types
- Removing fields or endpoints
- Modifying authentication requirements
- Changing validation rules

**Non-breaking changes** (no version increment):

- Adding new optional fields to responses
- Adding new endpoints or optional request parameters
- Bug fixes and performance improvements

### Deprecation Strategy

Timeline and communication:

- Announce deprecation 6-12 months before removal
- Return deprecation headers per RFC 9745 / RFC 8594: `Deprecation: @1778457600` (Unix timestamp of the deprecation date), `Sunset: Wed, 11 Nov 2026 11:11:11 GMT`, and `Link: <https://api.example.com/docs/migration>; rel="deprecation"`
- Document migration path in API documentation
- Support minimum 2 versions simultaneously (current + previous)

**Example timeline**:

1. v2 released
2. v1 deprecated (6-12 months support)
3. v3 released
4. v1 removed, v2 deprecated

## 14. Identity & Access Management

Configure least-privilege access control for API infrastructure, service accounts, and secrets management to minimize blast radius of compromised credentials.

### Cloud IAM Policies

**Serverless Functions** (AWS Lambda, GCP Cloud Run functions, Azure Functions):

Attach minimal execution role to each function:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:region:account:secret:prod/api/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:region:account:log-group:/aws/lambda/api-*"
    }
  ]
}
```

**GCP Service Account**:

```bash
# Create service account
gcloud iam service-accounts create api-function-sa

# Grant access to the specific secret only (a project-level binding exposes every secret in the project)
gcloud secrets add-iam-policy-binding prod-api-db-password \
  --member="serviceAccount:api-function-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Deploy with service account (Cloud Functions is now Cloud Run functions)
gcloud run deploy api-function --source . --function handler --base-image RUNTIME_ID \
  --region REGION \
  --service-account=api-function-sa@PROJECT_ID.iam.gserviceaccount.com
```

**Azure Managed Identity**:

```bash
# Enable managed identity
az functionapp identity assign --name api-function-app --resource-group production-rg

# Grant Key Vault access (new vaults default to Azure RBAC; `az keyvault set-policy` fails on RBAC vaults)
az role assignment create --role "Key Vault Secrets User" \
  --assignee-object-id PRINCIPAL_ID --assignee-principal-type ServicePrincipal \
  --scope "$(az keyvault show --name prod-keyvault --query id -o tsv)"
```

**Container/VM Roles**:

- AWS: Attach IAM role to EC2 instance profile or ECS task role
- GCP: Use Workload Identity Federation for GKE (see Kubernetes Security Guide)
- Azure: Use managed identity
- Never store credentials in environment variables or config files

### Service Account Management

**Scope and Separation**:

- One service account per application/function (never share)
- Separate accounts for dev/staging/production environments
- Naming: `{env}-{service}-{purpose}` (e.g., `prod-api-secrets`)

**Least Privilege**:

- Grant only required actions (avoid `*` wildcards)
- Restrict to specific resources (exact ARNs, paths, buckets)
- Use IAM conditions (IP restrictions, time-based, request attributes)
- Audit and remove unused permissions quarterly

---

**Lifecycle Management:**

Prevent accumulation of unused, over-privileged, or compromised accounts through rigorous lifecycle controls.

**Creation Process:**

1. Developer requests with justification (application name, required permissions, environment)
2. Security team reviews for least privilege and naming compliance
3. Provision via Infrastructure as Code (Terraform) with auto-tagging
4. Document in service account registry (owner, permissions, applications, last reviewed)

---

**Rotation Procedures:**

While workload identity/IAM roles use temporary credentials, service account keys require rotation. Prefer short-lived workload identity so there is nothing static to rotate.

**Rotation Schedule:**

- On a documented, risk-based schedule; 90 days is a common choice, not a mandate. PCI DSS v4.0.1 Req 8.6.3 requires application and system account passwords to be changed "periodically (at the frequency defined in the entity's targeted risk analysis) and upon suspicion or confirmation of compromise"; SOC 2 and ISO 27001 set no interval
- Immediate rotation: Suspected compromise, employee departure, key leakage
- NIST SP 800-63B-4's rule against forced periodic changes covers user passwords only, never service credentials

**Zero-Downtime Rotation Steps:**

1. Generate new key and deploy to 10% of instances (canary)
2. Monitor for authentication errors
3. Roll out to remaining 90%, keep old key active (12-24 hour overlap)
4. Validate all services using new credentials
5. Disable old key after 24 hours, delete after confirmation

---

**Monitoring for Compromise:**

Set up automated alerts for suspicious patterns:

| Alert Type                | Trigger                                     | Indicates                             |
| ------------------------- | ------------------------------------------- | ------------------------------------- |
| **Geographic anomalies**  | Access from unexpected countries/regions    | Compromised credentials               |
| **Time anomalies**        | Activity outside normal hours (3 AM)        | Unauthorized access                   |
| **Excessive API calls**   | 10x normal volume                           | Data exfiltration or misconfiguration |
| **Failed authentication** | >5 attempts in 10 minutes                   | Brute force attack                    |
| **Permission escalation** | Access attempts outside granted permissions | Privilege escalation attempt          |

**Detection Example (AWS CloudTrail):**

```python
import json
from datetime import datetime, timedelta, timezone

import boto3

cloudtrail = boto3.client('cloudtrail')

# Monitor AssumeRole events for anomalies
def detect_anomalies():
    paginator = cloudtrail.get_paginator('lookup_events')  # 50 events per page
    pages = paginator.paginate(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'}],
        StartTime=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    for page in pages:
        for event in page['Events']:
            # The raw record (with sourceIPAddress) is a JSON string in CloudTrailEvent
            record = json.loads(event['CloudTrailEvent'])
            source_ip = record.get('sourceIPAddress')
            if not is_expected_ip(source_ip):
                alert_security_team(f"Anomalous access from {source_ip}")
```

---

**Service Accounts vs Workload Identity:**

| Feature         | Service Account Keys | Workload Identity (IAM Roles)                  |
| --------------- | -------------------- | ---------------------------------------------- |
| Rotation        | Manual, risk-based   | Automatic, short-lived (minutes to hours)      |
| Compromise Risk | High (long-lived)    | Low (temporary)                                |
| Leakage Risk    | High (keys in logs)  | Low (no stored keys; still stealable via SSRF) |
| Use Case        | Cross-cloud, CI/CD   | Cloud-native apps                              |

**Recommendation**: Always prefer workload identity (EKS Pod Identity - AWS now recommends it over IRSA, Workload Identity Federation for GKE, Microsoft Entra Workload ID on AKS) over service account keys when available. Use keys only when workload identity is not an option.

---

**Governance Policies:**

- **Approval**: Production service accounts require security team sign-off
- **Tagging**: Enforce tags (Owner, Environment, Purpose, CreatedDate, LastReviewed)
- **Quarterly audits**: Review all accounts, remove unused, tighten overly permissive policies
- **Auto-deactivation**: Service accounts inactive >90 days automatically disabled
- **Key limits**: Maximum 2 active keys per account (current + rotation overlap)

**Decommissioning Process:**

1. Disable (set Inactive status, don't delete)
2. Monitor for authentication failures over 7 days
3. Confirm no applications still using account
4. Delete service account and all keys/credentials
5. Update registry with decommission date and reason

### Secrets Retrieval Patterns

**Serverless Cold Start Caching**:

```python
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig

# Built once per execution environment; entries refresh every 5 minutes
client = botocore.session.get_session().create_client('secretsmanager')
cache = SecretCache(config=SecretCacheConfig(secret_refresh_interval=300), client=client)

def lambda_handler(event, context):
    db_password = cache.get_secret_string('prod/api/db-password')
    # Warm invocations hit the cache; a rotated secret is picked up within 5 minutes
```

Never cache a secret with `functools.lru_cache`: it has no TTL, and Lambda keeps warm environments for hours, so a rotated password stays stale until the environment is recycled. The AWS Parameters and Secrets Lambda Extension (HTTP on `localhost:2773`, 300 s TTL by default) does the same without a code dependency.

**Container Startup Pattern**:

```python
from google.cloud import secretmanager

class Config:
    def __init__(self):
        client = secretmanager.SecretManagerServiceClient()
        self.db_password = client.access_secret_version(
            name="projects/PROJECT_ID/secrets/db-password/versions/latest"
        ).payload.data.decode('UTF-8')

# Initialize once at startup
config = Config()
```

**Long-Running Service Refresh**:

```python
import logging
import time
from threading import Thread

class SecretManager:
    def __init__(self):
        # Load synchronously so callers never see an empty dict
        self.secrets = {'db_password': fetch_secret('prod/api/db-password')}
        Thread(target=self._refresh_loop, daemon=True).start()

    def _refresh_loop(self):
        while True:
            time.sleep(3600)  # Refresh hourly
            try:
                self.secrets['db_password'] = fetch_secret('prod/api/db-password')
            except Exception:
                # Keep the last known-good value; one failed refresh must not kill the loop
                logging.exception("Secret refresh failed, retrying next interval")
```

### Monitoring and Auditing

**Enable Cloud Audit Logs**:

- AWS CloudTrail: Log IAM role assumptions, API calls, secret accesses
- GCP Cloud Audit Logs: Log service account usage, Secret Manager access
- Azure Activity Logs: Log managed identity auth, Key Vault access

**Alert on Suspicious Activity**: feed the triggers from the Monitoring for Compromise table (Service Account Management, above) into your SIEM, plus alerts on new IAM policy attachments and on secret access from unexpected IPs/regions.

**Regular Audits**:

- Review and delete unused service accounts quarterly
- Analyze audit logs for privilege escalation patterns
- Verify environment separation (dev can't access prod)
- Check for overly permissive policies

## 15. Incident Response

Respond to security incidents quickly and effectively to minimize damage.

### Detection & Initial Response

**Automated Detection**:

- Monitor authentication failures, rate limit violations, unusual traffic patterns
- Alert on error rate spikes, latency increases, WAF blocks
- Track failed login attempts (>5/minute per IP indicates brute force)

**Immediate Actions**:

1. **Contain**: Block attacking IPs at edge (Cloudflare, AWS WAF, Cloud Armor)
2. **Investigate**: Use request IDs to trace attack in logs
3. **Isolate**: Revoke compromised tokens, force password resets
4. **Preserve**: Export logs before rotation for forensic analysis

### Containment & Recovery

**Emergency Measures**:

- Add malicious IPs to WAF block list
- Implement aggressive rate limiting on attacked endpoints (10-20 req/min)
- Rotate compromised credentials (API keys, database passwords, JWT signing keys)
- Deploy patches if vulnerability was exploited

**Investigation**:

- Filter logs by IP address, request ID, or user to identify attack scope
- Analyze authentication patterns, unusual endpoint access, large response sizes
- Determine: attack origin, methods used, data accessed, duration

### Post-Incident

**Documentation**:

- Timeline of events with request IDs and log evidence
- Attack vector and remediation actions taken
- Data/systems affected and estimated impact

**Improvements**:

- Update WAF rules based on attack patterns observed
- Enhance monitoring/alerting to detect similar incidents earlier
- Patch identified vulnerabilities and strengthen security controls
- Notify affected users per compliance requirements (GDPR, CCPA, HIPAA)

## 16. Attack Scenarios Prevented

This guide's security controls prevent real-world attacks commonly seen in production environments.

**Credential Stuffing**

- Attack: Stolen username/password pairs used for unauthorized access
- Mitigated by: Edge rate limiting, application `/login` limits (5 req/min), failed auth monitoring, IP blocking

**JWT Token Manipulation**

- Attack: Tampering with tokens to elevate privileges or impersonate users
- Mitigated by: Complete JWT validation (signature, issuer, audience, expiration), algorithm confusion prevention (RS256 only), short-lived tokens (15 min)

**API Key Exposure & Abuse**

- Attack: Leaked keys from GitHub or client-side code used to access services
- Mitigated by: Secret scanning (TruffleHog, GitHub), secrets in external vaults, per-user rate limiting, automated rotation

**SQL Injection**

- Attack: Malicious SQL injected into parameters to access/modify database
- Mitigated by: Parameterized queries (prepared statements), input validation (Zod, Pydantic, Joi), WAF rules blocking injection patterns, SAST scanning (Opengrep) catching vulnerable code pre-deployment

**Database Breach & Data Exfiltration**

- Attack: Direct database access via compromised credentials, stolen backups, or insider threat exposing plaintext sensitive data
- Mitigated by: Managed database encryption at rest (AWS RDS, GCP Cloud SQL, Azure TDE), application-level encryption for PII/PHI/PCI data (AES-256-GCM with KMS), encrypted backups, secrets in external vaults, least-privilege database access

**Information Disclosure via Error Messages**

- Attack: Extracting sensitive data from verbose errors (database details, file paths, internal IPs)
- Mitigated by: Generic external error messages, detailed internal-only logging, request IDs for support, consistent error structure

**DDoS / Resource Exhaustion**

- Attack: Overwhelming API with requests to cause degradation or outage
- Mitigated by: Edge DDoS protection (Cloudflare, AWS Shield, Cloud Armor), aggressive edge rate limiting (100-2000 req/min per IP), endpoint-specific limits, auto-scaling

**Cached Data Leakage & Cache Poisoning**

- Attack: A shared cache serves user A's response to user B, or an attacker gets a harmful response cached for everyone via unkeyed inputs (e.g. `X-Forwarded-Host`)
- Mitigated by: Cache keys include the verified caller identity, `Cache-Control: no-store`/`private` on user-specific responses, never reflecting unkeyed headers into responses, `Vary: Origin` when CORS headers vary, authentication-aware API Gateway caching

**Dependency Vulnerabilities**

- Attack: Exploiting known vulnerabilities in outdated libraries
- Mitigated by: Dependabot automated updates catching vulnerable packages, pre-deployment security scans, regular audits, timely patching

## 17. References

### Security Tools

- [Dependabot](https://github.com/dependabot/dependabot-core)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Semgrep](https://semgrep.dev/)
- [Opengrep](https://github.com/opengrep/opengrep)
- [Aikido Security](https://www.aikido.dev/)
- [Coraza](https://github.com/corazawaf/coraza)
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)

### Validation & Rate Limiting

- [Zod](https://github.com/colinhacks/zod)
- [Joi](https://github.com/hapijs/joi)
- [Pydantic](https://github.com/pydantic/pydantic)
- [go-playground/validator](https://github.com/go-playground/validator)
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- [slowapi](https://github.com/laurentS/slowapi)
- [tollbooth](https://github.com/didip/tollbooth)

### Standards & Documentation

- [OWASP Top 10](https://owasp.org/projects/top-ten)
- [OWASP API Security Top 10](https://api-security.owasp.org/)
- [OpenAPI Specification](https://swagger.io/specification/)
- [OAuth 2.0](https://oauth.net/2/)
- [JWT](https://www.jwt.io/)
- [OWASP API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [CA/Browser Forum Ballot SC-081v3 (certificate validity schedule)](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)
- [Node.js http.Server timeouts](https://nodejs.org/api/http.html#serverrequesttimeout)
- [RFC 9745 Deprecation Header](https://www.rfc-editor.org/rfc/rfc9745.html)
- [PCI DSS v4.0.1](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)

### Incident Reports

- [Optus breach caused by a coding error, alleges ACMA (CSO Online)](https://www.csoonline.com/article/2492520/optus-breach-occurred-due-to-a-coding-error-alleges-acma.html)
- [T-Mobile Form 8-K on the 2023 API breach (SEC)](https://www.sec.gov/Archives/edgar/data/1283699/000119312523010949/d641142d8k.htm)
- [LinkedIn denies 700M-record scrape is a data breach (Computer Weekly)](https://www.computerweekly.com/news/252503281/LinkedIn-denies-exposure-of-700-million-user-records-is-a-data-breach)
