# API Security Design Guide

**Last Updated:** January 21, 2026

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
    - [Serverless Cold Start Mitigation](#serverless-cold-start-mitigation-1)
13. [API Versioning](#13-api-versioning)
    - [Versioning Approaches](#versioning-approaches)
    - [When to Increment Versions](#when-to-increment-versions)
    - [Deprecation Strategy](#deprecation-strategy)
14. [Identity & Access Management](#14-identity--access-management)
    - [Cloud IAM Policies for API Infrastructure](#cloud-iam-policies-for-api-infrastructure)
    - [Service Account Management](#service-account-management)
    - [Secrets Retrieval Patterns](#secrets-retrieval-patterns)
    - [Database Access Patterns](#database-access-patterns)
    - [Access Monitoring and Auditing](#access-monitoring-and-auditing)
15. [Incident Response](#15-incident-response)
    - [Detection & Initial Response](#detection--initial-response)
    - [Containment & Recovery](#containment--recovery)
    - [Post-Incident](#post-incident)
16. [Attack Scenarios Prevented](#16-attack-scenarios-prevented)
    - [Authentication & Authorization Attacks](#authentication--authorization-attacks)
    - [Injection & Input Attacks](#injection--input-attacks)
    - [Availability & Performance Attacks](#availability--performance-attacks)
    - [Supply Chain & Dependencies](#supply-chain--dependencies)
17. [References](#17-references)

## 1. Overview

This guide outlines a production-grade API design approach that balances security, performance, and maintainability. The patterns are cloud-agnostic and work with major cloud providers (AWS, GCP, Azure) and their respective services for serverless functions, container orchestration, secrets management, and logging.

**Core Principles:**

- **Security First**: Defense in depth from edge to application to data layer
- **Performance Conscious**: Optimize for latency and throughput without compromising security
- **Cloud Agnostic**: Works across AWS, GCP, Azure with equivalent services
- **Production Ready**: Battle-tested patterns from real-world deployments

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
- [Opengrep](https://github.com/opengrep/opengrep) - Static application security testing

### External Services

**Secrets Management** (required - choose one):

- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault
- HashiCorp Vault

**Logging & SIEM** (required - choose one):

- AWS CloudWatch Logs
- GCP Cloud Logging
- Azure Monitor
- Splunk
- Self-hosted (ELK Stack, Loki)

**Cold Storage** (required for compliance):

- AWS S3 Glacier / S3 Glacier Deep Archive
- GCP Coldline Storage / Archive Storage
- Azure Cool Blob Storage / Archive Blob Storage

**Edge Protection** (required - choose one):

- Cloudflare (Free tier available with WAF + DDoS protection)
- AWS CloudFront + AWS WAF
- GCP Cloud Armor + Cloud CDN
- Azure Front Door + Azure WAF

**Rate Limiting State Storage** (choose one):

- Redis (any cloud or self-hosted)
- AWS DynamoDB
- GCP Firestore
- Azure Cosmos DB

## 3. Architecture Patterns

### Serverless vs Containers/VMs

**Serverless (AWS Lambda, GCP Cloud Functions, Azure Functions)**

Advantages:

- Easier to manage - no provisioning, patching, or scaling configuration
- More secure - ephemeral environments reduce attack surface
- Auto-scaling and pay-per-invocation pricing

Disadvantages:

- Cold start latency (100ms-3s depending on language)
- Cannot handle stateful workloads or persistent connections
- Not suitable for WebSockets, streaming, or long-running processes

Use serverless when:

- Event-driven workloads with sporadic traffic
- Can tolerate 100-500ms cold start latency
- Team lacks dedicated DevOps resources

**Containers/VMs (ECS, GKE, AKS, EC2, Compute Engine)**

Advantages:

- Lower latency - no cold starts
- Supports stateful services, WebSockets, connection pooling
- More cost-effective for consistent high traffic

Disadvantages:

- Requires provisioning, patching, monitoring, scaling configuration
- Higher management overhead

Use containers/VMs when:

- Latency-critical applications (<50ms response time)
- Stateful services (WebSockets, streaming, persistent connections)
- High, consistent traffic patterns

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
# Kong configuration - applies to all routes
plugins:
  - name: jwt
    config:
      key_claim_name: kid
      secret_is_base64: false
      claims_to_verify:
        - exp
        - iss
        - aud
  - name: rate-limiting
    config:
      minute: 100
      policy: redis
      redis_host: redis.internal
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
- GCP Cloud Functions minimum instances

**Scheduled Invocations**:

- Ping functions every 5-10 minutes to keep warm
- AWS CloudWatch Events, GCP Cloud Scheduler, Azure Timer Triggers
- Invoke lightweight health check endpoint

### Language Selection for Serverless

**Go** (Recommended):

- Cold start: ~150-250ms
- Compiled, static binaries, strong dependency management
- Built-in concurrency (goroutines)
- Best balance of performance and developer experience

**Rust**:

- Cold start: ~100-200ms
- Highest performance, memory safety guarantees
- Steeper learning curve
- Best for: Ultra-low latency requirements, cost optimization

**TypeScript/Node.js**:

- Cold start: ~200-500ms
- Rapid development, massive ecosystem
- Good for I/O-heavy workloads
- Best for: Full-stack JavaScript teams, high developer velocity

**Python**:

- Cold start: ~200-500ms
- Excellent for data/ML APIs, large ecosystem
- Competitive cold start times despite being interpreted
- Best for: Data processing, ML inference, teams familiar with Python

**Java**:

- Cold start: ~2-3 seconds (JVM initialization)
- Slowest cold starts without mitigation
- With SnapStart (2025): Reduces to ~200-400ms
- Only use in containers/VMs or with SnapStart/GraalVM native images

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
- Detects 700+ secret types (AWS keys, GCP service accounts, API tokens)
- Run as pre-commit hook or in CI/CD pipeline
- Command: `trufflehog git file://. --only-verified`

**GitHub Secret Scanning**:

- Built-in to GitHub (free for public repos, paid for private)
- Automatically scans commits for known secret patterns
- Partners with cloud providers (AWS, GCP, Azure) to revoke leaked credentials

Use [pre-commit](https://pre-commit.com/) framework to run TruffleHog before commits reach remote.

### Static Application Security Testing (SAST)

[Opengrep](https://github.com/opengrep/opengrep) (formerly Semgrep):

- Scans source code for security vulnerabilities
- Detects: SQL injection, XSS, insecure crypto, authentication issues, hardcoded secrets
- Supports 30+ languages (JavaScript, Python, Go, Java, C#, etc.)
- Run in CI/CD on every PR: `semgrep scan --config auto`

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

**Cloudflare**:

- Free tier with DDoS protection and basic WAF rules
- Global CDN with edge caching
- Easy DNS-based setup
- **Risk**: Dual-cloud dependency (Cloudflare OR cloud provider down = service down)

**Cloud-Native** (AWS WAF + CloudFront, GCP Cloud Armor, Azure Front Door):

- Single cloud provider reduces failure points
- Native integration with cloud services
- **Advantage**: If cloud goes down, entire stack fails together (not twice the failure risk)

**Recommendation**: Cloud-native if committed to single provider, Cloudflare for multi-cloud or free tier.

### Origin IP Restriction (Critical)

Configure firewall rules to allow traffic ONLY from edge provider IP ranges:

- Prevents attackers from bypassing edge protection by hitting origin directly
- Attackers can discover origin IPs via DNS history, SSL certificates, etc.
- Cloudflare IPs: https://www.cloudflare.com/ips/
- Cloud-native: Use security groups/firewall rules to allow only load balancer traffic

### Basic Rate Limiting at Edge

Implement aggressive catch-all rate limiting for DDoS mitigation:

- Cloudflare: 100 requests/second per IP (free tier: 1 rule)
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
- Allow production domain and localhost for development
- Example allowed origins: `https://example.com`, `http://localhost:3000`

**TypeScript/Node.js example:**

```javascript
const allowedOrigins = ["https://example.com", "http://localhost:3000"];
cors({
  origin: (origin, callback) => {
    allowedOrigins.includes(origin)
      ? callback(null, true)
      : callback(new Error("Not allowed by CORS"));
  },
});
```

### Authentication & Authorization

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

### Modern Authentication Patterns

Implement secure authentication flows beyond basic JWT validation for production-grade systems.

**OAuth 2.1 / OIDC Flow** (recommended for APIs):

```
1. Client redirects to auth server (e.g., Auth0, AWS Cognito)
2. User authenticates → Auth server issues authorization code
3. Client exchanges code for tokens:
   - Access token (short-lived, 15 min): API access
   - Refresh token (long-lived, 7-30 days): Get new access tokens
   - ID token (OIDC): User identity claims
4. Client calls API with access token in Authorization header
5. When access token expires, use refresh token to get new access token
```

**Refresh Token Rotation** (prevents token theft):

```javascript
// Token refresh endpoint
app.post("/auth/refresh", async (req, res) => {
  const { refresh_token } = req.body;

  // Validate refresh token
  const session = await validateRefreshToken(refresh_token);
  if (!session) return res.status(401).json({ error: "Invalid token" });

  // Issue new access + refresh tokens
  const newAccessToken = generateAccessToken(session.userId);
  const newRefreshToken = generateRefreshToken(session.userId);

  // Invalidate old refresh token (one-time use)
  await revokeRefreshToken(refresh_token);

  res.json({
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    expires_in: 900, // 15 minutes
  });
});
```

**Session Management Best Practices:**

- **Token storage**: Store refresh tokens in httpOnly cookies (not localStorage - vulnerable to XSS)
- **Session tracking**: Store active sessions in Redis with user ID, device info, IP, last activity
- **Concurrent sessions**: Limit to 3-5 active sessions per user, revoke oldest when exceeded
- **Session timeout**: Absolute timeout (7 days) + idle timeout (30 min of inactivity)
- **Logout**: Revoke both access and refresh tokens, clear server-side session

**Multi-Factor Authentication (MFA):**

```javascript
// After password validation, require MFA
if (user.mfa_enabled) {
  // Send TOTP code via authenticator app or SMS
  const mfaToken = generateMFAToken(user.id);

  return res.json({
    requires_mfa: true,
    mfa_token: mfaToken, // Temporary token to validate MFA
  });
}

// MFA verification endpoint
app.post("/auth/verify-mfa", async (req, res) => {
  const { mfa_token, code } = req.body;

  const userId = await validateMFAToken(mfa_token);
  const isValid = await verifyTOTP(userId, code);

  if (!isValid) return res.status(401).json({ error: "Invalid code" });

  // Issue full access + refresh tokens after MFA
  const tokens = generateTokens(userId);
  res.json(tokens);
});
```

**Passwordless Authentication (WebAuthn/FIDO2):**

Modern alternative to passwords using hardware security keys or biometrics:

- Phishing-resistant (cryptographic challenge-response)
- No password storage/management required
- Works with browser WebAuthn API or mobile biometrics
- Implement using libraries: SimpleWebAuthn (Node.js), py_webauthn (Python)

**Account Lockout & Brute Force Protection:**

```javascript
// Track failed login attempts (Redis)
const attempts = await redis.incr(`login:attempts:${email}`);
await redis.expire(`login:attempts:${email}`, 600); // 10 min window

if (attempts > 5) {
  // Lock account for 15 minutes
  await redis.setex(`login:locked:${email}`, 900, "1");
  return res.status(429).json({
    error: "Too many failed attempts. Try again in 15 minutes.",
  });
}

// On successful login, reset attempts
await redis.del(`login:attempts:${email}`);
```

**Token Revocation:**

Implement token blacklist for immediate logout (important for security incidents):

```javascript
// Revoke token on logout
app.post("/auth/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const decoded = jwt.decode(token);

  // Add to blacklist until token would naturally expire
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);
  await redis.setex(`blacklist:${token}`, ttl, "1");

  res.json({ message: "Logged out successfully" });
});

// Middleware to check blacklist
async function checkBlacklist(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  const isBlacklisted = await redis.exists(`blacklist:${token}`);

  if (isBlacklisted) {
    return res.status(401).json({ error: "Token revoked" });
  }
  next();
}
```

Combine these patterns for defense-in-depth: short-lived access tokens + refresh rotation + MFA + session limits + blacklist capability.

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

Encrypt sensitive fields in application code before writing to database using AES-256-GCM or equivalent:

- Encrypt: Credit card numbers, SSNs, medical records, financial data
- Use envelope encryption: Generate data encryption key (DEK) from KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault)
- Store encrypted DEK alongside ciphertext in database
- Libraries: AWS Encryption SDK, Google Tink, Azure SDK

**Why both layers**:

- Managed DB encryption: Compliance baseline, protects data on disk
- Application-level encryption: Protects against DBAs, SQL injection, credential compromise, stolen backups

**When application-level encryption is required**:

- HIPAA PHI, PCI-DSS cardholder data, highly sensitive PII
- Zero-trust requirements (don't trust cloud admins or DBAs)
- Multi-tenant SaaS with customer-managed encryption keys
- Regulatory requirements for end-to-end encryption

### Field-Level Encryption for PII/PHI

Encrypt individual sensitive fields in your database to protect against application compromise, insider threats, and credential breaches where database-level encryption is insufficient.

**When to use field-level encryption:**

- PII: Names, addresses, SSNs, emails, phone numbers
- PHI: Medical records, diagnoses, prescriptions
- PCI: Credit card numbers, CVV codes
- Compliance requirements (GDPR, HIPAA, PCI-DSS) mandating data protection beyond database encryption

**Envelope Encryption Pattern** (industry standard):

```
User Data → Encrypt with Data Encryption Key (DEK)
DEK → Encrypt with Key Encryption Key (KEK) from KMS
Store: Encrypted data + Encrypted DEK
```

**Implementation example (Python with AWS KMS):**

```python
import boto3
import base64
from cryptography.fernet import Fernet

kms = boto3.client('kms')

def encrypt_field(plaintext, kms_key_id):
    # Generate data encryption key
    response = kms.generate_data_key(KeyId=kms_key_id, KeySpec='AES_256')
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    # Encrypt data with DEK
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
    encrypted_data = cipher.encrypt(plaintext.encode())

    # Store both encrypted data and encrypted DEK
    return {
        'encrypted_data': base64.b64encode(encrypted_data).decode(),
        'encrypted_key': base64.b64encode(encrypted_key).decode()
    }

def decrypt_field(encrypted_data, encrypted_key):
    # Decrypt DEK using KMS
    response = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_key))
    plaintext_key = response['Plaintext']

    # Decrypt data with DEK
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
    return cipher.decrypt(base64.b64decode(encrypted_data)).decode()
```

**Cloud KMS options:**

- AWS: KMS with envelope encryption, automatic key rotation
- GCP: Cloud KMS with customer-managed encryption keys (CMEK)
- Azure: Key Vault for key management and encryption operations

**Key considerations:**

- **Performance**: Encrypt only necessary fields (SSN, credit cards), not entire records
- **Searchability**: Encrypted fields cannot be queried/indexed - use searchable encryption libraries or hash indexes for lookup
- **Key rotation**: Rotate KEK annually, re-encrypt DEKs (data re-encryption not required with envelope pattern)
- **Access control**: Restrict KMS key permissions to application service accounts only

**Database schema example:**

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255),  -- Not encrypted (needed for login)
    ssn_encrypted TEXT,  -- Encrypted SSN
    ssn_dek_encrypted TEXT,  -- Encrypted data key for SSN
    created_at TIMESTAMP
);
```

This pattern provides defense-in-depth: even if attackers gain database access, they cannot decrypt sensitive fields without KMS access.

### Encryption in Transit & TLS Requirements

Encrypt all network communication to protect data as it travels between clients, edge services, application servers, and databases.

**TLS Version Requirements**:

- **TLS 1.3** (Recommended): Faster handshake, improved security, removed weak ciphers
- **TLS 1.2** (Acceptable): Use as fallback for legacy client compatibility
- **Deprecate TLS 1.0/1.1**: Both are outdated and vulnerable (POODLE, BEAST attacks)

Prefer TLS 1.3 for all modern clients (browsers, mobile apps, API clients). Use TLS 1.2 fallback only if analytics show significant traffic from legacy systems.

**Edge-to-Origin TLS Configuration**:

**Cloudflare Setup**:

- **Client → Cloudflare**: Cloudflare's SSL certificate (automatic, managed by Cloudflare)
- **Cloudflare → Origin Server**: Origin server's SSL certificate (Cloudflare Origin Certificate or self-signed)
- **SSL Mode**: Set to **Strict** or **Full (Strict)** in Cloudflare dashboard
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
   - **Required for**: HIPAA, PCI-DSS, SOC 2, zero-trust architecture
   - Defense in depth - traffic encrypted even within VPC

**Database Connection Encryption**:

Always enforce SSL/TLS for database connections to prevent credential exposure:

- **AWS RDS**: Set `require_secure_transport = 1` parameter, use `sslmode=require` in connection string
- **GCP Cloud SQL**: Enable "Require SSL" option, download server CA certificate
- **Azure Database**: Set `require_secure_transport = ON`, use SSL connection string parameter

Example connection strings:

```python
# PostgreSQL with SSL
DATABASE_URL = "postgresql://user:pass@host:5432/db?sslmode=require"

# MySQL with SSL
DATABASE_URL = "mysql://user:pass@host:3306/db?ssl-mode=REQUIRED"
```

**Service-to-Service Communication**:

- **Kubernetes deployments**: Use Istio service mesh for automatic mutual TLS (mTLS) between pods (see Kubernetes Security Guide)
- **Non-Kubernetes**: Internal API calls should use HTTPS or be isolated in private network with strict access controls
- **External third-party APIs**: Always use HTTPS, validate TLS certificates, enforce TLS 1.2+ minimum

**Certificate Management**:

- Use managed certificates with automatic renewal: Let's Encrypt (free), AWS ACM, GCP Certificate Manager, Azure certificates
- Set HSTS header `Strict-Transport-Security: max-age=31536000; includeSubDomains` to force HTTPS in browsers
- Automate rotation for origin certificates (30-90 day validity recommended)

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
@app.get("/users/{id}")  # Only allows GET
async def get_user(id: int):
    return user

@app.post("/users")  # Only allows POST
async def create_user(user: User):
    return created_user
```

This prevents method confusion attacks and ensures endpoints behave as designed. For example, a GET endpoint should never modify data, and attempting a POST to a read-only endpoint should be immediately rejected.

**JSON Schema Validation**:

Validate request bodies against expected schema, return **400 Bad Request** if validation fails.

Validation libraries:

- TypeScript/Node.js: [Zod](https://github.com/colinhacks/zod), [Joi](https://github.com/hapijs/joi)
- Python: [Pydantic](https://github.com/pydantic/pydantic)
- Go: [go-playground/validator](https://github.com/go-playground/validator)

Validate: Required fields, data types, value constraints (length, ranges, patterns), enum values, nested structure

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

- Validate paths don't contain `..`, `/`, `\`
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

**Per-User Limits** (by tier):

- Free: 100 requests/hour
- Pro: 1,000 requests/hour
- Enterprise: 10,000+ requests/hour

**Endpoint-Specific Limits**:

- `/login`: 5 requests/minute (brute force prevention)
- `/password-reset`: 3 requests/hour (abuse prevention)
- `/search`: 100 requests/minute (expensive operations)
- `/profile`: 1,000 requests/minute (cheap reads)

**IP-Based Limits**:

- 1,000 requests/hour per IP for unauthenticated endpoints

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

**2xx Success:**

- `200 OK`: Successful GET, PUT, PATCH, DELETE
- `201 Created`: Successful POST creating resource
- `204 No Content`: Successful DELETE with no body

**4xx Client Errors:**

- `400 Bad Request`: Invalid request body or validation failure
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Authenticated but lacks permission
- `404 Not Found`: Resource doesn't exist
- `405 Method Not Allowed`: Wrong HTTP method
- `409 Conflict`: Resource conflict
- `429 Too Many Requests`: Rate limit exceeded

**5xx Server Errors:**

- `500 Internal Server Error`: Unexpected error
- `503 Service Unavailable`: Service temporarily down

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

Store active logs in fast-access storage for debugging and monitoring:

- AWS CloudWatch Logs, GCP Cloud Logging, Azure Monitor
- Splunk, ELK Stack, Loki
- Enable searching, filtering, real-time alerts
- 30-day retention sufficient for active troubleshooting

### Cold Storage (Multi-Year for Compliance)

Archive logs in compressed, low-cost storage for regulatory compliance:

- AWS S3 Glacier / Glacier Deep Archive
- GCP Coldline Storage / Archive Storage
- Azure Cool Blob Storage / Archive Blob Storage

**Retention requirements:**

- SOC2: 1-7 years
- ISO 27001: 1-3 years
- HIPAA: 6 years
- GDPR: 1-3 years

**Archive process:**

1. Export from hot storage after 30 days
2. Compress (gzip, zstd)
3. Upload to cold storage with lifecycle policies
4. Delete from hot storage

### Compliance Considerations

**Data Privacy**:

- Never log sensitive PII (passwords, credit cards, SSNs) without encryption/hashing
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
go func() { user = getUser(userID); wg.Done() }()
go func() { posts = getPosts(userID); wg.Done() }()
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

- AWS API Gateway, GCP Cloud Endpoints cache responses
- Configure TTL per endpoint (seconds to hours)
- Reduces backend invocations for identical requests
- **Critical**: For authenticated endpoints, cache key MUST include authentication context (user ID, auth token) to prevent serving user A's data to user B
- Safe to cache: Public GET endpoints, static reference data
- Dangerous to cache: User-specific data, personalized responses (without proper cache keys)

**Application-Level Caching** (Redis, Memcached):

- Cache database query results and expensive computations
- Session storage for faster lookups
- Set appropriate TTLs based on data staleness tolerance

**Database Optimization**:

- Add indexes on frequently queried fields
- Use connection pooling (RDS Proxy for serverless)
- Implement read replicas for read-heavy workloads

**Cache Invalidation**:

- Invalidate on data updates (write-through or write-behind)
- Use versioned cache keys for easy invalidation
- Monitor cache hit rates to optimize TTLs

### Serverless Cold Start Mitigation

Beyond provisioned concurrency and scheduled invocations (see Architecture Patterns section):

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
- Return deprecation headers: `Deprecation: true`, `Sunset: Wed, 11 Nov 2026 11:11:11 GMT`
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

**Serverless Functions** (AWS Lambda, GCP Cloud Functions, Azure Functions):

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
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:region:account:log-group:/aws/lambda/api-*"
    }
  ]
}
```

**GCP Service Account**:

```bash
# Create service account
gcloud iam service-accounts create api-function-sa

# Grant specific permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:api-function-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Deploy with service account
gcloud functions deploy api-function \
  --service-account=api-function-sa@PROJECT_ID.iam.gserviceaccount.com
```

**Azure Managed Identity**:

```bash
# Enable managed identity
az functionapp identity assign --name api-function-app --resource-group production-rg

# Grant Key Vault access
az keyvault set-policy --name prod-keyvault --object-id PRINCIPAL_ID --secret-permissions get
```

**Container/VM Roles**:

- AWS: Attach IAM role to EC2 instance profile or ECS task role
- GCP: Use Workload Identity (see Kubernetes Security Guide)
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

**Lifecycle Management:**

Prevent accumulation of unused, over-privileged, or compromised accounts through rigorous lifecycle controls.

**Creation Process:**

1. Developer requests with justification (application name, required permissions, environment)
2. Security team reviews for least privilege and naming compliance
3. Provision via Infrastructure as Code (Terraform) with auto-tagging
4. Document in service account registry (owner, permissions, applications, last reviewed)

**Rotation Procedures (Long-Lived Credentials):**

While workload identity/IAM roles use temporary credentials, service account keys require rotation:

- **Schedule**: Every 90 days (compliance: PCI-DSS, SOC2, ISO 27001)
- **Immediate**: Suspected compromise, employee departure, key leakage

**Zero-Downtime Rotation:**

1. Generate new key and deploy to 10% of instances (canary)
2. Monitor for authentication errors
3. Roll out to remaining 90%, keep old key active (12-24 hour overlap)
4. Validate all services using new credentials
5. Disable old key after 24 hours, delete after confirmation

**Monitoring for Compromise:**

Set up automated alerts for suspicious patterns:

- **Geographic anomalies**: Access from unexpected countries/regions
- **Time anomalies**: Activity outside normal business hours (3 AM when no deployments occur)
- **Excessive API calls**: 10x normal volume indicates data exfiltration or misconfiguration
- **Failed authentication**: >5 attempts in 10 minutes suggests brute force
- **Permission escalation**: Attempts to access resources outside granted permissions

**Detection Example (AWS CloudTrail):**

```python
# Monitor AssumeRole events for anomalies
def detect_anomalies():
    events = cloudtrail.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'}],
        StartTime=datetime.now() - timedelta(hours=1)
    )

    for event in events:
        source_ip = event.get('SourceIPAddress')
        if not is_expected_ip(source_ip):
            alert_security_team(f"Anomalous access from {source_ip}")
```

**Service Accounts vs Workload Identity:**

| Feature         | Service Account Keys | Workload Identity (IAM Roles) |
| --------------- | -------------------- | ----------------------------- |
| Rotation        | Manual, 90 days      | Automatic, 15-60 min          |
| Compromise Risk | High (long-lived)    | Low (temporary)               |
| Leakage Risk    | High (keys in logs)  | None (no keys)                |
| Use Case        | Cross-cloud, CI/CD   | Cloud-native apps             |

**Recommendation**: Always prefer workload identity (AWS IRSA, GKE Workload Identity, AKS Managed Identity) over service account keys when available. Use keys only when workload identity is not an option.

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
import boto3
from functools import lru_cache

secrets_client = boto3.client('secretsmanager')

@lru_cache(maxsize=128)
def get_secret(secret_name):
    response = secrets_client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

def lambda_handler(event, context):
    db_password = get_secret('prod/api/db-password')
    # Secret cached for container lifetime
```

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
import time
from threading import Thread

class SecretManager:
    def __init__(self):
        self.secrets = {}
        Thread(target=self._refresh_loop, daemon=True).start()

    def _refresh_loop(self):
        while True:
            self.secrets['db_password'] = fetch_secret('prod/api/db-password')
            time.sleep(3600)  # Refresh hourly
```

### Database Access

**Application User (Non-Root)**:

```sql
-- PostgreSQL example
CREATE USER api_app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, orders TO api_app_user;
REVOKE CREATE ON SCHEMA public FROM api_app_user;
```

**IAM Database Authentication** (eliminates passwords):

AWS RDS IAM Auth:

```python
import boto3
import pymysql

rds_client = boto3.client('rds')
token = rds_client.generate_db_auth_token(
    DBHostname='prod-db.cluster.us-east-1.rds.amazonaws.com',
    Port=3306,
    DBUsername='api_iam_user',
    Region='us-east-1'
)

connection = pymysql.connect(
    host='prod-db.cluster.us-east-1.rds.amazonaws.com',
    user='api_iam_user',
    password=token,  # Token valid 15 minutes
    ssl={'ssl_mode': 'REQUIRED'}
)
```

GCP Cloud SQL and Azure Database support similar IAM authentication.

### Monitoring and Auditing

**Enable Cloud Audit Logs**:

- AWS CloudTrail: Log IAM role assumptions, API calls, secret accesses
- GCP Cloud Audit Logs: Log service account usage, Secret Manager access
- Azure Activity Logs: Log managed identity auth, Key Vault access

**Alert on Suspicious Activity**:

- Failed authentication (>5 attempts in 10 minutes)
- Secret access from unexpected IPs/regions
- New IAM policy attachments or role assumptions
- Service account usage outside normal hours

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

### Authentication & Authorization Attacks

**Credential Stuffing**

- Attack: Stolen username/password pairs used for unauthorized access
- Mitigated by: Edge rate limiting, application `/login` limits (5 req/min), failed auth monitoring, IP blocking

**JWT Token Manipulation**

- Attack: Tampering with tokens to elevate privileges or impersonate users
- Mitigated by: Complete JWT validation (signature, issuer, audience, expiration), algorithm confusion prevention (RS256 only), short-lived tokens (15 min)

**API Key Exposure & Abuse**

- Attack: Leaked keys from GitHub or client-side code used to access services
- Mitigated by: Secret scanning (TruffleHog, GitHub), secrets in external vaults, per-user rate limiting, automated rotation

### Injection & Input Attacks

**SQL Injection**

- Attack: Malicious SQL injected into parameters to access/modify database
- Mitigated by: Parameterized queries (prepared statements), input validation (Zod, Pydantic, Joi), WAF rules blocking injection patterns, SAST scanning (Opengrep) catching vulnerable code pre-deployment

**Database Breach & Data Exfiltration**

- Attack: Direct database access via compromised credentials, stolen backups, or insider threat exposing plaintext sensitive data
- Mitigated by: Managed database encryption at rest (AWS RDS, GCP Cloud SQL, Azure TDE), application-level encryption for PII/PHI/PCI data (AES-256-GCM with KMS), encrypted backups, secrets in external vaults, least-privilege database access

**Information Disclosure via Error Messages**

- Attack: Extracting sensitive data from verbose errors (database details, file paths, internal IPs)
- Mitigated by: Generic external error messages, detailed internal-only logging, request IDs for support, consistent error structure

### Availability & Performance Attacks

**DDoS / Resource Exhaustion**

- Attack: Overwhelming API with requests to cause degradation or outage
- Mitigated by: Edge DDoS protection (Cloudflare, AWS Shield, Cloud Armor), aggressive edge rate limiting (100-2000 req/min per IP), endpoint-specific limits, auto-scaling

**Cache Poisoning**

- Attack: Serving user A's cached data to user B, leaking sensitive information
- Mitigated by: Cache keys include authentication context, `Cache-Control: no-store` on sensitive endpoints, proper CORS, authentication-aware API Gateway caching

### Supply Chain & Dependencies

**Dependency Vulnerabilities**

- Attack: Exploiting known vulnerabilities in outdated libraries
- Mitigated by: Dependabot automated updates catching vulnerable packages, pre-deployment security scans, regular audits, timely patching

## 17. References

### Security Tools

- [Dependabot](https://github.com/dependabot/dependabot-core) - Automated dependency updates
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning
- [Opengrep](https://github.com/opengrep/opengrep) - Static application security testing
- [Coraza](https://github.com/corazawaf/coraza) - Web application firewall
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) - Web application firewall engine

### Validation & Rate Limiting

- [Zod](https://github.com/colinhacks/zod) - TypeScript schema validation
- [Joi](https://github.com/hapijs/joi) - JavaScript schema validation
- [Pydantic](https://github.com/pydantic/pydantic) - Python data validation
- [go-playground/validator](https://github.com/go-playground/validator) - Go struct validation
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit) - Node.js rate limiting
- [slowapi](https://github.com/laurentS/slowapi) - Python rate limiting
- [tollbooth](https://github.com/didip/tollbooth) - Go rate limiting

### Standards & Documentation

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application security risks
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) - API security risks
- [OpenAPI Specification](https://swagger.io/specification/) - API documentation standard
- [OAuth 2.0](https://oauth.net/2/) - Authorization framework
- [JWT](https://jwt.io/) - JSON Web Tokens standard
