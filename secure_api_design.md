# Secure API Design Guide

A cloud-agnostic guide for building production-ready APIs with a practical blend of security and performance. This guide includes industry best practices and lessons learned from real-world implementations across serverless and traditional architectures.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Architecture Patterns](#architecture-patterns)
4. [Application Security (Pre-Deployment)](#application-security-pre-deployment)
5. [Edge Security Layer](#edge-security-layer)
6. [Runtime Security Layer](#runtime-security-layer)
7. [Rate Limiting & Throttling](#rate-limiting--throttling)
8. [Error Handling & Responses](#error-handling--responses)
9. [Observability & Compliance](#observability--compliance)
10. [Performance Optimization](#performance-optimization)
11. [API Versioning](#api-versioning)
12. [References](#references)

## Overview

This guide outlines a production-grade API design approach that balances security, performance, and maintainability. The patterns are cloud-agnostic and work with major cloud providers (AWS, GCP, Azure) and their respective services for serverless functions, container orchestration, secrets management, and logging.

**Core Principles:**

- **Security First**: Defense in depth from edge to application to data layer
- **Performance Conscious**: Optimize for latency and throughput without compromising security
- **Cloud Agnostic**: Works across AWS, GCP, Azure with equivalent services
- **Production Ready**: Battle-tested patterns from real-world deployments

## Prerequisites

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

## Architecture Patterns

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

## Application Security (Pre-Deployment)

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

## Edge Security Layer

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

## Runtime Security Layer

Validate and secure every API request at the application layer before processing.

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

### Request Validation

**HTTP Method Validation**:

Validate HTTP method matches endpoint requirements, return **405 Method Not Allowed** for incorrect methods:

- GET: Read-only, no body
- POST: Create resources with body
- PUT/PATCH: Update resources with body
- DELETE: Remove resources

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

## Rate Limiting & Throttling

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

## Error Handling & Responses

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

## Observability & Compliance

Implement comprehensive logging for security, debugging, and regulatory compliance (SOC2, ISO 27001, HIPAA, etc.).

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

### Log Correlation with Request IDs

Use request IDs to correlate logs across distributed systems:

- Track request flow through microservices
- Link audit logs, error logs, performance metrics
- Debug issues across service boundaries
- Essential for troubleshooting in distributed architectures

## Performance Optimization

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

## API Versioning

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

## References

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
