# Secure Production Handbook

Battle-tested security guides for production systems. Cloud-agnostic patterns for AWS, GCP, and Azure.

Built from real-world experience securing APIs, databases, Kubernetes clusters, and data pipelines at scale. These guides prevent the mistakes that led to breaches at Capital One, Uber, Equifax, and thousands of other companies.

## Core Philosophy

Security is simple when you follow three principles:

1. **Use managed services** - Cloud providers employ hundreds of security engineers. You don't.
2. **Layer your defenses** - Every control will eventually fail. Plan for it.
3. **Keep it simple** - Complexity is the enemy of security. The best decision is often the simplest one.

## The 10 Essential Principles

### 1. Managed Services Are Non-Negotiable

Never self-host what cloud providers will manage for you. Not because you can't, but because you shouldn't have to.

**Use managed:**

- Databases: RDS, Cloud SQL, Azure Database (not self-hosted PostgreSQL)
- Kubernetes: EKS, GKE, AKS (not bare metal clusters)
- Message queues: MSK, Pub/Sub, Event Hubs (not self-managed Kafka)

**Why:** Automatic patching, built-in backups, expert-managed security, 99.95%+ SLA. You eliminate entire classes of vulnerabilities by delegating to teams that specialize in hardening these services.

**Trade-off:** Slightly higher cost ($50-150/month vs $0), but you avoid the $200k/year platform engineer and the 3am database outage.

**Cloud provider equivalents:**

| Service        | AWS             | GCP            | Azure                   |
| -------------- | --------------- | -------------- | ----------------------- |
| Kubernetes     | EKS             | GKE            | AKS                     |
| Databases      | RDS             | Cloud SQL      | Database for PostgreSQL |
| Object Storage | S3              | Cloud Storage  | Blob Storage            |
| Secrets        | Secrets Manager | Secret Manager | Key Vault               |
| Logging        | CloudWatch      | Cloud Logging  | Monitor                 |

---

### 2. Defense in Depth: Security Happens in Layers

A breach requires breaking through multiple independent controls. Design your architecture so that compromising one layer doesn't compromise everything.

**Example API security stack:**

```
Internet → WAF (blocks attacks)
        → Rate Limiting (blocks abuse)
        → Authentication (verifies identity)
        → Authorization (checks permissions)
        → Input Validation (sanitizes data)
        → Database ACLs (limits access)
        → Field Encryption (protects data)
```

**Why:** The Capital One breach happened because a single misconfigured WAF gave access to everything. With defense in depth, that misconfiguration would have hit encrypted data the attacker couldn't decrypt.

---

### 3. Encrypt Everything, Everywhere, Always

Encryption is your last line of defense when all access controls fail.

**Three layers required:**

1. **At-rest:** KMS/Cloud KMS for databases, object storage, backups
2. **In-transit:** TLS 1.2+ for all network traffic (no exceptions)
3. **Field-level:** Application-layer encryption for PII/PHI/PCI before storing

**Why field-level matters:** Database encryption protects against stolen disks. Field-level encryption protects against stolen databases. Even your own DBAs can't read the plaintext without KMS keys.

```python
# Database admin sees this in the database:
encrypted_ssn = "AQICAHh8sK3...c5Jwj2mA=="

# Not this:
plaintext_ssn = "123-45-6789"
```

---

### 4. Least Privilege: Grant the Minimum Necessary

Every credential, API key, and IAM role should have the smallest possible set of permissions. When (not if) credentials leak, you want to limit the damage.

**Examples:**

- Database users: `SELECT, INSERT` on 3 tables, not `ALL PRIVILEGES` on `*.*`
- IAM roles: `s3:GetObject` on one bucket, not `s3:*` on `arn:aws:s3:::*`
- Kubernetes: namespace-scoped `edit`, not cluster-wide `cluster-admin`

**Why:** The Uber breach exposed 57 million records because stolen credentials had access to everything. Least privilege would have limited the breach to a single service.

---

### 5. Secrets Belong in Vaults, Nowhere Else

The #1 cause of credential leaks is hardcoded secrets. No exceptions.

**Always use:**

- AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault

**Never use:**

- Environment variables in Dockerfiles
- `.env` files committed to Git
- API keys in frontend JavaScript
- Kubernetes ConfigMaps for sensitive data

**Enforce with:**

- TruffleHog: Scans every commit, blocks pushes containing secrets
- GitHub Secret Scanning: Automatically detects committed credentials
- Pre-commit hooks: Prevents secrets from reaching version control

**Why:** GitHub has over 10,000 exposed AWS credentials at any given time. Automated scanning catches 99% of these before they become breaches.

---

### 6. Network Isolation: Private Subnets Are Required

Your data layer should never be accessible from the internet. Ever.

**Architecture:**

```
Internet → Load Balancer (public subnet)
         → Application Servers (private subnet)
         → Database (private subnet, no public IP)
```

**Security groups allow:**

- Database accepts connections only from application server security group
- Application servers accept connections only from load balancer
- No inbound connections from 0.0.0.0/0 to databases

**Why:** The MongoDB ransomware attacks of 2017-2020 compromised over 100,000 databases. Every single one was internet-accessible. Private subnets would have prevented all of them.

---

### 7. Backups Must Be Automated and Tested

You will lose data. The only question is whether you can recover it.

**Requirements:**

- Automated daily snapshots (no manual backups)
- Point-in-time recovery (5-minute granularity for databases)
- 30 days hot storage, 7 years cold for compliance
- Cross-region replication for disaster recovery

**Critical:** Test recovery quarterly. Actually restore from backup and validate data integrity. Untested backups are not backups.

**Why:** GitLab accidentally deleted their production database in 2017. Their backups hadn't worked for months. They lost 6 hours of data. Tested backups would have limited the loss to 5 minutes.

**RTO/RPO targets:**

- Recovery Time Objective (RTO): 1-2 hours
- Recovery Point Objective (RPO): 5 minutes (with PITR)

---

### 8. Audit Logs Are Non-Negotiable for Compliance

You need to know who did what, when, and from where. For compliance, for incident response, for threat detection.

**Log everything:**

- CloudTrail / Cloud Logging: Every API call (who, what, when, from where)
- Database audit logs: Table access, schema changes, failed authentication
- Application logs: User actions, API requests, authentication events

**Retention requirements:**

- 30 days hot (fast search, alerting)
- 7 years cold (compliance: SOC2, HIPAA, GDPR)

**Structure logs as JSON:**

```json
{
  "timestamp": "2026-01-30T10:15:30Z",
  "user_id": "user_12345",
  "action": "database.query",
  "resource": "users_table",
  "result": "success",
  "request_id": "req_abc123"
}
```

**Why:** When Capital One was breached, audit logs showed exactly what the attacker accessed. Without logs, they wouldn't have known the scope or been able to notify affected customers.

---

### 9. Rate Limiting Prevents Abuse at Every Layer

Attacks scale. Your defenses should too.

**Implement at three layers:**

**Edge (Cloudflare, AWS WAF):**

- 100-2000 requests/minute per IP
- Blocks DDoS, credential stuffing

**Application:**

- `/login`: 5 requests/minute per IP (prevents brute force)
- `/api/sensitive`: 10 requests/minute per user (prevents abuse)

**Database:**

- Connection pooling: 20-100 max connections (prevents exhaustion)

**Store state in:**

- Redis (fast, survives restarts)
- DynamoDB / Firestore (serverless, scales automatically)

**Why:** The GitHub DDoS attack of 2018 peaked at 1.35 Tbps. Rate limiting at the edge absorbed the attack before it reached their infrastructure.

---

### 10. Pin Every Version, Never Use `latest`

`latest` is a security vulnerability disguised as convenience.

**Always pin specific versions:**

- Application dependencies: `"react": "18.2.0"` (not `"^18.0.0"` or `"latest"`)
- Base images: `FROM python:3.11.7-slim` (not `FROM python:latest`)
- Kubernetes: `image: registry/app:v1.2.3` (not `image: registry/app:latest`)

**Why `latest` is dangerous:**

- Breaks reproducibility (what you tested isn't what deployed)
- Enables supply chain attacks (attacker compromises `latest` tag)
- Hides dependency changes (silent updates introduce vulnerabilities)

**Use Dependabot or Renovate:**

- Automated pull requests for updates
- Test before merging
- Full change history in Git

**Why:** The Log4Shell vulnerability (2021) affected every application using `latest` or version ranges. Pinned versions gave teams time to test patches before deploying.

---

## The Golden Rule

**Security is enforced server-side, never client-side.**

- Frontend validation is UX, not security
- JWT verification happens on the backend, not in React
- Authorization checks happen in database queries, not UI conditionals
- All client input is malicious until proven otherwise

A user with browser DevTools can bypass any client-side security. Design accordingly.

---

## Guides

- **[API Security Design Guide](api_security_design_guide.md)** - REST APIs, edge protection, authentication, rate limiting
- **[Database Security Guide](database_security_guide.md)** - PostgreSQL, encryption, backups, high availability
- **[Kubernetes Security Guide](kubernetes_security_guide.md)** - Network policies, secrets management, GitOps
- **[Object Storage Security Guide](object_storage_security_guide.md)** - S3/GCS/Blob Storage, access control, compliance
- **[Data Pipeline Security Guide](data_pipeline_security_guide.md)** - Kafka and Spark security
- **[React Frontend Security Guide](react_frontend_security_guide.md)** - Client-side security, authentication patterns
- **[SLSA Build Pipeline Guide](slsa_build_pipeline_guide.md)** - Supply chain security, SLSA Level 3 compliance

---

**Last Updated:** January 2026
