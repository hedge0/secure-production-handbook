# Secure Production Handbook

Battle-tested security guides for production systems. Cloud-agnostic patterns for AWS, GCP, and Azure.

Built from real-world experience securing APIs, databases, Kubernetes clusters, and data pipelines at scale. These guides prevent the mistakes that led to breaches at Capital One, Uber, Equifax, and thousands of other companies.

## Core Philosophy

Security is simple when you follow three rules:

1. **Use managed services** - Cloud providers employ hundreds of security engineers. You don't.
2. **Layer your defenses** - Every control will eventually fail. Plan for it.
3. **Keep it simple** - Complexity is the enemy of security. The best decision is often the simplest one.

## The 10 Essential Principles

### 1. Managed Services Are Non-Negotiable

Never self-host what cloud providers will manage for you. Not because you can't, but because you shouldn't have to.

**Use managed:**

- Databases: RDS, Cloud SQL, Azure Database for PostgreSQL (not self-hosted PostgreSQL)
- Kubernetes: EKS, GKE, AKS (not bare metal clusters)
- Message queues: MSK, Managed Service for Apache Kafka (or Pub/Sub), Event Hubs (not self-managed Kafka)

**Why:** Automatic patching, built-in backups, expert-managed security, 99.95-99.99% SLA on Multi-AZ/HA deployments (single-instance tiers get less: 99.5% on RDS, 99.9% on Azure, no SLA on Cloud SQL). You eliminate entire classes of vulnerabilities by delegating to teams that specialize in hardening these services.

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

```text
Internet → WAF (blocks attacks)
        → Rate Limiting (blocks abuse)
        → Authentication (verifies identity)
        → Authorization (checks permissions)
        → Input Validation (sanitizes data)
        → Database ACLs (limits access)
        → Field Encryption (protects data)
```

**Why:** The Capital One breach (2019) chained three failures: an SSRF bug in a misconfigured WAF host, an instance metadata service (IMDSv1) that handed out the host's IAM role credentials, and a role that could list and read 700+ S3 buckets. The buckets were encrypted at rest, and it didn't matter: the stolen role was authorized to decrypt. What held was the field-level tokenization on most Social Security and account numbers. Every layer in this stack exists because the one above it will eventually fail; the layers that actually contain a breach are the ones an attacker's stolen credentials cannot unlock.

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

**Why:** In the 2016 Uber breach, attackers reused leaked passwords to log into engineers' GitHub accounts (no MFA), found an AWS access key hardcoded in a private repo, and pulled 57 million riders' and drivers' records from unencrypted S3 backups. The root failure was a hardcoded cloud credential (see Principle 5); a scoped, short-lived role instead of a static key with broad access would have turned the leak into a contained incident.

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
- GitHub Secret Scanning: Automatically detects committed credentials (free on public repos; private repos need GitHub Secret Protection, $19/active committer/month on Team and Enterprise Cloud)
- Aikido Security: Secrets detection plus SAST, dependency, IaC and container scanning in one platform, with a free Developer tier; it also ships a secrets pre-commit hook, and which findings can block a PR depends on your plan
- Pre-commit hooks: Prevents secrets from reaching version control

**Why:** GitGuardian counted 23.8 million new secrets pushed to public GitHub in 2024, up 25% year on year, and 70% of the secrets leaked in 2022 were still valid two years later. Scanning at commit time stops them before they become breaches.

---

### 6. Network Isolation: Private Subnets Are Required

Your data layer should never be accessible from the internet. Ever.

**Architecture:**

```text
Internet → Load Balancer (public subnet)
         → Application Servers (private subnet)
         → Database (private subnet, no public IP)
```

**Security groups allow:**

- Database accepts connections only from application server security group
- Application servers accept connections only from load balancer
- No inbound connections from 0.0.0.0/0 to databases

**Why:** In January 2017, automated ransom scripts wiped more than 27,000 internet-exposed MongoDB instances in about a week. In July 2020, another wave hit 22,900, nearly half of all MongoDB servers reachable from the internet. Every victim was bound to a public interface with no authentication. Private subnets would have prevented all of them.

---

### 7. Backups Must Be Automated and Tested

You will lose data. The only question is whether you can recover it.

**Requirements:**

- Automated daily snapshots (no manual backups)
- Point-in-time recovery (restore to any second; RDS ships transaction logs every 5 minutes, so the latest restorable time trails by up to 5 minutes)
- 30 days hot storage, 7 years cold (house policy, not a SOC 2, HIPAA or GDPR mandate); for backups full of personal data, GDPR's storage-limitation principle argues against blanket multi-year retention, so document why you keep them
- Cross-region replication for disaster recovery

**Critical:** Test recovery quarterly. Actually restore from backup and validate data integrity. Untested backups are not backups.

**Why:** In January 2017, a GitLab engineer accidentally deleted the primary production database directory. Their scheduled pg_dump backups had been silently producing empty files (a pg_dump 9.2 vs PostgreSQL 9.6 mismatch), and none of their five backup and replication mechanisms worked reliably. They restored a six-hour-old LVM snapshot and lost 6 hours of data. Tested backups would have limited the loss to 5 minutes.

**RTO/RPO targets:**

- Recovery Time Objective (RTO): 1-2 hours
- Recovery Point Objective (RPO): 5 minutes (with PITR)

---

### 8. Audit Logs Are Non-Negotiable for Compliance

You need to know who did what, when, and from where. For compliance, for incident response, for threat detection.

**Log everything:**

- CloudTrail / Cloud Audit Logs / Azure Activity Log: Every API call (who, what, when, from where). Management events are on by default; data events (S3 object reads, Lambda invokes) and GCP Data Access logs are off by default and must be enabled
- Database audit logs: Table access, schema changes, failed authentication
- Application logs: User actions, API requests, authentication events

**Retention requirements:**

- 30 days hot (fast search, alerting)
- 7 years cold (house policy; covers HIPAA's 6-year documentation rule, 45 CFR 164.316, and PCI DSS v4.0.1 Req 10.5.1's 12 months, 3 immediately available; SOC 2 and GDPR set no period, and GDPR's storage limitation means you must justify keeping logs with personal data)

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

- 100-2000 requests/minute per IP (AWS WAF counts over 1/2/5/10-minute windows; Cloudflare Free only counts in 10-second windows, per-minute periods need Pro or above)
- Slows down single-source abuse and scrapers; pair with bot management and MFA for distributed credential stuffing, and with provider DDoS protection for volumetric floods

**Application:**

- `/login`: 5 requests/minute per IP (prevents brute force)
- `/api/sensitive`: 10 requests/minute per user (prevents abuse)

**Database:**

- Connection pooling: 20-100 max connections (prevents exhaustion)

**Store state in:**

- Redis (fast, survives restarts)
- DynamoDB / Firestore (serverless, scales automatically)

**Why:** Rate limiting stops abuse, not floods. The 1.35 Tbps memcached amplification attack on GitHub (2018) was absorbed by rerouting traffic through Akamai Prolexic's scrubbing network, not by a rate limiter. Use your provider's volumetric DDoS protection (AWS Shield, Cloud Armor, Cloudflare) for the flood, and rate limits for the brute force, scraping, and abuse that get through it.

---

### 10. Pin Every Version, Never Use `latest`

`latest` is a security vulnerability disguised as convenience.

**Always pin specific versions:**

- Application dependencies: an exact `"react": "19.3.0"` in package.json (not `"^19.0.0"` or `"latest"`) plus a committed lockfile (`package-lock.json`, `pnpm-lock.yaml`) installed with `npm ci` / `pnpm install --frozen-lockfile`; the lockfile is what pins the transitive tree
- Base images: `FROM python:3.14.7-slim@sha256:<digest>` (not `FROM python:latest`); a version tag alone is still mutable, the digest is not
- Kubernetes: `image: registry/app:v1.2.3@sha256:<digest>` (not `image: registry/app:latest`); Renovate and Dependabot keep digests current

**Why `latest` is dangerous:**

- Breaks reproducibility (what you tested isn't what deployed)
- Enables supply chain attacks (anyone with push access can re-point a tag, `latest` or `v1.2.3`; only a digest cannot move)
- Hides dependency changes (silent updates introduce vulnerabilities)

**Use Dependabot or Renovate:**

- Automated pull requests for updates
- Test before merging
- Full change history in Git

**Why:** In October 2021, a hijacked maintainer account published ua-parser-js 0.7.29, 0.8.0 and 1.0.0 (~8M weekly downloads) with a Monero miner and a Windows password stealer. The malicious versions were live for about four hours. Any build that resolved a floating range in that window pulled the malware; exact pins plus a committed lockfile did not. Pinning is not a patch, though: a pinned vulnerable release is still vulnerable, so merge the Dependabot or Renovate bumps fast.

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

## Sources

- Capital One (2019): https://www.capitalone.com/digital/facts2019/ and https://threats.wiz.io/all-incidents/capital-one-incident-march-2019
- Uber (2016): https://www.ftc.gov/system/files/documents/cases/152_3054_c-4662_uber_technologies_revised_complaint.pdf
- GitGuardian secrets statistics: https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/
- MongoDB ransomware (2017): https://thehackernews.com/2017/01/mongodb-database-security.html
- MongoDB ransomware (2020): https://www.darkreading.com/cloud-security/22-900-mongodb-databases-affected-in-ransomware-attack
- GitLab (2017): https://about.gitlab.com/blog/postmortem-of-database-outage-of-january-31/
- GitHub DDoS (2018): https://github.blog/news-insights/company-news/ddos-incident-report/
- ua-parser-js (2021): https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/

**Last Updated:** September 22, 2026
