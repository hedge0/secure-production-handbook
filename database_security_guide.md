# Database Security Guide

**Last Updated:** September 22, 2026

A cloud-agnostic guide focused on securing production SQL databases (primarily PostgreSQL) with defense-in-depth security, high availability, and disaster recovery. Includes comparisons to NoSQL alternatives and guidance on when each is appropriate. This guide includes industry best practices and lessons learned from real-world implementations.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Architecture & Deployment](#3-architecture--deployment)
   - [Managed Databases (Required)](#managed-databases-required)
   - [High Availability & Multi-AZ](#high-availability--multi-az)
   - [Read Replica Architecture](#read-replica-architecture)
4. [NoSQL Databases: When to Use and Security Considerations](#4-nosql-databases-when-to-use-and-security-considerations)
   - [When to Use NoSQL vs SQL](#when-to-use-nosql-vs-sql)
   - [NoSQL Security Implementation](#nosql-security-implementation)
   - [Security Comparison and Recommendations](#security-comparison-and-recommendations)
5. [Network Security](#5-network-security)
   - [Network Isolation](#network-isolation)
   - [Security Groups](#security-groups)
   - [Connection from Applications](#connection-from-applications)
6. [Authentication & Access Control](#6-authentication--access-control)
   - [Least-Privilege Database Users](#least-privilege-database-users)
   - [Row-Level Security for Multi-Tenant Data](#row-level-security-for-multi-tenant-data)
   - [IAM Database Authentication](#iam-database-authentication)
   - [Secrets Management](#secrets-management)
7. [Encryption](#7-encryption)
   - [Encryption at Rest](#encryption-at-rest)
   - [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi)
   - [Encryption in Transit](#encryption-in-transit)
8. [Performance & Scaling](#8-performance--scaling)
   - [Connection Pooling](#connection-pooling)
   - [Query Timeouts for DoS Prevention](#query-timeouts-for-dos-prevention)
   - [Read/Write Splitting](#readwrite-splitting)
   - [Query Optimization](#query-optimization)
   - [Monitoring](#monitoring)
9. [Backup & Disaster Recovery](#9-backup--disaster-recovery)
   - [Automated Backups](#automated-backups)
   - [Point-in-Time Recovery](#point-in-time-recovery)
   - [Disaster Recovery Procedures](#disaster-recovery-procedures)
10. [Compliance & Auditing](#10-compliance--auditing)
    - [Audit Logging](#audit-logging)
    - [Data Retention](#data-retention)
11. [Attack Scenarios Prevented](#11-attack-scenarios-prevented)
12. [References](#12-references)

## 1. Overview

This guide provides production-ready patterns for securing SQL databases across cloud providers, with PostgreSQL as the primary focus. A dedicated section compares SQL to NoSQL alternatives (DynamoDB, Firestore, MongoDB Atlas) and provides guidance on when each is appropriate. Databases store critical business data, user information, and application state. A database breach can result in massive data loss, regulatory fines, and reputational damage.

**Common Use Cases:**

- Application state and session storage
- User authentication data (credentials, profiles, preferences)
- Financial transactions and payment processing
- Healthcare records and PII (HIPAA compliance)
- E-commerce orders and inventory
- Analytics and reporting data
- Audit trails and compliance logging

**Real-World Breaches:**

- **Uber (2016)**: Attackers reused leaked passwords to get into engineers' GitHub accounts (no MFA), found a hardcoded AWS access key in a private repo, and downloaded unencrypted database backups from S3, exposing 57M riders and drivers
- **Equifax (2017)**: An unpatched Apache Struts flaw (CVE-2017-5638) in a public dispute portal, then plaintext database credentials on that server, let attackers query 147M consumers' records for 76 days undetected; settlement up to $700M
- **Capital One (2019)**: An attacker used an SSRF bug in a misconfigured WAF on EC2 to pull the instance's over-privileged IAM role credentials from the metadata service, and ~106M credit applications were copied out of S3 - no database was touched (not RDS)
- **MGM Resorts (2019)**: A compromised cloud server leaked guest contact records; MGM confirmed 10.6M guests (a later dark-web listing claimed 142M, never confirmed)

**Core Principles:**

- **Defense in Depth**: Multiple security layers from network to encryption to access control
- **Least Privilege**: Minimize access permissions and blast radius
- **Managed Services First**: Use cloud-managed databases to reduce operational burden
- **Encryption Everywhere**: At-rest, in-transit, and field-level for sensitive data
- **High Availability**: Multi-AZ deployments with automatic failover
- **Tested Recovery**: Automated backups with validated recovery procedures

## 2. Prerequisites

### Required Tools

- [psql](https://www.postgresql.org/docs/current/app-psql.html) - PostgreSQL command-line client
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning

### External Services

Cloud-agnostic service options for managed databases, secrets management, and backup storage.

| Service Category                  | AWS                      | GCP                                | Azure                             | Self-Hosted / Open Source |
| --------------------------------- | ------------------------ | ---------------------------------- | --------------------------------- | ------------------------- |
| **Managed Databases** (required)  | RDS (PostgreSQL, Aurora) | Cloud SQL                          | Database for PostgreSQL           | -                         |
| **Secrets Management** (required) | Secrets Manager          | Secret Manager                     | Key Vault                         | HashiCorp Vault           |
| **Key Management** (required)     | KMS                      | Cloud KMS                          | Key Vault                         | HashiCorp Vault           |
| **Backup Storage** (compliance)   | S3 (Standard, Glacier)   | Cloud Storage (Standard, Coldline) | Blob Storage (Hot, Cool, Archive) | MinIO, S3-compatible      |
| **Logging & SIEM** (required)     | CloudWatch Logs          | Cloud Logging                      | Monitor                           | Splunk, ELK Stack, Loki   |

## 3. Architecture & Deployment

### Managed Databases (Required)

**Never run databases in Kubernetes or on self-managed VMs for production workloads.** Use managed cloud databases.

**Why Managed Databases:**

| Aspect                 | Managed (RDS, Cloud SQL, Azure DB)           | Self-Hosted                       |
| ---------------------- | -------------------------------------------- | --------------------------------- |
| **Operational Burden** | Low - provider handles patching, backups, HA | High - you manage everything      |
| **High Availability**  | Built-in Multi-AZ automatic failover         | Manual configuration required     |
| **Backups**            | Automatic daily snapshots, PITR              | Manual backup system              |
| **Security**           | Managed patching, encryption, isolation      | You handle OS/DB patches          |
| **Best For**           | Production workloads                         | Extreme performance/control needs |

**Configuration:**

- Deploy in private subnets
- Security group allows only application servers (Kubernetes worker nodes, containers, serverless)
- Multi-AZ enabled (automatic failover in 60-120 seconds)
- Automated daily snapshots with 7-30 day retention
- Point-in-time recovery enabled
- Create application database user with least privilege (never use root/admin for applications)
- Grant only required permissions (SELECT, INSERT, UPDATE, DELETE on specific tables)

### High Availability & Multi-AZ

Deploy databases across multiple availability zones for automatic failover.

**Multi-AZ Architecture:**

```
Primary (AZ-1)
  ↓ Synchronous replication
Standby (AZ-2)
  ↓ Automatic failover (60-120s)
```

**Cloud Provider Implementation:**

- **AWS RDS**: Multi-AZ deployment (synchronous replication, automatic failover)
- **GCP Cloud SQL**: High availability configuration with automatic failover
- **Azure Database**: Zone-redundant high availability

**Benefits:**

- Protects against AZ-level outages
- Zero data loss during failover (synchronous replication)
- Automatic failover without manual intervention
- Transparent to application (same endpoint)

### Read Replica Architecture

Scale read-heavy workloads (>80% reads) by routing reads to replicas and writes to primary.

**Architecture:**

```
Primary (writes only)
  ├─→ Read Replica 1 (AZ-1)
  ├─→ Read Replica 2 (AZ-2)
  └─→ Read Replica 3 (cross-region)
```

**When to Use:**

- Read-heavy workloads (>80% reads)
- Analytics/reporting queries (offload from primary)
- Cross-region disaster recovery

**Replica Lag:**

- Asynchronous replication typically lags 100-500ms
- For read-after-write consistency, query primary
- Monitor replica lag and alert if exceeds 5 seconds

## 4. NoSQL Databases: When to Use and Security Considerations

### When to Use NoSQL vs SQL

**Default to SQL for most applications.** Use managed PostgreSQL (RDS, Cloud SQL, Azure Database) unless you have proven requirements for NoSQL.

| Aspect                | SQL (PostgreSQL)                             | NoSQL (DynamoDB, Firestore, MongoDB)      |
| --------------------- | -------------------------------------------- | ----------------------------------------- |
| **Data Integrity**    | ACID transactions, foreign keys, constraints | Limited transactions; consistency varies  |
| **Query Flexibility** | Complex JOINs, ad-hoc queries                | Must design for access patterns upfront   |
| **Security Model**    | Row-level permissions, query validation      | Application-enforced, no query validation |
| **Audit Logging**     | Granular (pgaudit)                           | Vendor-specific, often expensive          |
| **Team Familiarity**  | Universal SQL knowledge                      | Specialized per database                  |

**When You Actually Need NoSQL:**

Choose NoSQL only when you have **proven, measured requirements**:

- **Extreme write throughput** (>50,000 writes/second) - DynamoDB
- **Real-time sync with offline support** - Firestore
- **Global multi-region with single-digit latency** - DynamoDB Global Tables, Firestore
- **Key-value caching with TTL** - DynamoDB, Redis
- **Serverless auto-scaling** - DynamoDB On-Demand, Firestore

**When NOT to use NoSQL:**

- ❌ "We might need to scale" (SQL scales to millions of users)
- ❌ "NoSQL is faster" (SQL with proper indexes is equally fast)
- ❌ "Flexible schema" (PostgreSQL JSONB provides this)
- ❌ Complex reporting/analytics (SQL with JOINs is far superior)

**Key Security Difference:**

SQL databases enforce GRANTs at the database layer, and PostgreSQL Row-Level Security can limit which rows a user sees. Without RLS policies, though, an application user with `SELECT` on `users` reads every row. DynamoDB IAM conditions and Firestore rules are also enforced server-side, but a backend running as one role can read anything its rules allow. Either way, check in application code that the user owns the record.

### NoSQL Security Implementation

**DynamoDB (AWS):**

Access control via IAM policies:

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:Query"],
  "Resource": "arn:aws:dynamodb:*:*:table/users",
  "Condition": {
    "ForAllValues:StringEquals": {
      "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
    }
  }
}
```

**Critical:** `LeadingKeys` only scopes access when each end user calls DynamoDB with their own federated credentials (e.g. Cognito identity pools). A backend with one IAM role can read the entire table, so always validate that the user owns the resource in application code.

Configuration:

- At-rest encryption: Always on (AWS owned key by default); switch to a customer managed KMS key, at creation or later, when you need key-policy control and CloudTrail audit of key use
- In-transit: TLS by default
- Point-in-Time Recovery: Enable for production tables
- Audit logging: CloudTrail data events (expensive, enable only for sensitive tables)

**Firestore (GCP):**

Security rules required for client access:

```text
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

**Critical:** Default is deny-all. Rules are evaluated server-side but must be carefully tested - complex rules are error-prone.

Configuration:

- At-rest encryption: Google-managed keys (default) or CMEK
- In-transit: TLS by default
- Audit logging: Cloud Audit Logs for admin and data access, log security rule evaluations

**MongoDB Atlas:**

Access control via database users and roles:

- Use SCRAM-SHA-256 authentication
- Create custom roles instead of default `readWrite` (too permissive)
- **IP allowlist required** - never use `0.0.0.0/0`

NoSQL injection prevention:

```javascript
// Validate input types before queries
if (typeof email !== "string") throw new Error("Invalid input");
const user = await db.collection("users").findOne({ email: email });
```

Configuration:

- At-rest encryption: Enabled by default (cloud provider keys or CMEK)
- In-transit: TLS required
- Field-level encryption: Queryable Encryption (equality and range queries on encrypted fields, MongoDB 8.0+) or Client-Side Field Level Encryption (CSFLE) for PII/PHI
- Audit logging: Database auditing (M10+ clusters), log export (MongoDB 7.0+) to S3, Google Cloud Storage, Azure Blob Storage, Datadog, Splunk or OpenTelemetry

**Common NoSQL Security Risks:**

1. **No Query Validation**: Application can query any data if IAM/rules permit - must validate authorization in application code
2. **Injection via Unsanitized Input**: NoSQL injection possible with object/array inputs - always validate input types
3. **Overly Permissive Policies**: DynamoDB IAM without `LeadingKeys`, Firestore rules missing `request.auth.uid` checks, MongoDB default `readWrite` role

### Security Comparison and Recommendations

| Security Feature           | SQL                   | DynamoDB            | Firestore           | MongoDB        |
| -------------------------- | --------------------- | ------------------- | ------------------- | -------------- |
| **Authorization**          | Database-enforced     | IAM policies        | Security Rules      | Database roles |
| **Query Validation**       | Yes                   | No                  | Rules only          | No             |
| **Injection Protection**   | Parameterized queries | App validation      | Rules validation    | App validation |
| **Field-Level Encryption** | pgcrypto or app-side  | App-side            | App-side            | CSFLE          |
| **Audit Granularity**      | High (pgaudit)        | Medium (CloudTrail) | Medium (Cloud Logs) | Medium (Atlas) |

**Recommended Strategy for 95% of Applications:**

1. **Start with PostgreSQL** (RDS, Cloud SQL, Azure Database)
2. **Add Redis** for caching and session storage
3. **Only add NoSQL** when you have proven, measured requirements

**PostgreSQL with JSONB** provides flexible schema for most "NoSQL use cases" while maintaining ACID guarantees and SQL query power.

## 5. Network Security

### Network Isolation

**Deploy databases in private subnets with no direct internet access.**

**Architecture:**

```
Internet → Internet Gateway → Public Subnet (NAT, Bastion/VPN)
                                      ↓
                              Private Subnet (Databases)
```

**Configuration:**

- Databases in private subnets with no route to Internet Gateway
- No public IP addresses
- All access through VPN or bastion host

**Benefits:**

- Database not accessible from internet
- Network-level isolation even if credentials compromised
- Attack surface minimized

### Security Groups

Restrict database access to only authorized sources.

**Example (AWS Security Group):**

| Type     | Protocol | Port | Source         | Purpose                |
| -------- | -------- | ---- | -------------- | ---------------------- |
| Inbound  | TCP      | 5432 | sg-k8s-workers | Kubernetes pods        |
| Inbound  | TCP      | 5432 | sg-app-servers | Application containers |
| Inbound  | TCP      | 5432 | sg-bastion     | Admin access           |
| Outbound | All      | All  | 0.0.0.0/0      | Allow outbound         |

**Best Practices:**

- Use security group IDs as sources (not CIDR ranges)
- Never allow `0.0.0.0/0` inbound on port 5432
- Separate security groups per environment (dev, staging, prod)
- On EKS, `sg-k8s-workers` admits every pod on those nodes; use Security Groups for Pods so only the app's pods reach 5432

### Connection from Applications

Applications must retrieve database credentials securely without hardcoding them in code or configuration files.

**From Kubernetes:**

Use Secrets Store CSI Driver to inject credentials from cloud secrets manager into Kubernetes pods. This approach keeps credentials in the external vault (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) and automatically injects them into pods at runtime.

**Why this approach:**

- The external vault stays the source of truth; the synced Kubernetes Secret is a namespaced cache that follows the vault (managed control planes already encrypt etcd at rest - EKS envelope-encrypts all API data with KMS on 1.28+, GKE encrypts Secrets at rest by default, AKS supports KMS etcd encryption - so the win is central rotation, audit and IAM-scoped access, not "base64 vs encrypted")
- Automatic synchronization with external vault (rotation refreshes mounted files and the synced Secret)
- Cloud-native workload identity (EKS Pod Identity or IRSA, Workload Identity Federation for GKE, Microsoft Entra Workload ID) - no long-lived credentials
- Audit trail in cloud provider logs

**Cloud-native integrations:**

- **AWS EKS**: AWS Secrets and Configuration Provider (ASCP) for the Secrets Store CSI Driver, also packaged as the `aws-secrets-store-csi-driver-provider` EKS add-on; authenticate with EKS Pod Identity (`usePodIdentity: "true"`) or IRSA
- **GKE**: Secret Manager add-on (Google-managed Secrets Store CSI Driver, `secrets-store-gke.csi.k8s.io`) with Workload Identity Federation for GKE
- **AKS**: Azure Key Vault Provider for Secrets Store CSI Driver with Microsoft Entra Workload ID

**Setup (AWS EKS Example):**

```bash
# Step 1: Install Secrets Store CSI Driver (Secret sync and rotation are OFF by default - enable both)
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true \
  --set rotationPollInterval=2m \
  --set 'tokenRequests[0].audience=sts.amazonaws.com' \
  --set 'tokenRequests[1].audience=pods.eks.amazonaws.com'  # ASCP needs these audiences (IRSA, Pod Identity)

# Step 2: Install AWS Secrets Manager provider (skip its bundled copy of the driver - installed above)
helm repo add aws-secrets-manager https://aws.github.io/secrets-store-csi-driver-provider-aws
helm install -n kube-system secrets-provider-aws aws-secrets-manager/secrets-store-csi-driver-provider-aws \
  --set secrets-store-csi-driver.install=false
```

**SecretProviderClass Configuration:**

```yaml
# Define which secrets to sync from AWS Secrets Manager
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: db-credentials-sync
  namespace: production
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/database/credentials"
        objectType: "secretsmanager"
        jmesPath:
          - path: username
            objectAlias: username
          - path: password
            objectAlias: password
          - path: host
            objectAlias: host
  # Optional: Create K8s Secret for environment variable injection
  secretObjects:
    - secretName: db-credentials
      type: Opaque
      data:
        - objectName: username
          key: username
        - objectName: password
          key: password
        - objectName: host
          key: host
```

**Pod Configuration:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  namespace: production
spec:
  serviceAccountName: app-service-account # Bound to an IAM role via EKS Pod Identity (preferred) or IRSA; for Pod Identity add `usePodIdentity: "true"` to the SecretProviderClass spec.parameters
  containers:
    - name: app
      image: myapp:latest
      env:
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: db-credentials # Created by CSI driver from vault
              key: host
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: db-credentials # Created by CSI driver from vault
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials # Created by CSI driver from vault
              key: password
        - name: DB_NAME
          value: "mydb"
        - name: DB_PORT
          value: "5432"
      volumeMounts:
        - name: secrets-store
          mountPath: "/mnt/secrets"
          readOnly: true
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "db-credentials-sync"
```

**How this works:**

1. The AWS provider (ASCP) authenticates to AWS with the pod's EKS Pod Identity association or IRSA role
2. Fetches secrets from AWS Secrets Manager
3. Creates Kubernetes Secret (`db-credentials`) with vault contents
4. Pod consumes secret via environment variables
5. When the vault secret rotates, the driver (with `enableSecretRotation=true`) refreshes the mounted files and the synced K8s Secret on the next poll
6. Environment variables are read once at start - run [Reloader](https://github.com/stakater/Reloader) (or read `/mnt/secrets/*` at connect time) so pods pick up rotated credentials without a manual restart

**From Serverless:**

Serverless functions retrieve credentials at runtime directly from secrets manager. This avoids storing credentials in environment variables.

**Why this approach:**

- Credentials fetched on cold start (not in deployment package)
- IAM role controls which functions can access which secrets
- Audit trail of secret access in CloudTrail
- Rotation needs no redeployment: the cache re-fetches after its TTL, and on an authentication failure re-fetch the secret and retry once

```python
import json
import time

import boto3

# Created once per cold start and reused by warm invocations
client = boto3.client('secretsmanager', region_name='us-east-1')
_cache = {'value': None, 'expires': 0.0}

def get_db_credentials(ttl_seconds=300):
    # Re-fetch after the TTL so rotated credentials are picked up
    if time.time() >= _cache['expires']:
        response = client.get_secret_value(SecretId='prod/database/credentials')
        _cache['value'] = json.loads(response['SecretString'])
        _cache['expires'] = time.time() + ttl_seconds
    return _cache['value']
```

## 6. Authentication & Access Control

### Least-Privilege Database Users

Create application-specific database users with minimal required permissions.

**Never use root/admin user for application connections.**

**PostgreSQL Example:**

```sql
-- Create application user (not superuser)
CREATE USER api_app_user WITH PASSWORD 'secure_password_from_vault';

-- Grant only necessary permissions on specific tables
GRANT USAGE ON SCHEMA public TO api_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, orders TO api_app_user;

-- Lock down the public schema. CREATE on public is granted to PUBLIC, not to the user:
-- revoke it there (the default on new PostgreSQL 15+ databases; upgrades keep the old grant)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Leave pg_catalog and information_schema alone: access comes via PUBLIC,
-- and drivers, ORMs and psql need to read the catalogs

-- For read-only analytics user (ALL TABLES covers existing tables only; DEFAULT PRIVILEGES covers future ones
-- created by the role named in FOR ROLE - use the role that runs your migrations)
CREATE USER analytics_readonly WITH PASSWORD 'secure_password_from_vault';
GRANT USAGE ON SCHEMA public TO analytics_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO analytics_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE migration_owner IN SCHEMA public
  GRANT SELECT ON TABLES TO analytics_readonly;
```

**Best Practices:**

- Grant permissions on specific tables, not entire schemas
- Separate users for different applications
- Revoke CREATE on schemas from application users, and never let them own tables: PostgreSQL has no grantable DROP or ALTER privilege - the table owner (and any member of the owning role) can always run them, so run migrations as a separate owner role

### Row-Level Security for Multi-Tenant Data

**If tenants share tables, enforce isolation in the database, not only in application code.** One missing `WHERE tenant_id = ...` leaks another customer's data. PostgreSQL Row-Level Security (RLS) applies the tenant filter to every query and blocks writes into other tenants, so a bug returns zero rows instead of someone else's.

```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY; -- Applies to the table owner too

CREATE POLICY tenant_isolation ON orders
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Per request, first statement inside the transaction ($1 bound by the driver):
-- SELECT set_config('app.tenant_id', $1, true);  -- true = transaction-local
```

**Rules:**

- No tenant set = no rows; no policy = default deny
- Superusers and roles with `BYPASSRLS` skip every policy - the application role must be neither
- Never set the tenant with session-level `SET`; it survives `release()` into the next request on that pooled connection
- Views check policies as the view owner, so a view owned by a superuser returns every tenant's rows - create views `WITH (security_invoker = true)` (PostgreSQL 15+)
- Index `tenant_id` - the policy predicate runs on every query
- RLS is a backstop, not a replacement for authorization checks in application code

### IAM Database Authentication

Eliminate password-based authentication using cloud IAM roles (ephemeral 15-minute tokens).

**AWS RDS IAM Authentication:**

```sql
-- One-time: the database user must hold rds_iam (no password is set)
CREATE USER api_iam_user;
GRANT rds_iam TO api_iam_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, orders TO api_iam_user;
```

```python
import boto3
import psycopg2

# Generate short-lived authentication token (valid 15 minutes). It is checked only when a
# connection opens: pools must generate a fresh token for each new connection
rds_client = boto3.client('rds', region_name='us-east-1')
token = rds_client.generate_db_auth_token(
    DBHostname='prod-db.cluster.us-east-1.rds.amazonaws.com',
    Port=5432,
    DBUsername='api_iam_user',
    Region='us-east-1'
)

# Connect using token instead of password
connection = psycopg2.connect(
    host='prod-db.cluster.us-east-1.rds.amazonaws.com',
    user='api_iam_user',
    password=token,
    database='mydb',
    sslmode='verify-full',  # The token is a bearer credential: verify the server first
    sslrootcert='/etc/ssl/rds/global-bundle.pem'  # From truststore.pki.rds.amazonaws.com
)
```

**Benefits:**

- No long-lived passwords to manage or rotate
- Tokens expire after 15 minutes
- IAM controls who can generate tokens
- Audit trail from PostgreSQL connection logging (`log_connections = on`) - CloudTrail does **not** record `generate-db-auth-token`

**GCP Cloud SQL (IAM database authentication) and Azure Database for PostgreSQL (Microsoft Entra authentication) support similar token-based login.**

### Secrets Management

Store database credentials in an external secrets manager, never in code, container images or committed config. Inject them at runtime; a mounted file (`/mnt/secrets`) is safer than an environment variable, which child processes inherit and crash dumps capture.

**Secrets to Store:**

- Database host/endpoint
- Database username
- Database password
- Database name

**AWS Secrets Manager Example:**

```bash
# Store database credentials
aws secretsmanager create-secret \
  --name prod/database/credentials \
  --secret-string '{
    "username": "api_app_user",
    "password": "generated-secure-password",
    "host": "prod-db.cluster.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "mydb"
  }'
```

**Credential Rotation:**

Prefer credentials that expire on their own (IAM database authentication, workload identity) so there is nothing static to rotate. NIST SP 800-63B-4's rule against forced periodic changes covers user passwords only, never service credentials; OWASP recommends rotating secrets regularly, and PCI DSS v4.0.1 Req 8.6.3 requires application and system account passwords to be changed "periodically (at the frequency defined in the entity's targeted risk analysis) and upon suspicion or confirmation of compromise".

**Rotate static database passwords:**

- Immediately when compromise is confirmed or suspected
- Immediately when someone with access leaves
- Otherwise on a documented risk-based schedule, automated with Secrets Manager rotation (90 days is a common choice)

**Better security approach:**

- Use short-lived credentials (IAM database authentication - tokens expire after 15 minutes)
- Implement proper access controls and audit logging
- Monitor for unauthorized access attempts
- Use workload identity in Kubernetes (EKS Pod Identity or IRSA, Workload Identity Federation for GKE, Microsoft Entra Workload ID) for automatic credential refresh

## 7. Encryption

### Encryption at Rest

Enable database encryption to protect against physical disk theft and unauthorized disk access.

**Managed Database Encryption:**

Choose encryption and the key at database creation (none of these can be changed in place later):

- **AWS RDS**: `storage_encrypted = true` with a customer managed `kms_key_id` (opt-in for RDS for PostgreSQL; an unencrypted instance is fixed only by restoring an encrypted snapshot copy). New Aurora clusters are encrypted by default since February 2026 with an AWS owned key - pick a customer managed key when you need to audit or control it
- **GCP Cloud SQL**: Encrypted by default with Google-managed keys; select CMEK at instance creation if you need to control the key
- **Azure Database**: Storage encryption always on with service-managed keys; customer-managed keys (Key Vault) only at server creation

**When Managed Encryption Protects:**

- Physical disk theft from data center
- Unauthorized access to disk snapshots
- Decommissioned disks not properly wiped

**When It Doesn't Protect:**

- Application compromise with database credentials
- SQL injection attacks
- Database administrator with legitimate access
- Logical backups (`pg_dump`, exports) taken outside the managed service, unless separately encrypted

### Field-Level Encryption for PII/PHI

Encrypt sensitive fields in application code before writing to database using envelope encryption.

**When to Use Field-Level Encryption:**

- PII: Social Security Numbers, passport numbers, driver's license numbers
- PHI: Medical records, diagnoses, prescriptions
- PCI: Credit card numbers, CVV codes
- Compliance requirements (GDPR, HIPAA, PCI-DSS) mandating data protection beyond database encryption
- Zero-trust requirements (don't trust cloud admins or DBAs)

**Envelope Encryption Pattern:**

```
User Data → Encrypt with Data Encryption Key (DEK)
DEK → Encrypt with Key Encryption Key (KEK) from KMS
Store: Encrypted data + Encrypted DEK
```

**Implementation (Python with AWS KMS):**

Fernet splits the 32-byte `AES_256` data key into a 128-bit HMAC-SHA256 key and a 128-bit AES-CBC key, so the data itself is AES-128 authenticated encryption. That is sound; if a standard mandates AES-256, use `AESGCM` from the same `cryptography` package or the AWS Encryption SDK.

```python
import boto3
import base64
from cryptography.fernet import Fernet

kms = boto3.client('kms', region_name='us-east-1')

def encrypt_field(plaintext, kms_key_id, context):
    # context binds the DEK to one record, e.g. {'table': 'users', 'column': 'ssn', 'id': str(user_id)}.
    # KMS refuses to decrypt it under any other context, so ciphertext copied to another row is useless.
    response = kms.generate_data_key(
        KeyId=kms_key_id, KeySpec='AES_256', EncryptionContext=context
    )
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    # Encrypt data with DEK (Fernet: AES-128-CBC + HMAC-SHA256 from the 32-byte key)
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key))
    encrypted_data = cipher.encrypt(plaintext.encode())  # Fernet token, already base64

    # Return both encrypted data and encrypted DEK
    return {
        'encrypted_data': encrypted_data.decode(),
        'encrypted_key': base64.b64encode(encrypted_key).decode()
    }

def decrypt_field(encrypted_data, encrypted_key, kms_key_id, context):
    # Decrypt DEK using KMS - fails unless the same encryption context is supplied
    response = kms.decrypt(
        CiphertextBlob=base64.b64decode(encrypted_key),
        KeyId=kms_key_id,
        EncryptionContext=context
    )
    plaintext_key = response['Plaintext']

    # Decrypt data with DEK
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key))
    return cipher.decrypt(encrypted_data.encode()).decode()
```

**Cloud KMS Options:**

- AWS: KMS with envelope encryption, automatic key rotation
- GCP: Cloud KMS with customer-managed encryption keys (CMEK)
- Azure: Key Vault for key management and encryption operations

**Database Schema Example:**

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,      -- Not encrypted (needed for login)
    name VARCHAR(255),                -- Not encrypted (low sensitivity)
    ssn_encrypted TEXT,               -- Encrypted SSN ciphertext
    ssn_dek_encrypted TEXT,           -- Encrypted data key for SSN
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

**How this works in practice:**

```python
# When creating a user (psycopg2 cursor: placeholders are %s, not $1)
kms_key_id = 'arn:aws:kms:us-east-1:123456789012:key/abcd1234...'
context = {'table': 'users', 'column': 'ssn', 'id': str(user_id)}
cur = conn.cursor()

# Encrypt SSN before storing
encrypted_ssn = encrypt_field('123-45-6789', kms_key_id, context)

# Store in database
cur.execute(
    "INSERT INTO users (id, email, ssn_encrypted, ssn_dek_encrypted) VALUES (%s, %s, %s, %s)",
    (str(user_id), email, encrypted_ssn['encrypted_data'], encrypted_ssn['encrypted_key'])
)

# When retrieving a user
cur.execute("SELECT ssn_encrypted, ssn_dek_encrypted FROM users WHERE id = %s", (str(user_id),))
ssn_encrypted, ssn_dek_encrypted = cur.fetchone()

# Decrypt SSN
ssn = decrypt_field(ssn_encrypted, ssn_dek_encrypted, kms_key_id, context)
# Application has decrypted SSN: '123-45-6789'
```

**Why this is defense-in-depth:**

If an attacker gains database access through SQL injection, compromised credentials, or insider threat:

- They see encrypted ciphertext: `gAAAAABh1X8Q9...` (useless without KMS access)
- To decrypt, they need BOTH:
  1. Database access (they have this)
  2. KMS decrypt permission (they don't have this - controlled by separate IAM policy)

**What each layer protects:**

- **Managed database encryption**: Protects against physical disk theft
- **Field-level encryption**: Protects against database-only compromise (SQL injection, leaked DB credentials or dumps) and DBAs without KMS access - not against code running as the application (it holds `kms:Decrypt`) or cloud admins who can change the key policy
- **In-transit encryption**: Protects against network eavesdropping
- **Access controls**: Prevents unauthorized KMS decrypt access

**Key Considerations:**

- **Performance**: Encrypt only necessary fields (SSN, credit cards), not entire records
- **Searchability**: Encrypted fields cannot be queried/indexed
- **Key rotation**: Enable KMS automatic rotation (period configurable 90-2560 days, default 365; on-demand rotation also available). KMS keeps old key material, so stored DEKs still decrypt without re-encryption; re-wrap DEKs with `ReEncrypt` only when moving to a new KMS key
- **Access control**: Restrict KMS key permissions to application service accounts only
- **Row binding**: Always pass a per-record `EncryptionContext` (as `encrypt_field` does); without it, an attacker with SQL write access can copy a victim's `ssn_encrypted` and `ssn_dek_encrypted` into their own row and let the app decrypt them

**Defense in Depth:**

Even if attackers gain database access, they cannot decrypt sensitive fields without KMS access.

### Encryption in Transit

Encrypt all database connections using TLS/SSL to prevent credential exposure and man-in-the-middle attacks.

**Why encryption in transit matters:**

- Prevents credential theft when transmitted over network
- Protects data from eavesdropping within VPC (defense in depth)
- Required for compliance (PCI-DSS, HIPAA, SOC2)
- Prevents man-in-the-middle attacks

**Enable TLS/SSL:**

- **AWS RDS (PostgreSQL)**: `rds.force_ssl = 1` in a custom parameter group (already the default on RDS for PostgreSQL 15+; `require_secure_transport` is the MySQL/MariaDB parameter)
- **GCP Cloud SQL**: `gcloud sql instances patch INSTANCE --ssl-mode=ENCRYPTED_ONLY` (the legacy "Require SSL" / `require-ssl` flag is superseded by `ssl_mode`)
- **Azure Database**: Set `require_secure_transport = ON`

**Connection String:**

```python
# PostgreSQL with SSL
import psycopg2

conn = psycopg2.connect(
    host="prod-db.cluster.us-east-1.rds.amazonaws.com",
    database="mydb",
    user="api_app_user",
    password="secure_password",
    sslmode="verify-full",  # Encrypt AND verify CA + hostname (see SSL Modes below)
    sslrootcert="/etc/ssl/rds/global-bundle.pem"  # provider CA bundle, e.g. https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
)
```

**SSL Modes (PostgreSQL):**

| Mode          | Encryption | Certificate Validation | Security Level | Use Case                                                    |
| ------------- | ---------- | ---------------------- | -------------- | ----------------------------------------------------------- |
| `disable`     | ❌ No      | ❌ No                  | None           | Never use in production                                     |
| `require`     | ✅ Yes     | ❌ No                  | Basic          | Minimum for production - encrypts but doesn't verify server |
| `verify-ca`   | ✅ Yes     | ⚠️ CA only             | Better         | Any cert from the same CA passes (e.g. any RDS instance)    |
| `verify-full` | ✅ Yes     | ✅ Full                | Best           | Validates CA and hostname match - blocks impersonation      |

**What each mode protects against:**

- `require`: Protects data from eavesdropping but vulnerable to impersonation (attacker can present fake certificate)
- `verify-ca`: Prevents untrusted certificates but hostname mismatch possible
- `verify-full`: Maximum protection - validates both certificate authority and hostname match

**Recommendation:** Use `verify-full` with server CA certificate for production. Download CA certificate from your cloud provider and specify in connection.

## 8. Performance & Scaling

### Connection Pooling

Reuse database connections to improve performance and prevent connection exhaustion attacks.

**What connection pooling accomplishes:**

Without pooling, each query creates a new database connection:

```
Request 1: Create connection (200ms) → Query (5ms) → Close connection
Request 2: Create connection (200ms) → Query (5ms) → Close connection
Total time: 410ms for 2 queries
```

With pooling, connections are reused:

```
Startup: Create 20 connections (kept alive)
Request 1: Borrow connection from pool → Query (5ms) → Return to pool
Request 2: Borrow connection from pool → Query (5ms) → Return to pool
Total time: 10ms for 2 queries (40x faster)
```

**Why this matters:**

- **Performance**: Removes per-request connection setup (TCP, TLS, and authentication handshakes)
- **Security**: Prevents connection exhaustion attacks (limits max connections)
- **Reliability**: Reduces database resource consumption (fewer TCP handshakes, auth checks)

**Serverless (RDS Proxy):**

Use RDS Proxy for serverless functions because each Lambda instance creates its own connections. Without a proxy, 1000 concurrent Lambdas = 1000+ database connections (exceeds most database limits).

**How RDS Proxy works:**

- Lambda creates connection to RDS Proxy (not directly to database)
- RDS Proxy multiplexes thousands of Lambda connections into ~100 database connections
- Database sees consistent connection count regardless of Lambda scaling
- Avoid session-level `SET` (including `SET statement_timeout`) through the proxy: on PostgreSQL it pins the connection and defeats multiplexing. Set timeouts with `ALTER ROLE ... SET` instead

**Example (Lambda via RDS Proxy):**

```javascript
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.RDS_PROXY_ENDPOINT, // RDS Proxy manages pooling
  database: "mydb",
  max: 2, // Keep minimal per Lambda
  idleTimeoutMillis: 1000,
  ssl: { rejectUnauthorized: true },
});
```

**Containers (Application-Level):**

```javascript
const fs = require("fs");
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST,
  database: "mydb",
  max: 20, // Max connections per container
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: {
    rejectUnauthorized: true,
    // RDS certificates chain to Amazon RDS root CAs, which are not in Node's trust store
    // (https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem)
    ca: fs.readFileSync("/etc/ssl/rds/global-bundle.pem").toString(),
  },
});

async function getUser(id) {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    return result.rows[0];
  } finally {
    client.release(); // Return to pool
  }
}
```

**Server-Level (PgBouncer):**

For very high scale, use PgBouncer to multiplex thousands of app connections into fewer database connections.

### Query Timeouts for DoS Prevention

Query timeouts prevent resource exhaustion attacks where malicious or poorly optimized queries consume database resources indefinitely. Without timeouts, a single bad query can lock tables, exhaust connections, and cause cascading failures.

**PostgreSQL Configuration:**

```sql
-- Set at database level (recommended for production)
ALTER DATABASE mydb SET statement_timeout = '30s';
-- statement_timeout does not end idle transactions that hold locks
ALTER DATABASE mydb SET idle_in_transaction_session_timeout = '60s';
ALTER DATABASE mydb SET lock_timeout = '5s';

-- Set at user level (application-specific limits)
ALTER ROLE api_app_user SET statement_timeout = '5s';

-- Set at session level (per-connection override; never on pooled connections, use SET LOCAL inside a transaction)
SET statement_timeout = '10s';
```

**Application-Level Timeouts:**

```javascript
const fs = require("fs");
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST,
  database: "mydb",
  max: 20,
  connectionTimeoutMillis: 2000, // Timeout acquiring connection
  idleTimeoutMillis: 30000, // Close idle connections
  query_timeout: 5000, // Timeout individual queries (5s)
  statement_timeout: 5000, // PostgreSQL statement timeout
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync("/etc/ssl/rds/global-bundle.pem").toString(),
  },
});

// Per-query timeout override: SET LOCAL ends with the transaction, so the
// 30s limit never leaks to the next borrower of this pooled connection
async function complexQuery() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL statement_timeout = 30000"); // 30s, this transaction only
    const result = await client.query("SELECT * FROM large_table WHERE ...");
    await client.query("COMMIT");
    return result.rows;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
```

**Timeout Strategy:**

- **Simple queries** (primary key lookups): 1-2 seconds
- **Standard queries** (indexed searches): 5 seconds
- **Complex queries** (joins, aggregations): 10-30 seconds
- **Analytics/reporting**: 60 seconds (run on read replicas)

**Why this prevents DoS:**

Without timeouts, an attacker can craft queries that:

- Full table scan on billions of rows (hours to complete)
- Cartesian joins creating massive intermediate results (exhaust memory)
- Recursive CTEs with no termination condition (infinite loops)
- Lock contention queries blocking all other transactions

**With statement_timeout = 5s:**

- Bad query cancelled after 5 seconds
- Connection returned to pool
- Database resources freed
- Other queries continue normally

**Attack scenario prevented:**

```sql
-- Malicious query (no timeout: runs for hours, locks table)
SELECT * FROM users u1
CROSS JOIN users u2
CROSS JOIN users u3;  -- Cartesian product: billions of rows

-- With statement_timeout = 5s: query cancelled, no damage
-- ERROR:  canceling statement due to statement timeout
```

**Monitoring query timeouts:**

PostgreSQL logs every cancelled statement as `ERROR:  canceling statement due to statement timeout`; count those log lines (`pg_stat_statements` can't: it stores normalized query text, not errors, and records no execution statistics for statements that fail). CloudWatch Logs Insights on the exported `/aws/rds/instance/<id>/postgresql` log group:

```text
fields @timestamp, @message
| filter @message like /canceling statement due to statement timeout/
| stats count(*) as timeouts by bin(5m)
```

Alert if timeouts exceed 1% of total queries.

**Best practices:**

- Set conservative defaults (5s for application users)
- Override for known slow queries (analytics, batch jobs)
- Monitor timeout frequency (high rate = optimization needed)
- Log timed-out queries for investigation
- Fail fast (5s timeout) rather than hang (no timeout)

### Read/Write Splitting

Route read queries to replicas and write queries to the primary to keep load off the single write node.

**Why this pattern matters:**

PostgreSQL uses a single-primary architecture:

- **Primary database**: Handles ALL writes (one instance)
- **Read replicas**: Handle reads only (can scale to dozens)

**The problem without read/write splitting:**

```
All traffic → Primary database
- 95% reads competing with 5% writes for resources
- Reads slow down writes
- Writes slow down reads
- Single bottleneck for everything
```

**With read/write splitting:**

```
Writes (5%) → Primary database (protected, handles only writes)
Reads (95%) → Replica pool (distributed across multiple instances)
- Primary focused only on writes (fast, reliable)
- Reads distributed across replicas (scalable)
- No resource contention
```

**When to use:**

- Read-heavy workloads (>80% reads) - most applications
- Analytics/reporting queries (expensive, can run on replicas)
- High traffic (protects primary from overload)

**When NOT to use:**

- Write-heavy workloads (>50% writes) - primary still bottleneck
- Real-time consistency critical for ALL reads - replica lag (100-500ms) may be unacceptable

**Implementation:**

```javascript
class DatabaseManager {
  constructor() {
    this.primary = createPool(process.env.PRIMARY_DB_URL);
    this.replicas = [
      createPool(process.env.REPLICA_1_URL),
      createPool(process.env.REPLICA_2_URL),
    ];
  }

  getReadPool() {
    const index = Math.floor(Math.random() * this.replicas.length);
    return this.replicas[index];
  }

  getWritePool() {
    return this.primary;
  }
}

const db = new DatabaseManager();

// Route reads to replicas
async function getUser(id) {
  return db.getReadPool().query("SELECT * FROM users WHERE id = $1", [id]);
}

// Route writes to primary
async function createUser(userData) {
  return db
    .getWritePool()
    .query("INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *", [
      userData.name,
      userData.email,
    ]);
}

// Read-after-write: query primary for consistency
async function updateUser(id, data) {
  await db
    .getWritePool()
    .query("UPDATE users SET name = $1 WHERE id = $2", [data.name, id]);
  // Read from primary to ensure latest data
  return db.getWritePool().query("SELECT * FROM users WHERE id = $1", [id]);
}
```

### Query Optimization

Optimize queries to prevent performance degradation and security attacks.

**Use Prepared Statements (Prevents SQL Injection + Performance):**

Prepared statements prevent SQL injection by separating SQL structure from data values.

**How SQL injection works (without prepared statements):**

```python
# Bad: String concatenation
email = "'; DROP TABLE users; --"  # Malicious input
query = f"SELECT * FROM users WHERE email = '{email}'"
# Executed: SELECT * FROM users WHERE email = ''; DROP TABLE users; --'
# Result: Users table deleted
```

**How prepared statements prevent it:**

```python
# Good: Parameterized query (psycopg placeholder is %s; node-postgres uses $1)
email = "'; DROP TABLE users; --"  # Same malicious input
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
# Input is treated as a literal string, not executable SQL
# Result: No users found (safe - query looks for email "'; DROP TABLE users; --")
```

**Why this works:**

- SQL structure kept separate from data values (node-postgres and psycopg 3 send them separately; psycopg2 escapes them client-side)
- The placeholder (`$1`, `%s`) marks a value slot, never SQL code
- User input cannot modify query structure
- Bonus: prepared statements (node-postgres `name` option; psycopg 3 prepares repeated queries) let PostgreSQL reuse the query plan

```javascript
// Good: Parameterized query
const result = await pool.query(
  "SELECT * FROM users WHERE email = $1 AND status = $2",
  [email, "active"],
);

// Bad: String concatenation (SQL injection risk)
const unsafe = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**Set Query Timeouts:**

See [Query Timeouts for DoS Prevention](#query-timeouts-for-dos-prevention).

**Use LIMIT:**

```javascript
// Paginate results - cap the client-supplied page size
const pageSize = Math.min(Math.max(Number(limit) || 20, 1), 100);
const users = await pool.query(
  "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
  [pageSize, offset],
);
```

**Avoid N+1 Queries:**

```javascript
// Bad: N+1 queries
const { rows: users } = await db.query("SELECT * FROM users LIMIT 10");
for (const user of users) {
  const { rows } = await db.query("SELECT * FROM orders WHERE user_id = $1", [
    user.id,
  ]);
  user.orders = rows;
}

// Good: Single JOIN
const { rows: usersWithOrders } = await db.query(`
  SELECT u.*,
         COALESCE(json_agg(o.*) FILTER (WHERE o.id IS NOT NULL), '[]') AS orders
  FROM users u
  LEFT JOIN orders o ON o.user_id = u.id
  GROUP BY u.id
  LIMIT 10
`);
```

**Create Indexes:**

```sql
-- Add indexes for common queries (CONCURRENTLY avoids blocking writes on live tables;
-- it can't run inside a transaction block)
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_orders_user_created ON orders(user_id, created_at DESC);
```

### Monitoring

Monitor database performance to detect attacks and degradation early.

**Key Metrics:**

| Metric              | Alert Threshold     | Indicates                       |
| ------------------- | ------------------- | ------------------------------- |
| Connection count    | >80% of max         | Connection exhaustion or leak   |
| Query latency (p99) | >500ms              | Missing indexes or slow queries |
| Replica lag         | >5 seconds          | Replication overload            |
| CPU utilization     | >80% sustained      | Database overload               |
| Slow query count    | >10 queries >5s/min | Unoptimized queries or attack   |

**Cloud Monitoring:**

- **AWS**: CloudWatch RDS metrics, CloudWatch Database Insights (replaced the Performance Insights console on July 31, 2026)
- **GCP**: Cloud Monitoring, Query Insights
- **Azure**: Azure Monitor, Query Performance Insight

## 9. Backup & Disaster Recovery

### Automated Backups

Enable automated daily snapshots with appropriate retention.

**Configuration:**

- **AWS RDS**: Automated backups with 1-35 day retention (set it explicitly: the API/CLI default is 1 day)
- **GCP Cloud SQL**: Automated backups with 1-365 day retention (default 7 days Enterprise, 15 Enterprise Plus)
- **Azure Database**: Automated backups with 7-35 day retention

**Retention Policy:**

- Daily snapshots: 30 days (hot storage)
- Monthly snapshots: 7 years (house policy; covers HIPAA's 6-year documentation rule and PCI's 12 months - GDPR storage limitation argues against blanket multi-year retention of personal data)

**Backup Encryption:**

- Enabled by default when database encryption enabled
- Backups encrypted with same KMS key as database

### Point-in-Time Recovery

Enable PITR for protection against accidental data deletion.

**Configuration:**

- **AWS RDS**: Enabled with automated backups; restore to any point in the retention window (transaction logs ship to S3 every 5 minutes)
- **GCP Cloud SQL**: Enabled with write-ahead log archiving (`--enable-point-in-time-recovery`; default on Enterprise Plus, console-only default on Enterprise)
- **Azure Database**: Enabled with automated backups (WAL archiving, RPO up to 5 minutes)

**Recovery Example:**

```bash
# AWS RDS: Restore to specific timestamp
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier prod-db \
  --target-db-instance-identifier prod-db-restored \
  --restore-time 2026-01-23T14:30:00Z
```

**Use Cases:**

- Accidental DELETE/DROP statement
- Application bug corrupting data
- Ransomware attack

**RPO (Recovery Point Objective):** 5 minutes

### Disaster Recovery Procedures

**Cross-Region Replica:**

Maintain cross-region read replica for disaster recovery:

- **AWS RDS**: Cross-region read replica
- **GCP Cloud SQL**: Cross-region replica
- **Azure Database**: Cross-region read replica (geo-replica), or geo-restore from geo-redundant backup (up to 1-hour RPO; enable at server creation)

**Recovery Steps:**

1. Restore from automated snapshot or PITR (15-30 minutes)
2. Update application connection strings
3. Rotate database credentials

```bash
# Rotate credentials after recovery: change the password in the database,
# then write a new version of the SAME secret so every consumer picks it up
psql "host=prod-db-restored.cluster.us-east-1.rds.amazonaws.com dbname=mydb user=admin_user sslmode=verify-full sslrootcert=/etc/ssl/rds/global-bundle.pem" \
  -c "ALTER USER api_app_user WITH PASSWORD 'new-secure-password';"

aws secretsmanager put-secret-value \
  --secret-id prod/database/credentials \
  --secret-string '{
    "username": "api_app_user",
    "password": "new-secure-password",
    "host": "prod-db-restored.cluster.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "mydb"
  }'
```

4. Validate data integrity

**RTO (Recovery Time Objective):** 1-2 hours

**Testing:**

Test disaster recovery quarterly:

1. Restore latest snapshot to test environment
2. Verify data integrity
3. Run application smoke tests
4. Document actual RTO achieved

## 10. Compliance & Auditing

### Audit Logging

Enable database audit logging for access tracking.

**PostgreSQL (pgaudit):**

Prerequisites (AWS RDS): run `CREATE ROLE rds_pgaudit NOLOGIN;`, then in the DB parameter group (not SQL: `ALTER SYSTEM` needs superuser, which RDS, Cloud SQL and Azure don't grant) add `pgaudit` to `shared_preload_libraries`, set `pgaudit.role = rds_pgaudit`, and reboot. On Cloud SQL, set the `cloudsql.enable_pgaudit` flag instead.

```sql
-- Enable pgaudit extension (fails until pgaudit is preloaded)
CREATE EXTENSION pgaudit;

-- Log DDL, privilege changes (GRANT/REVOKE, roles) and writes on all tables (session audit logging)
ALTER DATABASE mydb SET pgaudit.log = 'ddl, role, write';

-- Log reads and writes on specific tables (object audit logging):
-- pgaudit logs any statement the audit role holds the privilege for
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO rds_pgaudit;
```

**What to Log:**

- Failed authentication attempts (PostgreSQL server log, not pgaudit - export it to CloudWatch or Cloud Logging)
- Schema changes (CREATE, ALTER, DROP)
- Data modifications on sensitive tables
- Privilege changes (GRANT, REVOKE)

**Log Forwarding:**

Forward to centralized SIEM (Splunk, ELK Stack, cloud logging).

### Data Retention

Backup tiers follow the [Automated Backups](#automated-backups) retention policy: daily snapshots kept 30 days in hot storage for fast recovery, monthly snapshots kept 7 years as house policy (SOC 2 sets no period; HIPAA's 6 years covers Security Rule documentation, and medical-record retention is state law; GDPR storage limitation applies to every snapshot holding personal data). Long-term tier by provider:

- AWS: AWS Backup plan with a monthly rule retained for 7 years (restorable RDS snapshots; lock the vault). RDS "Export to S3" writes Parquet for analytics and can't be restored to a database, so for a cheaper archive use `pg_dump` to S3 with a Glacier lifecycle rule
- GCP: Cloud SQL enhanced backups (monthly schedule, retention up to 10 years) or `gcloud sql export sql` to a Coldline/Archive bucket
- Azure: Azure Backup long-term retention for Flexible Server (pg_dump-based, up to 10 years)

**Regulatory Requirements:**

- **GDPR**: Right to erasure, 72-hour breach notification, encryption as an Art. 32 measure (not a blanket mandate), storage limitation
- **HIPAA**: PHI encryption (addressable today; the January 2025 proposed rule would make it required), 6-year retention of Security Rule documentation (incl. audit records), tested backup and recovery plan
- **PCI DSS v4.0.1**: Cardholder data encryption, access restrictions, key changes at the end of each key's defined cryptoperiod (Req 3.7.4), audit logs kept 12 months with 3 months immediately available (Req 10.5.1)
- **SOC 2**: Access controls, encryption, continuous monitoring; no prescribed log retention - define one (1 year is common) and follow it

## 11. Attack Scenarios Prevented

This guide's security controls prevent real-world database attacks.

**Credential Theft & Unauthorized Access**

- Attack: Stolen database credentials used to access database
- Mitigated by: IAM database authentication (short-lived tokens), network isolation (private subnets), security groups (authorized sources only)

**Database Breach via Application Compromise**

- Attack: Leaked application database credentials expose all data (field-level encryption does not help once an attacker runs code as the application, which holds `kms:Decrypt`)
- Mitigated by: Field-level encryption (sensitive data encrypted with KMS), least-privilege users (limited permissions), audit logging (detect unauthorized access)

**Insider Threat (DBA / Cloud Admin)**

- Attack: Database administrator accesses plaintext sensitive data
- Mitigated by: Field-level envelope encryption (DBA cannot decrypt without KMS access), audit logging (track all access), separation of duties

**Backup Theft**

- Attack: Stolen database backups expose sensitive data
- Mitigated by: Backup encryption, field-level encryption (even decrypted backups have encrypted fields), IAM access controls

**SQL Injection**

- Attack: Malicious SQL injected to access/modify database
- Mitigated by: Prepared statements (parameterized queries), least-privilege users (limited damage), query timeouts, input validation at application layer

**Connection Exhaustion**

- Attack: Overwhelming database with connections to cause denial of service
- Mitigated by: Connection pooling (manages connections efficiently), network isolation (only trusted sources), monitoring (alert at >80% usage)

**Query Complexity Attack**

- Attack: Expensive queries cause database overload
- Mitigated by: Query timeouts (5-second limit), connection pooling, read replicas (offload from primary), indexes, monitoring

## 12. References

### Database Systems

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PgBouncer](https://www.pgbouncer.org/)
- [pgaudit](https://github.com/pgaudit/pgaudit)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL CREATE VIEW (security_invoker)](https://www.postgresql.org/docs/current/sql-createview.html)
- [AWS Row-Level Security Recommendations for Multi-Tenant PostgreSQL](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/rls.html)

### Managed Database Services

- [AWS RDS](https://aws.amazon.com/rds/)
- [AWS RDS Proxy](https://aws.amazon.com/rds/proxy/)
- [GCP Cloud SQL](https://cloud.google.com/sql)
- [Azure Database for PostgreSQL](https://azure.microsoft.com/en-us/products/postgresql/)

### Encryption & Key Management

- [AWS KMS](https://aws.amazon.com/kms/)
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html)
- [GCP Cloud KMS](https://cloud.google.com/security/products/security-key-management)
- [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/)
- [Google Tink](https://developers.google.com/tink)

### Secrets Management Services

- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [GCP Secret Manager](https://cloud.google.com/security/products/secret-manager)
- [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/)
- [HashiCorp Vault](https://developer.hashicorp.com/vault)

### Standards & Compliance

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR](https://gdpr.eu/)
- [NIST SP 800-63B-4 Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [PCI DSS v4.0.1 Standard](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf)
- [HIPAA Documentation Retention (45 CFR 164.316)](https://www.law.cornell.edu/cfr/text/45/164.316)

### Incident Reports

- [FTC: Uber Revised Complaint (2016 Breach)](https://www.ftc.gov/system/files/documents/cases/152_3054_c-4662_uber_technologies_revised_complaint.pdf)
- [GAO-18-559: Equifax Data Breach](https://www.gao.gov/assets/gao-18-559.pdf)
- [DOJ: Capital One Intruder Convicted](https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions)
- [MGM Resorts Breach: 10.6M Guests Confirmed](https://www.silicon.co.uk/cloud/cloud-management/mgm-resorts-data-breach-10-million-331834)
