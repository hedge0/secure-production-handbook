# Database Security Guide

**Last Updated:** January 26, 2026

A cloud-agnostic guide for securing production PostgreSQL databases with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world implementations.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Architecture & Deployment](#3-architecture--deployment)
   - [Managed Databases (Required)](#managed-databases-required)
   - [High Availability & Multi-AZ](#high-availability--multi-az)
   - [Read Replica Architecture](#read-replica-architecture)
4. [Network Security](#4-network-security)
   - [Network Isolation](#network-isolation)
   - [Security Groups](#security-groups)
   - [Connection from Applications](#connection-from-applications)
5. [Authentication & Access Control](#5-authentication--access-control)
   - [Least-Privilege Database Users](#least-privilege-database-users)
   - [IAM Database Authentication](#iam-database-authentication)
   - [Secrets Management](#secrets-management)
6. [Encryption](#6-encryption)
   - [Encryption at Rest](#encryption-at-rest)
   - [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi)
   - [Encryption in Transit](#encryption-in-transit)
7. [Performance & Scaling](#7-performance--scaling)
   - [Connection Pooling](#connection-pooling)
   - [Read/Write Splitting](#readwrite-splitting)
   - [Query Optimization](#query-optimization)
   - [Monitoring](#monitoring)
8. [Backup & Disaster Recovery](#8-backup--disaster-recovery)
   - [Automated Backups](#automated-backups)
   - [Point-in-Time Recovery](#point-in-time-recovery)
   - [Disaster Recovery Procedures](#disaster-recovery-procedures)
9. [Compliance & Auditing](#9-compliance--auditing)
   - [Audit Logging](#audit-logging)
   - [Data Retention](#data-retention)
10. [Attack Scenarios Prevented](#10-attack-scenarios-prevented)
11. [References](#11-references)

## 1. Overview

Databases store critical business data, user information, and application state. A database breach can result in massive data loss, regulatory fines, and reputational damage. This guide provides production-ready patterns for securing PostgreSQL databases across cloud providers.

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

## 4. Network Security

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

### Connection from Applications

Applications must retrieve database credentials securely without hardcoding them in code or configuration files.

**From Kubernetes:**

Use Secrets Store CSI Driver to inject credentials from cloud secrets manager into Kubernetes pods. This approach keeps credentials in the external vault (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) and automatically injects them into pods at runtime.

**Why this approach:**

- Credentials never stored in Kubernetes native Secrets (which are only base64-encoded, not encrypted)
- Automatic synchronization with external vault (rotation updates pods automatically)
- Cloud-native integration using Workload Identity/IRSA (no long-lived credentials)
- Audit trail in cloud provider logs

**Cloud-native integrations:**

- **AWS EKS**: Secrets Store CSI Driver with AWS Secrets Manager
- **GKE**: Workload Identity with Secret Manager
- **AKS**: Azure Key Vault Provider for Secrets Store CSI Driver

**Setup (AWS EKS Example):**

```bash
# Step 1: Install Secrets Store CSI Driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver --namespace kube-system

# Step 2: Install AWS Secrets Manager provider
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
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
  serviceAccountName: app-service-account # Must have IRSA/Workload Identity configured
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

1. CSI driver authenticates to AWS using pod's IRSA role
2. Fetches secrets from AWS Secrets Manager
3. Creates Kubernetes Secret (`db-credentials`) with vault contents
4. Pod consumes secret via environment variables
5. When vault secret rotates, CSI driver automatically updates K8s Secret
6. Pod restart picks up new credentials (no manual intervention)

**From Serverless:**

Serverless functions retrieve credentials at runtime directly from secrets manager. This avoids storing credentials in environment variables.

**Why this approach:**

- Credentials fetched on cold start (not in deployment package)
- IAM role controls which functions can access which secrets
- Audit trail of secret access in CloudTrail
- Rotation updates are immediate (no redeployment needed)

```python
import boto3
import json

def get_db_credentials():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId='prod/database/credentials')
    return json.loads(response['SecretString'])
```

## 5. Authentication & Access Control

### Least-Privilege Database Users

Create application-specific database users with minimal required permissions.

**Never use root/admin user for application connections.**

**PostgreSQL Example:**

```sql
-- Create application user (not superuser)
CREATE USER api_app_user WITH PASSWORD 'secure_password_from_vault';

-- Grant only necessary permissions on specific tables
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, orders TO api_app_user;

-- Revoke dangerous permissions
REVOKE CREATE ON SCHEMA public FROM api_app_user;
REVOKE ALL ON pg_catalog, information_schema FROM api_app_user;

-- For read-only analytics user
CREATE USER analytics_readonly WITH PASSWORD 'secure_password_from_vault';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO analytics_readonly;
```

**Best Practices:**

- Grant permissions on specific tables, not entire schemas
- Separate users for different applications
- Revoke CREATE, DROP, ALTER permissions from application users

### IAM Database Authentication

Eliminate password-based authentication using cloud IAM roles (ephemeral 15-minute tokens).

**AWS RDS IAM Authentication:**

```python
import boto3
import psycopg2

# Generate short-lived authentication token (valid 15 minutes)
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
    sslmode='require'
)
```

**Benefits:**

- No long-lived passwords to manage or rotate
- Tokens expire after 15 minutes
- IAM controls who can generate tokens
- Audit trail in CloudTrail

**GCP Cloud SQL and Azure Database support similar IAM authentication.**

### Secrets Management

Store database credentials in external secrets manager, never in code or environment variables.

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

Modern best practices (NIST SP 800-63B, OWASP 2024): Routine rotation no longer recommended - focus on preventing exposure.

**Rotate only when:**

- Secrets confirmed or suspected compromised
- Employee with access leaves organization
- Compliance requirements mandate rotation

**Better security approach:**

- Use short-lived credentials (IAM database authentication - tokens expire after 15 minutes)
- Implement proper access controls and audit logging
- Monitor for unauthorized access attempts
- Use Workload Identity/IRSA in Kubernetes (automatic credential refresh)

## 6. Encryption

### Encryption at Rest

Enable database encryption to protect against physical disk theft and unauthorized disk access.

**Managed Database Encryption:**

Enable encryption at database creation:

- **AWS RDS**: `storage_encrypted = true` with optional KMS key
- **GCP Cloud SQL**: Enable disk encryption with customer-managed keys
- **Azure Database**: Transparent Data Encryption (TDE) enabled by default

**When Managed Encryption Protects:**

- Physical disk theft from data center
- Unauthorized access to disk snapshots
- Decommissioned disks not properly wiped

**When It Doesn't Protect:**

- Application compromise with database credentials
- SQL injection attacks
- Database administrator with legitimate access
- Stolen database backups (if not separately encrypted)

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

```python
import boto3
import base64
from cryptography.fernet import Fernet

kms = boto3.client('kms', region_name='us-east-1')

def encrypt_field(plaintext, kms_key_id):
    # Generate data encryption key from KMS
    response = kms.generate_data_key(KeyId=kms_key_id, KeySpec='AES_256')
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    # Encrypt data with DEK
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
    encrypted_data = cipher.encrypt(plaintext.encode())

    # Return both encrypted data and encrypted DEK
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
# When creating a user
kms_key_id = 'arn:aws:kms:us-east-1:123456789012:key/abcd1234...'

# Encrypt SSN before storing
encrypted_ssn = encrypt_field('123-45-6789', kms_key_id)

# Store in database
conn.execute(
    "INSERT INTO users (id, email, ssn_encrypted, ssn_dek_encrypted) VALUES ($1, $2, $3, $4)",
    [user_id, email, encrypted_ssn['encrypted_data'], encrypted_ssn['encrypted_key']]
)

# When retrieving a user
row = conn.execute("SELECT ssn_encrypted, ssn_dek_encrypted FROM users WHERE id = $1", [user_id])

# Decrypt SSN
ssn = decrypt_field(row['ssn_encrypted'], row['ssn_dek_encrypted'])
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
- **Field-level encryption**: Protects against application/database compromise, DBAs, cloud admins
- **In-transit encryption**: Protects against network eavesdropping
- **Access controls**: Prevents unauthorized KMS decrypt access

**Key Considerations:**

- **Performance**: Encrypt only necessary fields (SSN, credit cards), not entire records
- **Searchability**: Encrypted fields cannot be queried/indexed
- **Key rotation**: Rotate KEK annually, re-encrypt DEKs (data re-encryption not required)
- **Access control**: Restrict KMS key permissions to application service accounts only

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

- **AWS RDS**: Set `require_secure_transport = 1` parameter
- **GCP Cloud SQL**: Enable "Require SSL" option
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
    sslmode="require"  # Enforce SSL - connection fails if TLS not available
)
```

**SSL Modes (PostgreSQL):**

| Mode          | Encryption | Certificate Validation | Security Level | Use Case                                                    |
| ------------- | ---------- | ---------------------- | -------------- | ----------------------------------------------------------- |
| `disable`     | ❌ No      | ❌ No                  | None           | Never use in production                                     |
| `require`     | ✅ Yes     | ❌ No                  | Basic          | Minimum for production - encrypts but doesn't verify server |
| `verify-ca`   | ✅ Yes     | ⚠️ CA only             | Better         | Validates certificate authority, prevents impersonation     |
| `verify-full` | ✅ Yes     | ✅ Full                | Best           | Validates CA and hostname match - prevents all MITM attacks |

**What each mode protects against:**

- `require`: Protects data from eavesdropping but vulnerable to impersonation (attacker can present fake certificate)
- `verify-ca`: Prevents untrusted certificates but hostname mismatch possible
- `verify-full`: Maximum protection - validates both certificate authority and hostname match

**Recommendation:** Use `verify-full` with server CA certificate for production. Download CA certificate from your cloud provider and specify in connection.

## 7. Performance & Scaling

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

- **Performance**: 10x faster query response (eliminates connection overhead)
- **Security**: Prevents connection exhaustion attacks (limits max connections)
- **Reliability**: Reduces database resource consumption (fewer TCP handshakes, auth checks)

**Serverless (RDS Proxy):**

Use RDS Proxy for serverless functions because each Lambda instance creates its own connections. Without a proxy, 1000 concurrent Lambdas = 1000+ database connections (exceeds most database limits).

**How RDS Proxy works:**

- Lambda creates connection to RDS Proxy (not directly to database)
- RDS Proxy multiplexes thousands of Lambda connections into ~100 database connections
- Database sees consistent connection count regardless of Lambda scaling

**Serverless (RDS Proxy):**

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
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST,
  database: "mydb",
  max: 20, // Max connections per container
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: { rejectUnauthorized: true },
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

**Benefits:**

- 10x faster query response (eliminates connection overhead)
- Prevents connection exhaustion attacks
- Reduces database resource consumption

### Read/Write Splitting

Route read queries to replicas and write queries to primary to protect the single-write bottleneck.

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
# Good: Parameterized query
email = "'; DROP TABLE users; --"  # Same malicious input
query = "SELECT * FROM users WHERE email = $1"
params = [email]
# Database treats entire input as a literal string, not executable SQL
# Result: No users found (safe - query looks for email "'; DROP TABLE users; --")
```

**Why this works:**

- SQL structure sent to database separately from data values
- Database knows `$1` is a parameter placeholder (not SQL code)
- User input cannot modify query structure
- Bonus: Database caches query plan (faster execution)

```javascript
// Good: Parameterized query
const result = await pool.query(
  "SELECT * FROM users WHERE email = $1 AND status = $2",
  [email, "active"]
);

// Bad: String concatenation (SQL injection risk)
const result = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**Set Query Timeouts:**

```javascript
await client.query("SET statement_timeout = 5000"); // 5 second max
```

**Use LIMIT:**

```javascript
// Paginate results
const users = await pool.query(
  "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
  [limit, offset]
);
```

**Avoid N+1 Queries:**

```javascript
// Bad: N+1 queries
const users = await db.query("SELECT * FROM users LIMIT 10");
for (const user of users) {
  user.orders = await db.query("SELECT * FROM orders WHERE user_id = $1", [
    user.id,
  ]);
}

// Good: Single JOIN
const users = await db.query(`
  SELECT u.*, json_agg(o.*) as orders
  FROM users u
  LEFT JOIN orders o ON o.user_id = u.id
  GROUP BY u.id
  LIMIT 10
`);
```

**Create Indexes:**

```sql
-- Add indexes for common queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_orders_user_created ON orders(user_id, created_at DESC);
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

- **AWS**: CloudWatch RDS metrics, Performance Insights
- **GCP**: Cloud Monitoring, Query Insights
- **Azure**: Azure Monitor, Query Performance Insight

## 8. Backup & Disaster Recovery

### Automated Backups

Enable automated daily snapshots with appropriate retention.

**Configuration:**

- **AWS RDS**: Automated backups with 7-35 day retention
- **GCP Cloud SQL**: Automated backups with 7-365 day retention
- **Azure Database**: Automated backups with 7-35 day retention

**Retention Policy:**

- Daily snapshots: 30 days (hot storage)
- Monthly snapshots: 7 years (cold storage for compliance)

**Backup Encryption:**

- Enabled by default when database encryption enabled
- Backups encrypted with same KMS key as database

### Point-in-Time Recovery

Enable PITR for protection against accidental data deletion.

**Configuration:**

- **AWS RDS**: Enabled with automated backups (5-minute granularity)
- **GCP Cloud SQL**: Enabled with binary logging
- **Azure Database**: Enabled with automated backups

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
- **Azure Database**: Geo-restore

**Recovery Steps:**

1. Restore from automated snapshot or PITR (15-30 minutes)
2. Update application connection strings
3. Rotate database credentials

```bash
# Rotate credentials after recovery
aws secretsmanager create-secret \
  --name prod/database/credentials-new \
  --secret-string '{
    "username": "api_app_user",
    "password": "new-secure-password",
    "host": "prod-db-restored.cluster.us-east-1.rds.amazonaws.com"
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

## 9. Compliance & Auditing

### Audit Logging

Enable database audit logging for access tracking.

**PostgreSQL (pgaudit):**

```sql
-- Enable pgaudit extension
CREATE EXTENSION pgaudit;

-- Log DDL and writes on sensitive tables
ALTER SYSTEM SET pgaudit.log = 'ddl, write';

-- Log specific table access
ALTER TABLE users SET (pgaudit.log = 'read, write');
```

**What to Log:**

- Failed authentication attempts
- Schema changes (CREATE, ALTER, DROP)
- Data modifications on sensitive tables
- Privilege changes (GRANT, REVOKE)

**Log Forwarding:**

Forward to centralized SIEM (Splunk, ELK Stack, cloud logging).

### Data Retention

**Hot Storage (30 days):**

- Automated daily snapshots
- Fast recovery

**Cold Storage (7 years):**

- Monthly snapshots exported to S3 Glacier/GCS Coldline/Azure Archive
- Compliance requirements (SOC2, HIPAA)

**Regulatory Requirements:**

- **GDPR**: Right to deletion, 72-hour breach notification, encryption required
- **HIPAA**: PHI encryption, 6-year audit log retention, encrypted backups
- **PCI-DSS**: Cardholder data encryption, access restrictions, annual key rotation
- **SOC2**: Access controls, encryption, continuous monitoring, 1-year log retention

## 10. Attack Scenarios Prevented

This guide's security controls prevent real-world database attacks.

**Credential Theft & Unauthorized Access**

- Attack: Stolen database credentials used to access database
- Mitigated by: IAM database authentication (short-lived tokens), network isolation (private subnets), security groups (authorized sources only)

**Database Breach via Application Compromise**

- Attack: Application compromise with database credentials exposes all data
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

## 11. References

### Database Systems

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PgBouncer](https://www.pgbouncer.org/)
- [pgaudit](https://github.com/pgaudit/pgaudit)

### Managed Database Services

- [AWS RDS](https://aws.amazon.com/rds/)
- [AWS RDS Proxy](https://aws.amazon.com/rds/proxy/)
- [GCP Cloud SQL](https://cloud.google.com/sql)
- [Azure Database for PostgreSQL](https://azure.microsoft.com/en-us/products/postgresql/)

### Encryption & Key Management

- [AWS KMS](https://aws.amazon.com/kms/)
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/)
- [GCP Cloud KMS](https://cloud.google.com/kms)
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
- [Google Tink](https://github.com/google/tink)

### Secrets Management

- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [GCP Secret Manager](https://cloud.google.com/secret-manager)
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
- [HashiCorp Vault](https://www.vaultproject.io/)

### Standards & Compliance

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR](https://gdpr.eu/)
