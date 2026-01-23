# Database Security Guide

**Last Updated:** January 23, 2026

A cloud-agnostic guide for securing production databases with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world implementations across managed and self-hosted database deployments.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Database Selection & Architecture](#3-database-selection--architecture)
   - [Managed vs Self-Hosted](#managed-vs-self-hosted)
   - [High Availability & Multi-AZ](#high-availability--multi-az)
   - [Read Replica Architecture](#read-replica-architecture)
4. [Network Security](#4-network-security)
   - [Network Isolation](#network-isolation)
   - [Security Groups & Firewall Rules](#security-groups--firewall-rules)
   - [Access Patterns](#access-patterns)
5. [Authentication & Access Control](#5-authentication--access-control)
   - [Least-Privilege Database Users](#least-privilege-database-users)
   - [IAM Database Authentication](#iam-database-authentication)
   - [Connection Pooling](#connection-pooling)
   - [Secrets Management](#secrets-management)
6. [Encryption](#6-encryption)
   - [Encryption at Rest](#encryption-at-rest)
   - [Field-Level Encryption](#field-level-encryption)
   - [Encryption in Transit](#encryption-in-transit)
7. [Performance & Scaling](#7-performance--scaling)
   - [Connection Pooling Patterns](#connection-pooling-patterns)
   - [Read/Write Splitting](#readwrite-splitting)
   - [Query Optimization](#query-optimization)
   - [Monitoring & Alerting](#monitoring--alerting)
8. [Backup & Disaster Recovery](#8-backup--disaster-recovery)
   - [Backup Strategy](#backup-strategy)
   - [Point-in-Time Recovery](#point-in-time-recovery)
   - [Disaster Recovery Procedures](#disaster-recovery-procedures)
   - [Recovery Testing](#recovery-testing)
9. [Compliance & Auditing](#9-compliance--auditing)
   - [Audit Logging](#audit-logging)
   - [Data Retention](#data-retention)
   - [Regulatory Requirements](#regulatory-requirements)
10. [Attack Scenarios Prevented](#10-attack-scenarios-prevented)
    - [Authentication & Access Attacks](#authentication--access-attacks)
    - [Data Exfiltration](#data-exfiltration)
    - [Injection Attacks](#injection-attacks)
11. [References](#11-references)

## 1. Overview

Databases are the foundation of modern applications, storing critical business data, user information, and application state. A database breach can result in massive data loss, regulatory fines, and reputational damage. This guide provides production-ready patterns for securing databases across cloud providers and deployment models.

**Core Principles:**

- **Defense in Depth**: Multiple security layers from network to encryption to access control
- **Least Privilege**: Minimize access permissions and blast radius
- **High Availability**: Multi-AZ deployments with automatic failover
- **Encryption Everywhere**: At-rest, in-transit, and field-level for sensitive data
- **Managed Services First**: Use cloud-managed databases to reduce operational burden
- **Backup & Recovery**: Automated backups with tested recovery procedures

## 2. Prerequisites

### Required Tools

**Database Clients:**

- [psql](https://www.postgresql.org/docs/current/app-psql.html) - PostgreSQL command-line client
- [mysql](https://dev.mysql.com/doc/refman/8.0/en/mysql.html) - MySQL command-line client

**Security Tools:**

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning to prevent credential leaks
- Cloud provider CLIs (AWS CLI, gcloud, az) - For IAM and infrastructure management

### External Services

Cloud-agnostic service options for managed databases, secrets management, and backup storage.

| Service Category                  | AWS                             | GCP                                | Azure                             | Self-Hosted / Open Source |
| --------------------------------- | ------------------------------- | ---------------------------------- | --------------------------------- | ------------------------- |
| **Managed Databases** (required)  | RDS (PostgreSQL, MySQL, Aurora) | Cloud SQL                          | Database for PostgreSQL/MySQL     | -                         |
| **Secrets Management** (required) | Secrets Manager                 | Secret Manager                     | Key Vault                         | HashiCorp Vault           |
| **Key Management** (required)     | KMS                             | Cloud KMS                          | Key Vault                         | HashiCorp Vault           |
| **Backup Storage** (compliance)   | S3 (Standard, Glacier)          | Cloud Storage (Standard, Coldline) | Blob Storage (Hot, Cool, Archive) | MinIO, S3-compatible      |
| **Logging & SIEM** (required)     | CloudWatch Logs                 | Cloud Logging                      | Monitor                           | Splunk, ELK Stack, Loki   |

**Notes:**

- **Managed Databases**: Strongly recommended for production - reduces operational burden, provides automated backups, patching, and high availability
- **Secrets Management**: Required for storing database credentials securely
- **Key Management**: Required for field-level encryption of sensitive data (PII, PHI, PCI)

## 3. Database Selection & Architecture

### Managed vs Self-Hosted

Choose between managed cloud databases and self-hosted deployments based on operational capacity and requirements.

| Aspect                 | Managed (RDS, Cloud SQL, Azure DB)                | Self-Hosted (PostgreSQL on VMs)                      |
| ---------------------- | ------------------------------------------------- | ---------------------------------------------------- |
| **Operational Burden** | Low - provider handles patching, backups, HA      | High - you manage everything                         |
| **Cost**               | Higher - pay for convenience                      | Lower - pay only for compute/storage                 |
| **Performance**        | Good - network-attached storage (EBS, PD)         | Excellent - local NVMe SSDs possible                 |
| **Control**            | Limited - some configuration restrictions         | Full - tune all parameters                           |
| **High Availability**  | Built-in - Multi-AZ automatic failover            | Manual - must configure replication and failover     |
| **Backups**            | Automatic - daily snapshots, PITR                 | Manual - must build backup system                    |
| **Scaling**            | Easy - click to scale or add replicas             | Manual - provision VMs, configure replication        |
| **Security**           | Managed - patching, encryption, network isolation | You manage - OS patches, database patches, hardening |
| **Best For**           | Most production workloads                         | Extreme performance needs, full control requirements |

**Recommendation:** Use managed databases (AWS RDS, GCP Cloud SQL, Azure Database) for production unless you have specific requirements that necessitate self-hosting and have dedicated database operations expertise.

### High Availability & Multi-AZ

Deploy databases across multiple availability zones for automatic failover and resilience.

**Multi-AZ Configuration:**

- Primary database in AZ-1
- Synchronous replication to standby in AZ-2 (and optionally AZ-3)
- Automatic failover in 60-120 seconds if primary fails
- No data loss during failover (synchronous replication)

**Cloud Provider Implementation:**

- **AWS RDS**: Enable Multi-AZ deployment (checkbox during creation)
- **GCP Cloud SQL**: Configure high availability with automatic failover
- **Azure Database**: Enable zone-redundant high availability

**Benefits:**

- Protects against AZ-level outages
- Zero data loss during failover (synchronous replication)
- Automatic failover without manual intervention
- Transparent to application (same endpoint)

### Read Replica Architecture

Scale read-heavy workloads by routing reads to replicas and writes to primary.

**Architecture:**

```
Primary (writes only)
  ├─→ Read Replica 1 (AZ-1)
  ├─→ Read Replica 2 (AZ-2)
  └─→ Read Replica 3 (cross-region for DR or global users)
```

**When to Use Read Replicas:**

| Workload Characteristic        | Recommendation      | Reason                                     |
| ------------------------------ | ------------------- | ------------------------------------------ |
| Read-heavy (>80% reads)        | ✅ Use replicas     | Distributes load, protects primary         |
| Write-heavy (>50% writes)      | ❌ Skip replicas    | Primary still bottleneck                   |
| Real-time consistency required | ⚠️ Use with caution | Replica lag (100-500ms) causes stale reads |
| Analytics/reporting queries    | ✅ Use replicas     | Offload expensive queries from primary     |

**Replica Lag Considerations:**

- Asynchronous replication typically lags 100-500ms behind primary
- For read-after-write consistency, query primary instead of replica
- Monitor replica lag metrics and alert if lag exceeds acceptable threshold

## 4. Network Security

### Network Isolation

Deploy databases in private subnets with no direct internet access.

**Private Subnet Architecture:**

```
Internet
  ↓
Internet Gateway
  ↓
Public Subnet (NAT Gateway, Bastion/VPN)
  ↓
Private Subnet (Databases - no internet access)
```

**Configuration:**

- Databases in private subnets with no route to Internet Gateway
- Security groups allow only authorized sources (application servers, VPN)
- No public IP addresses assigned to database instances

**Benefits:**

- Database not accessible from internet (attack surface minimized)
- All access must go through controlled entry points (VPN, bastion)
- Network-level isolation even if credentials compromised

### Security Groups & Firewall Rules

Restrict database access to only authorized sources using cloud security groups.

**Example Security Group (AWS):**

| Type     | Protocol | Port | Source         | Purpose                                      |
| -------- | -------- | ---- | -------------- | -------------------------------------------- |
| Inbound  | TCP      | 5432 | sg-app-servers | Application servers (PostgreSQL)             |
| Inbound  | TCP      | 3306 | sg-app-servers | Application servers (MySQL)                  |
| Inbound  | TCP      | 5432 | sg-bastion     | Bastion host for admin access                |
| Outbound | All      | All  | 0.0.0.0/0      | Allow outbound (for managed service updates) |

**Best Practices:**

- Use security group IDs (not CIDR ranges) for source when possible
- Separate security groups for different environments (dev, staging, prod)
- Never allow `0.0.0.0/0` inbound on database ports
- Log security group changes for audit trail

### Access Patterns

**From Kubernetes Pods:**

Use Secrets Store CSI Driver to inject database credentials from cloud secrets manager:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: app-service-account
  containers:
    - name: app
      image: myapp:latest
      env:
        - name: DB_HOST
          value: "prod-db.cluster.us-east-1.rds.amazonaws.com"
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "aws-secrets"
```

**From Serverless Functions:**

Retrieve credentials at runtime from secrets manager:

```python
import boto3
import json

def get_db_credentials():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId='prod/database/credentials')
    return json.loads(response['SecretString'])

# In Lambda handler (cache credentials)
db_creds = get_db_credentials()
```

**From Containers:**

Use secrets mounted as environment variables or files.

**Admin Access:**

- **VPN**: Recommended - secure tunnel from admin workstations
- **Bastion Host**: Alternative - hardened jump server in public subnet
- **Never**: Direct internet access to database

## 5. Authentication & Access Control

### Least-Privilege Database Users

Create application-specific database users with minimal required permissions.

**PostgreSQL Example:**

```sql
-- Create application user (not superuser)
CREATE USER api_app_user WITH PASSWORD 'secure_password_from_vault';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, orders, products TO api_app_user;

-- Revoke dangerous permissions
REVOKE CREATE ON SCHEMA public FROM api_app_user;
REVOKE ALL ON pg_catalog, information_schema FROM api_app_user;

-- For read-only analytics user
CREATE USER analytics_readonly WITH PASSWORD 'secure_password_from_vault';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO analytics_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO analytics_readonly;
```

**MySQL Example:**

```sql
-- Create application user
CREATE USER 'api_app_user'@'%' IDENTIFIED BY 'secure_password_from_vault';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.users TO 'api_app_user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.orders TO 'api_app_user'@'%';

-- Revoke dangerous permissions
REVOKE CREATE, DROP, ALTER ON *.* FROM 'api_app_user'@'%';
REVOKE SUPER, PROCESS, FILE ON *.* FROM 'api_app_user'@'%';
```

**Best Practices:**

- Never use root/admin user for application connections
- Grant permissions on specific tables, not entire schemas
- Separate users for different applications or microservices
- Create read-only users for analytics and reporting
- Revoke CREATE, DROP, ALTER permissions from application users

### IAM Database Authentication

Eliminate password-based authentication using cloud IAM roles (ephemeral tokens).

**AWS RDS IAM Authentication:**

```python
import boto3
import pymysql

# Generate short-lived authentication token (valid 15 minutes)
rds_client = boto3.client('rds', region_name='us-east-1')
token = rds_client.generate_db_auth_token(
    DBHostname='prod-db.cluster.us-east-1.rds.amazonaws.com',
    Port=3306,
    DBUsername='api_iam_user',
    Region='us-east-1'
)

# Connect using token instead of password
connection = pymysql.connect(
    host='prod-db.cluster.us-east-1.rds.amazonaws.com',
    user='api_iam_user',
    password=token,  # Token replaces password
    database='mydb',
    ssl={'ssl_mode': 'REQUIRED'}
)
```

**Benefits:**

- No long-lived passwords to manage or rotate
- Tokens expire after 15 minutes (short-lived credentials)
- IAM controls who can generate tokens (centralized access control)
- Audit trail in CloudTrail for all authentication attempts

**GCP Cloud SQL and Azure Database for PostgreSQL/MySQL support similar IAM authentication patterns.**

### Connection Pooling

Reuse database connections to improve performance and prevent connection exhaustion.

**Serverless Pattern (Cloud Proxy):**

```javascript
// Use RDS Proxy for serverless functions
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.RDS_PROXY_ENDPOINT, // RDS Proxy manages pooling
  database: "mydb",
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 2, // Keep minimal per Lambda (proxy handles rest)
  idleTimeoutMillis: 1000,
  ssl: { rejectUnauthorized: true },
});

module.exports = pool;
```

**Container Pattern (Application-Level Pooling):**

```javascript
// Node.js with pg
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST,
  database: "mydb",
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 20, // Max connections per container
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: { rejectUnauthorized: true },
});

// Reuse connections
async function getUser(id) {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    return result.rows[0];
  } finally {
    client.release(); // Return to pool, don't close
  }
}
```

**Server-Level Pooling (PgBouncer):**

PgBouncer sits between application and database, multiplexing thousands of app connections into fewer database connections.

```ini
# pgbouncer.ini
[databases]
mydb = host=prod-db.cluster.us-east-1.rds.amazonaws.com port=5432 dbname=mydb

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 10000
default_pool_size = 25
```

**Benefits:**

- 10x faster query response (eliminates connection overhead)
- Prevents database connection exhaustion
- Reduces resource consumption on database server

### Secrets Management

Store database credentials in external secrets manager, never in code or environment variables committed to git.

**Secrets to Store:**

- Database host/endpoint
- Database username
- Database password
- Database name
- SSL certificates (if using custom CA)

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

**Rotate Credentials Regularly:**

- Automated rotation every 90 days (AWS Secrets Manager supports automatic rotation)
- Manual rotation after security incidents
- Zero-downtime rotation: Create new credentials, update secret, deploy, then revoke old credentials

## 6. Encryption

### Encryption at Rest

Enable database encryption to protect against physical disk theft and unauthorized disk access.

**Managed Database Encryption** (baseline protection):

Enable encryption at database creation - protects data on disk:

- **AWS RDS**: Set `storage_encrypted = true`, optionally specify KMS key
- **GCP Cloud SQL**: Enable disk encryption with customer-managed encryption keys (CMEK)
- **Azure Database**: Transparent Data Encryption (TDE) enabled by default

**When Managed Encryption Protects:**

- Physical disk theft from data center
- Unauthorized access to disk snapshots
- Decommissioned disks not properly wiped
- Cloud provider admin with physical access

**When It Doesn't Protect:**

- Application compromise with database credentials
- SQL injection attacks
- Database administrator (DBA) with legitimate access
- Stolen database backups if not separately encrypted

### Field-Level Encryption

Encrypt sensitive fields in application code before writing to database using envelope encryption.

**When to Use Field-Level Encryption:**

- **PII**: Social Security Numbers, passport numbers, driver's license numbers
- **PHI**: Medical records, diagnoses, prescriptions, patient identifiers
- **PCI**: Credit card numbers, CVV codes, expiration dates
- **Compliance requirements**: GDPR, HIPAA, PCI-DSS mandating data protection beyond database encryption
- **Zero-trust requirements**: Don't trust cloud admins or DBAs with plaintext sensitive data

**Envelope Encryption Pattern** (industry standard):

```
User Data → Encrypt with Data Encryption Key (DEK)
DEK → Encrypt with Key Encryption Key (KEK) from KMS
Store: Encrypted data + Encrypted DEK
```

**Implementation Example (Python with AWS KMS):**

```python
import boto3
import base64
from cryptography.fernet import Fernet

kms = boto3.client('kms', region_name='us-east-1')

def encrypt_field(plaintext, kms_key_id):
    """Encrypt sensitive field using envelope encryption"""
    # Generate data encryption key from KMS
    response = kms.generate_data_key(
        KeyId=kms_key_id,
        KeySpec='AES_256'
    )
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
    """Decrypt sensitive field using envelope encryption"""
    # Decrypt DEK using KMS
    response = kms.decrypt(
        CiphertextBlob=base64.b64decode(encrypted_key)
    )
    plaintext_key = response['Plaintext']

    # Decrypt data with DEK
    cipher = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
    decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted.decode()

# Usage example
kms_key_id = 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab'

# Encrypt before writing to database
result = encrypt_field('123-45-6789', kms_key_id)
# Store result['encrypted_data'] and result['encrypted_key'] in database

# Decrypt when reading from database
ssn = decrypt_field(result['encrypted_data'], result['encrypted_key'])
```

**Cloud KMS Options:**

- **AWS**: KMS with envelope encryption, automatic key rotation
- **GCP**: Cloud KMS with customer-managed encryption keys (CMEK)
- **Azure**: Key Vault for key management and encryption operations

**Database Schema Example:**

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,           -- Not encrypted (needed for login)
    name VARCHAR(255),                     -- Not encrypted (low sensitivity)
    ssn_encrypted TEXT,                    -- Encrypted SSN ciphertext
    ssn_dek_encrypted TEXT,                -- Encrypted data key for SSN
    credit_card_encrypted TEXT,            -- Encrypted credit card ciphertext
    credit_card_dek_encrypted TEXT,        -- Encrypted data key for credit card
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index on non-encrypted fields only
CREATE INDEX idx_users_email ON users(email);
```

**Key Considerations:**

- **Performance**: Encrypt only necessary fields (SSN, credit cards), not entire records
- **Searchability**: Encrypted fields cannot be queried/indexed - use searchable encryption libraries or hash indexes for lookup
- **Key rotation**: Rotate KEK annually in KMS, re-encrypt DEKs (data re-encryption not required with envelope pattern)
- **Access control**: Restrict KMS key permissions to application service accounts only

**Defense in Depth:**

Even if attackers gain database access, they cannot decrypt sensitive fields without KMS access. This protects against:

- Database credential compromise
- SQL injection attacks
- Insider threats (DBAs, cloud admins)
- Stolen database backups

### Encryption in Transit

Encrypt all database connections using TLS/SSL to prevent credential exposure and man-in-the-middle attacks.

**Enable TLS/SSL on Database:**

- **AWS RDS**: Set `require_secure_transport = 1` parameter
- **GCP Cloud SQL**: Enable "Require SSL" option, download server CA certificate
- **Azure Database**: Set `require_secure_transport = ON`

**Connection String Examples:**

```python
# PostgreSQL with SSL
import psycopg2

conn = psycopg2.connect(
    host="prod-db.cluster.us-east-1.rds.amazonaws.com",
    database="mydb",
    user="api_app_user",
    password="secure_password",
    sslmode="require"  # Enforce SSL
)
```

```python
# MySQL with SSL
import pymysql

conn = pymysql.connect(
    host="prod-db.instance.us-east-1.rds.amazonaws.com",
    database="mydb",
    user="api_app_user",
    password="secure_password",
    ssl={'ssl_mode': 'REQUIRED'}  # Enforce SSL
)
```

**SSL/TLS Modes:**

| Mode          | Encryption | Certificate Validation | Use Case                                 |
| ------------- | ---------- | ---------------------- | ---------------------------------------- |
| `disable`     | ❌ No      | ❌ No                  | Never use in production                  |
| `require`     | ✅ Yes     | ❌ No                  | Minimum for production                   |
| `verify-ca`   | ✅ Yes     | ⚠️ CA only             | Better - validates certificate authority |
| `verify-full` | ✅ Yes     | ✅ Full                | Best - validates CA and hostname         |

**Best Practice:** Use `verify-full` mode with server CA certificate for maximum security.

## 7. Performance & Scaling

### Connection Pooling Patterns

| Pattern               | Implementation                                | Use Case                     | Security Benefit                                         |
| --------------------- | --------------------------------------------- | ---------------------------- | -------------------------------------------------------- |
| **Application-Level** | ORM built-in (Sequelize, TypeORM, SQLAlchemy) | Containers, traditional apps | Prevents connection exhaustion per instance              |
| **Server-Level**      | PgBouncer, ProxySQL, RDS Proxy                | Serverless, high-scale apps  | Centralizes connection management, reduces database load |

**Benefits:**

- Prevents connection exhaustion attacks
- Reduces database resource consumption
- Improves query response time (10x faster)

### Read/Write Splitting

Route read queries to replicas and write queries to primary for read-heavy workloads.

**Implementation Pattern:**

```javascript
// Database connection manager
class DatabaseManager {
  constructor() {
    this.primary = createPool(process.env.PRIMARY_DB_URL);
    this.replicas = [
      createPool(process.env.REPLICA_1_URL),
      createPool(process.env.REPLICA_2_URL),
      createPool(process.env.REPLICA_3_URL),
    ];
  }

  // Round-robin replica selection
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
  // Read from primary to ensure latest data (avoid replica lag)
  return db.getWritePool().query("SELECT * FROM users WHERE id = $1", [id]);
}
```

**Replica Lag Handling:**

- For eventually-consistent reads (most use cases), use replicas
- For strongly-consistent reads (just created/updated data), use primary
- Monitor replica lag and alert if exceeds acceptable threshold

### Query Optimization

Optimize database queries to prevent performance degradation and resource exhaustion attacks.

**Essential Practices:**

**1. Use Prepared Statements (Prevents SQL Injection + Performance):**

```javascript
// Good: Parameterized query (prevents SQL injection, cached query plan)
const result = await pool.query(
  "SELECT * FROM users WHERE email = $1 AND status = $2",
  [email, "active"]
);

// Bad: String concatenation (SQL injection risk, no caching)
const result = await pool.query(
  `SELECT * FROM users WHERE email = '${email}' AND status = 'active'`
);
```

**2. Set Query Timeouts:**

```javascript
// Prevent long-running queries from blocking resources
const client = await pool.connect();
try {
  await client.query("SET statement_timeout = 5000"); // 5 second timeout
  const result = await client.query(expensiveQuery, params);
  return result;
} catch (err) {
  if (err.code === "57014") {
    throw new Error("Query timeout - please refine search");
  }
  throw err;
} finally {
  client.release();
}
```

**3. Use LIMIT and Pagination:**

```javascript
// Bad: Returns millions of rows
const users = await db.query("SELECT * FROM users");

// Good: Paginate results
const users = await db.query(
  "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
  [limit, offset]
);
```

**4. Avoid N+1 Query Problems:**

```javascript
// Bad: N+1 queries (1 + N)
const users = await db.query("SELECT * FROM users LIMIT 10");
for (const user of users) {
  user.orders = await db.query("SELECT * FROM orders WHERE user_id = $1", [
    user.id,
  ]);
}

// Good: Single JOIN query
const users = await db.query(`
  SELECT u.*, json_agg(o.*) as orders
  FROM users u
  LEFT JOIN orders o ON o.user_id = u.id
  GROUP BY u.id
  LIMIT 10
`);
```

**5. Create Indexes on Frequently Queried Columns:**

```sql
-- Identify slow queries
-- PostgreSQL
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Add indexes for common queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_orders_user_created ON orders(user_id, created_at DESC);
CREATE INDEX idx_products_category ON products(category_id, price);
```

**Security Impact:**

| Attack                      | Without Optimization                             | With Optimization                            |
| --------------------------- | ------------------------------------------------ | -------------------------------------------- |
| **Query Complexity Attack** | Expensive query → database overload              | Query timeout (5s) limits impact             |
| **Table Scan Attack**       | No indexes → full table scan on millions of rows | Indexes → query completes in milliseconds    |
| **Connection Exhaustion**   | Slow queries hold connections open               | Connection pooling + timeouts free resources |
| **SQL Injection**           | String concatenation vulnerable                  | Prepared statements prevent injection        |

### Monitoring & Alerting

Monitor database performance to detect attacks and degradation early.

**Key Metrics:**

| Metric                  | Alert Threshold     | Indicates                                    |
| ----------------------- | ------------------- | -------------------------------------------- |
| **Connection Count**    | >80% of max         | Connection exhaustion attack or leak         |
| **Query Latency (p99)** | >500ms              | Slow queries or missing indexes              |
| **Replica Lag**         | >5 seconds          | Replication issues or overloaded primary     |
| **CPU Utilization**     | >80% sustained      | Database overload or inefficient queries     |
| **Failed Connections**  | >10/minute          | Database unavailable or connection limit hit |
| **Slow Query Count**    | >10 queries >5s/min | Unoptimized queries or attack                |
| **Disk I/O**            | >80% utilization    | Storage bottleneck                           |
| **Deadlocks**           | >5/hour             | Application concurrency issues               |

**Cloud Provider Monitoring:**

- **AWS**: CloudWatch RDS metrics, Performance Insights
- **GCP**: Cloud Monitoring, Query Insights
- **Azure**: Azure Monitor, Query Performance Insight

## 8. Backup & Disaster Recovery

### Backup Strategy

Implement automated backups with multiple retention periods for point-in-time recovery.

**Automated Snapshots:**

- **Daily snapshots**: Retain 7-30 days (configurable)
- **Weekly snapshots**: Retain 4-12 weeks
- **Monthly snapshots**: Retain 12 months (compliance)

**Cloud Provider Configuration:**

- **AWS RDS**: Automated backups with 1-35 day retention, manual snapshots for long-term
- **GCP Cloud SQL**: Automated backups with 7-365 day retention
- **Azure Database**: Automated backups with 7-35 day retention

**Backup Verification:**

Test backups regularly by restoring to non-production environment:

```bash
# AWS RDS: Restore snapshot to test instance
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier test-restore-$(date +%Y%m%d) \
  --db-snapshot-identifier prod-snapshot-20260123 \
  --db-instance-class db.t3.medium
```

**Backup Security:**

- Encrypt backups (enabled by default if database encryption enabled)
- Store in separate AWS account/GCP project for isolation
- Restrict IAM permissions for backup access
- Enable versioning on backup storage (S3, GCS, Azure Blob)

### Point-in-Time Recovery

Enable point-in-time recovery (PITR) for protection against accidental data deletion or corruption.

**Configuration:**

- **AWS RDS**: Automated backups enable PITR (5-minute granularity)
- **GCP Cloud SQL**: Binary logging enables PITR
- **Azure Database**: Automated backups enable PITR

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
- Ransomware attack (restore to before encryption)

**RPO (Recovery Point Objective):** 5 minutes (typical PITR granularity)

### Disaster Recovery Procedures

Complete environment recovery through infrastructure as code and database backups.

**Recovery Strategy:**

**Databases (Managed Services):**

1. Restore from automated snapshot or point-in-time recovery
2. Time to restore: 15-30 minutes depending on database size
3. Update application connection strings to new database endpoint

**Cross-Region Failover:**

For mission-critical databases, maintain cross-region read replica:

- **AWS RDS**: Cross-region read replica, promote to standalone in DR
- **GCP Cloud SQL**: Cross-region replica with automatic failover
- **Azure Database**: Geo-restore from geo-redundant backups

**Failover Procedure:**

```bash
# AWS RDS: Promote read replica to standalone database
aws rds promote-read-replica \
  --db-instance-identifier prod-db-replica-us-west-2

# Update application to point to new primary
# Rotate database credentials
aws secretsmanager create-secret \
  --name prod/database/credentials-new-region \
  --secret-string '{
    "username": "api_app_user",
    "password": "new-secure-password",
    "host": "prod-db-replica-us-west-2.rds.amazonaws.com"
  }'
```

**RTO (Recovery Time Objective) Targets:**

- Database restore: 15-30 minutes
- Full environment recovery: 1-2 hours (including application deployment)

### Recovery Testing

Test disaster recovery procedures quarterly to validate RTO/RPO targets.

**Test Procedure:**

1. Restore latest snapshot to test environment
2. Verify data integrity (row counts, checksums)
3. Run application smoke tests against restored database
4. Document actual RTO achieved
5. Update runbooks based on lessons learned

**Validation:**

- Check database version matches production
- Verify all tables and data present
- Confirm application can connect and query
- Test PITR by restoring to specific timestamp

## 9. Compliance & Auditing

### Audit Logging

Enable comprehensive audit logging for database access and changes.

**Cloud Provider Audit Logs:**

- **AWS RDS**: Enable database audit logging (PostgreSQL `pgaudit`, MySQL audit plugin)
- **GCP Cloud SQL**: Enable Cloud Audit Logs and database flags for logging
- **Azure Database**: Enable auditing to Log Analytics or Storage Account

**PostgreSQL Audit Logging:**

```sql
-- Enable pgaudit extension
CREATE EXTENSION pgaudit;

-- Log all DDL and DML on sensitive tables
ALTER SYSTEM SET pgaudit.log = 'ddl, write';
ALTER SYSTEM SET pgaudit.log_catalog = 'off';
ALTER SYSTEM SET pgaudit.log_parameter = 'on';

-- Log specific table access
ALTER TABLE users SET (pgaudit.log = 'read, write');
ALTER TABLE credit_cards SET (pgaudit.log = 'read, write');
```

**What to Log:**

- Failed authentication attempts
- Schema changes (CREATE, ALTER, DROP)
- Data modifications on sensitive tables (INSERT, UPDATE, DELETE)
- Privilege changes (GRANT, REVOKE)
- Connection attempts and sources

**Log Forwarding:**

Forward database logs to centralized SIEM (Splunk, ELK Stack, cloud logging):

- **AWS**: CloudWatch Logs → Elasticsearch/Splunk
- **GCP**: Cloud Logging → BigQuery/Splunk
- **Azure**: Azure Monitor → Log Analytics/Splunk

### Data Retention

Implement tiered storage for database backups to meet compliance requirements.

**Hot Storage (30 days):**

- Automated daily snapshots
- Fast recovery (minutes)
- Higher cost

**Cold Storage (Multi-Year for Compliance):**

- Monthly snapshots exported to S3 Glacier/GCS Coldline/Azure Archive
- Slower recovery (hours)
- Lower cost
- Retain 7+ years for compliance

**Retention Policy Example:**

| Backup Type         | Retention | Storage Tier                    | Purpose                  |
| ------------------- | --------- | ------------------------------- | ------------------------ |
| Automated snapshots | 30 days   | Hot (RDS/Cloud SQL native)      | Operational recovery     |
| Weekly snapshots    | 90 days   | Warm (S3 Standard/GCS Standard) | Extended recovery window |
| Monthly snapshots   | 7 years   | Cold (S3 Glacier/GCS Coldline)  | Compliance (SOC2, HIPAA) |

### Regulatory Requirements

**GDPR (General Data Protection Regulation):**

- Right to deletion: Implement hard delete procedures for user data
- Data breach notification: 72-hour reporting requirement
- Encryption: Required for personal data
- Audit logs: Retain evidence of data processing

**HIPAA (Health Insurance Portability and Accountability Act):**

- PHI encryption: At-rest and in-transit encryption required
- Access logs: Retain audit logs for 6 years
- Backup encryption: All backups must be encrypted
- Business Associate Agreement (BAA): Required with cloud provider

**PCI-DSS (Payment Card Industry Data Security Standard):**

- Cardholder data encryption: Field-level encryption required
- Access restrictions: Least privilege, strong authentication
- Audit trails: Log and monitor all access to cardholder data
- Key management: Rotate encryption keys annually

**SOC2 (Service Organization Control 2):**

- Access controls: Role-based access, least privilege
- Encryption: Data at-rest and in-transit
- Monitoring: Continuous monitoring and alerting
- Audit logs: Retain for at least 1 year

## 10. Attack Scenarios Prevented

This guide's security controls prevent real-world database attacks commonly seen in production environments.

### Authentication & Access Attacks

**Credential Stuffing / Brute Force**

- Attack: Stolen credentials or brute force attempts to access database
- Mitigated by: IAM database authentication (no long-lived passwords), failed login monitoring, network isolation (not internet-accessible), connection from trusted sources only

**Privilege Escalation**

- Attack: Application user gains admin privileges or accesses unauthorized tables
- Mitigated by: Least-privilege database users (no CREATE/DROP/ALTER), GRANT only on specific tables, revoke permissions on system catalogs, separate users per application

### Data Exfiltration

**Database Breach via Compromised Credentials**

- Attack: Stolen database credentials used to export entire database
- Mitigated by: Field-level encryption for sensitive data (encrypted SSN/credit cards unusable without KMS access), network isolation (not internet-accessible), IAM database authentication (short-lived tokens), audit logging (detect unauthorized access)

**Insider Threat (DBA / Cloud Admin)**

- Attack: Database administrator or cloud provider admin accesses plaintext sensitive data
- Mitigated by: Field-level envelope encryption (sensitive fields encrypted with KMS, DBA cannot decrypt without application KMS permissions), audit logging (track all access), separation of duties (DBAs don't have KMS decrypt permissions)

**Backup Theft**

- Attack: Stolen database backups expose sensitive data
- Mitigated by: Backup encryption (enabled by default when database encryption enabled), field-level encryption (even decrypted backups have encrypted sensitive fields), cross-account backup storage (isolate backups from production), IAM access controls (restrict backup access)

### Injection Attacks

**SQL Injection**

- Attack: Malicious SQL injected through application inputs to access/modify database
- Mitigated by: Prepared statements (parameterized queries prevent injection), least-privilege users (limited damage from successful injection), query timeouts (prevent resource exhaustion), input validation at application layer (see API Security Guide)

**Query Complexity Attack**

- Attack: Attacker triggers expensive queries to cause database overload and denial of service
- Mitigated by: Query timeouts (5-second limit prevents long-running queries), connection pooling (limits concurrent queries), read replicas (offload expensive queries from primary), indexes (prevent full table scans), monitoring (alert on slow query count)

**Connection Exhaustion**

- Attack: Overwhelming database with connection requests to exhaust connection pool
- Mitigated by: Connection pooling (PgBouncer/RDS Proxy manages connections efficiently), connection limits (max connections enforced), network isolation (only trusted sources can connect), monitoring (alert at >80% connection usage)

## 11. References

### Database Systems

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [MySQL Documentation](https://dev.mysql.com/doc/)
- [PgBouncer](https://www.pgbouncer.org/) - PostgreSQL connection pooler

### Managed Database Services

- [AWS RDS](https://aws.amazon.com/rds/) - Amazon Relational Database Service
- [AWS RDS Proxy](https://aws.amazon.com/rds/proxy/) - Connection pooling for RDS
- [GCP Cloud SQL](https://cloud.google.com/sql) - Google Cloud SQL
- [Azure Database](https://azure.microsoft.com/en-us/products/category/databases/) - Azure managed databases

### Encryption & Key Management

- [AWS KMS](https://aws.amazon.com/kms/) - Key Management Service
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/) - Client-side encryption library
- [GCP Cloud KMS](https://cloud.google.com/kms) - Google Cloud Key Management Service
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) - Azure key management
- [Google Tink](https://github.com/google/tink) - Multi-language crypto library

### Secrets Management

- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [GCP Secret Manager](https://cloud.google.com/secret-manager)
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
- [HashiCorp Vault](https://www.vaultproject.io/)

### Security Extensions

- [pgaudit](https://github.com/pgaudit/pgaudit) - PostgreSQL audit logging extension
- [pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html) - PostgreSQL trigram extension for fuzzy search on encrypted data

### Standards & Compliance

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
- [CIS MySQL Benchmark](https://www.cisecurity.org/benchmark/mysql)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR](https://gdpr.eu/)
