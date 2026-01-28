# Data Pipeline Security Guide

**Last Updated:** January 28, 2026

A cloud-agnostic guide focused on securing production data pipelines (Kafka for streaming, Spark for processing) with defense-in-depth security, high availability, and disaster recovery. This guide includes industry best practices and lessons learned from real-world implementations.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Do You Need Kafka + Spark?](#3-do-you-need-kafka--spark)
   - [When You Actually Need This Stack](#when-you-actually-need-this-stack)
   - [When to Use Simpler Alternatives](#when-to-use-simpler-alternatives)
   - [Cost Comparison](#cost-comparison)
4. [Architecture Patterns](#4-architecture-patterns)
   - [Managed Services (Recommended)](#managed-services-recommended)
   - [Pipeline Architecture](#pipeline-architecture)
   - [Network Topology](#network-topology)
5. [Kafka Security](#5-kafka-security)
   - [Authentication](#authentication)
   - [Authorization (ACLs)](#authorization-acls)
   - [Encryption](#encryption)
   - [Network Isolation](#network-isolation)
6. [Spark Security](#6-spark-security)
   - [Authentication & Authorization](#authentication--authorization)
   - [Encryption](#encryption-1)
   - [Network Security](#network-security)
   - [Secrets Management Integration](#secrets-management-integration)
7. [Data Security & Compliance](#7-data-security--compliance)
   - [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi)
   - [Data Masking & Tokenization](#data-masking--tokenization)
   - [Audit Logging](#audit-logging)
   - [Compliance Requirements](#compliance-requirements)
8. [Schema Management](#8-schema-management)
   - [Schema Registry Security](#schema-registry-security)
   - [Schema Validation](#schema-validation)
   - [Backward/Forward Compatibility](#backwardforward-compatibility)
9. [Access Control & IAM](#9-access-control--iam)
   - [Kafka Topic ACLs](#kafka-topic-acls)
   - [Spark Job Permissions](#spark-job-permissions)
   - [Cross-Account Access](#cross-account-access)
   - [Workload Identity Patterns](#workload-identity-patterns)
10. [Monitoring & Observability](#10-monitoring--observability)
    - [Kafka Metrics](#kafka-metrics)
    - [Spark Metrics](#spark-metrics)
    - [Centralized Logging](#centralized-logging)
    - [Security Alerting](#security-alerting)
11. [Attack Scenarios Prevented](#11-attack-scenarios-prevented)
12. [References](#12-references)

## 1. Overview

This guide provides production-ready patterns for securing data pipelines across cloud providers, with an opinionated focus on Apache Kafka for event streaming and Apache Spark for stream/batch processing. Data pipelines process sensitive information including user events, financial transactions, healthcare records, and business metrics. A pipeline breach can expose massive datasets, violate compliance requirements, and compromise downstream systems.

**Common Use Cases:**

- Change Data Capture (CDC) from databases to data warehouses
- Real-time analytics and metrics pipelines
- ETL/ELT for data lakes and warehouses
- Machine learning feature engineering pipelines
- Event-driven microservices communication
- Log aggregation and analysis
- IoT data ingestion and processing

**Real-World Breaches:**

- **Uber (2016)**: Exposed data pipeline credentials in GitHub, 57M users compromised
- **Elasticsearch clusters (ongoing)**: Unsecured Kafka/Elasticsearch pipelines exposing PII publicly
- **Healthcare providers (multiple)**: Unencrypted data pipelines exposing PHI in transit
- **Financial institutions**: Kafka ACL misconfigurations allowing unauthorized access to transaction streams

**Core Principles:**

- **Defense in Depth**: Multiple security layers from ingestion to processing to storage
- **Least Privilege**: Minimize access permissions and blast radius
- **Managed Services First**: Use cloud-managed Kafka and Spark to reduce operational burden
- **Encryption Everywhere**: At-rest, in-transit, and field-level for sensitive data
- **High Availability**: Multi-AZ deployments with automatic failover
- **Audit Everything**: Comprehensive logging for compliance and threat detection

## 2. Prerequisites

### Required Tools

- [Kafka CLI](https://kafka.apache.org/downloads) - Kafka command-line tools
- [Apache Spark](https://spark.apache.org/downloads.html) - Spark for local testing (managed services handle production)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning

### External Services

Cloud-agnostic service options for managed Kafka, Spark, storage, and secrets management.

| Service Category                  | AWS                               | GCP                           | Azure                         | Multi-Cloud               |
| --------------------------------- | --------------------------------- | ----------------------------- | ----------------------------- | ------------------------- |
| **Managed Kafka** (required)      | MSK (Managed Streaming for Kafka) | Managed Kafka (via Confluent) | Event Hubs (Kafka-compatible) | Confluent Cloud           |
| **Managed Spark** (required)      | EMR (Elastic MapReduce)           | Dataproc                      | HDInsight, Databricks         | Databricks                |
| **Object Storage** (required)     | S3                                | Cloud Storage (GCS)           | Blob Storage                  | -                         |
| **Data Warehouse**                | Redshift, Athena                  | BigQuery                      | Synapse Analytics             | Snowflake                 |
| **Schema Registry**               | MSK Schema Registry, Confluent    | Confluent Schema Registry     | Confluent Schema Registry     | Confluent Schema Registry |
| **Secrets Management** (required) | Secrets Manager                   | Secret Manager                | Key Vault                     | HashiCorp Vault           |
| **Key Management** (required)     | KMS                               | Cloud KMS                     | Key Vault                     | HashiCorp Vault           |
| **Logging & SIEM** (required)     | CloudWatch Logs, CloudTrail       | Cloud Logging                 | Monitor                       | Splunk, ELK Stack, Loki   |

**Notes:**

- **Managed Kafka**: MSK, Confluent Cloud, or Event Hubs (Kafka-compatible). Never run self-managed Kafka in production.
- **Managed Spark**: EMR, Dataproc, Databricks. Avoid running Spark on self-managed clusters.
- **Schema Registry**: Confluent Schema Registry is the de facto standard for Kafka schema management.

## 3. Do You Need Kafka + Spark?

**Default Recommendation: Most teams should start with simpler alternatives and only adopt Kafka + Spark when they have proven, measured requirements.**

### When You Actually Need This Stack

Choose Kafka + Spark when you have **proven requirements**:

**Event Streaming with Kafka:**

- **High-throughput event ingestion** (>100k events/second sustained)
- **Event replay required** (reprocess historical events for debugging or new consumers)
- **Multiple consumers per event stream** (fan-out to analytics, ML, monitoring)
- **Ordered event processing** (strict ordering guarantees within partitions)
- **Long retention periods** (days to weeks of event history)
- **Change Data Capture (CDC)** from databases to data warehouses

**Stream Processing with Spark:**

- **Complex transformations** (joins across multiple streams, windowing, aggregations)
- **Unified batch + streaming** (same codebase for both processing modes)
- **Large-scale data processing** (terabytes to petabytes)
- **Machine learning pipelines** (feature engineering, model training on streams)
- **SQL-based transformations** (Spark SQL for data engineers familiar with SQL)

**Operational Requirements:**

- Team has 2-3+ engineers who understand Kafka and Spark internals
- Budget allows $800-1,500+/month for managed services
- Willing to manage partitions, consumer groups, offsets, checkpointing

### When to Use Simpler Alternatives

**You probably DON'T need Kafka + Spark if:**

- ❌ You have <50k events/day (use SQS + Lambda or Pub/Sub + Cloud Functions)
- ❌ Events don't need replay (use simple queues)
- ❌ Single consumer per event type (use SQS, Pub/Sub, Service Bus)
- ❌ Simple transformations (map, filter) (use Lambda, Cloud Functions)
- ❌ Your team is <20 engineers (operational complexity too high)
- ❌ Budget is <$800/month for data infrastructure

**Simpler Alternatives:**

| Use Case                 | Instead of Kafka + Spark                | Why                               |
| ------------------------ | --------------------------------------- | --------------------------------- |
| Simple async jobs        | SQS + Lambda                            | Serverless, $0-50/month, zero ops |
| Event notifications      | SNS + Lambda, Pub/Sub + Cloud Functions | Built-in fan-out, managed         |
| Log aggregation          | CloudWatch Logs, Cloud Logging, Kinesis | Purpose-built, cheaper            |
| ETL (batch only)         | AWS Glue, Dataflow, Azure Data Factory  | Managed, serverless               |
| Simple stream processing | Kinesis Analytics, Dataflow             | Simpler than Spark                |
| Small-scale analytics    | BigQuery direct inserts, Redshift COPY  | No intermediate streaming layer   |

**Example: Event-Driven Architecture Without Kafka**

```
API → SNS Topic → [Lambda 1 (Email), Lambda 2 (Analytics), Lambda 3 (Webhook)]
```

**Cost:** ~$10-50/month for millions of events
**Operational Complexity:** Zero (fully managed)
**When to migrate to Kafka:** When you need event replay or Lambda timeout limits (15 min) become a constraint

### Cost Comparison

**Monthly Costs (Production Workloads):**

**Simple Alternative (SQS + Lambda):**

- SQS: $0.40 per million requests (~$10-30 for typical usage)
- Lambda: $0.20 per million requests (~$20-50 for 1GB, 3s avg)
- **Total: $30-80/month** for millions of events

**Kafka + Spark Stack (Managed Services):**

- **AWS MSK** (3 brokers, kafka.m5.large): $350/month
- **AWS EMR** (3 nodes, m5.xlarge, spot instances): $400-600/month
- **S3 Storage** (500GB): $12/month
- **Data Transfer**: $20-50/month
- **Secrets Manager**: $1-3/month
- **CloudWatch/Logging**: $10-30/month
- **Total: $800-1,050/month**

**Databricks Alternative (Managed Spark + Delta Lake):**

- **Databricks** (Standard tier, spot instances): $600-1,000/month
- **MSK or Confluent Cloud** (3 brokers): $350-500/month
- **S3/GCS Storage**: $12-25/month
- **Total: $1,000-1,500/month**

**Reality Check:** Kafka + Spark costs 10-25x more than SQS + Lambda for most workloads. Only adopt when you have specific requirements (event replay, complex transformations, >100k events/sec) that justify the cost and operational complexity.

## 4. Architecture Patterns

### Managed Services (Recommended)

**Never run self-managed Kafka or Spark clusters in production.** Use managed cloud services.

**Why Managed Services:**

| Aspect                 | Managed (MSK, EMR, Databricks)                       | Self-Hosted (EC2, GCE, VMs)                        |
| ---------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| **Operational Burden** | Low - provider handles patching, monitoring, scaling | High - you manage everything                       |
| **High Availability**  | Built-in multi-AZ, automatic failover                | Manual configuration, complex setup                |
| **Security Patching**  | Automatic updates for CVEs                           | Manual patching, delayed responses                 |
| **Scaling**            | Click to scale, auto-scaling options                 | Manual cluster resizing, downtime                  |
| **Cost**               | Predictable pricing, pay for usage                   | Hidden costs (ops team, downtime)                  |
| **Best For**           | Production workloads                                 | Cost optimization at extreme scale (Netflix, Uber) |

**Configuration Recommendations:**

**Managed Kafka (MSK, Confluent Cloud, Event Hubs):**

- Multi-AZ deployment (3 availability zones minimum)
- Encryption at rest (KMS/CMEK)
- Encryption in transit (TLS 1.2+)
- Private subnets (no public internet access)
- IAM authentication or mTLS (not SASL/PLAIN)

**Managed Spark (EMR, Dataproc, Databricks):**

- Auto-scaling enabled (scale workers based on load)
- Spot instances for workers (60-80% cost savings)
- Encryption at rest and in transit
- IAM roles for data access (not access keys)
- Private subnets

### Pipeline Architecture

**Recommended Data Flow:**

```
Source Systems (Databases, APIs, Logs)
  ↓
Kafka Topics (partitioned by key, 7-30 day retention)
  ↓
Spark Streaming Jobs (consume, transform, enrich)
  ↓
├─→ Structured Data → PostgreSQL / Data Warehouse (BigQuery, Redshift, Synapse)
├─→ Raw Documents → S3/GCS/Blob (partitioned by date: /year/month/day/)
└─→ Document Metadata → PostgreSQL (for querying)
  ↓
Analytics / ML / Business Intelligence
```

**Key Patterns:**

**1. Change Data Capture (CDC):**

```
PostgreSQL → Debezium CDC → Kafka Topic → Spark Streaming → Data Warehouse
```

**2. Event-Driven Microservices:**

```
API → Kafka Topic → [Spark Job 1, Spark Job 2, Spark Job 3] → Different Storage
```

**3. Real-Time Analytics:**

```
Application Events → Kafka → Spark Streaming (windowed aggregations) → Redis/PostgreSQL → Dashboard
```

**4. Machine Learning Pipeline:**

```
Raw Events → Kafka → Spark (feature engineering) → S3 (training data) → ML Model Training
```

### Network Topology

**Deploy Kafka and Spark in private subnets with no direct internet access.**

**Architecture:**

```
Internet → Internet Gateway → Public Subnet (NAT Gateway, Bastion/VPN)
                                      ↓
                              Private Subnet (Kafka Brokers, Spark Clusters)
                                      ↓
                              Private Subnet (Databases, S3 VPC Endpoint)
```

**Configuration:**

- **Kafka brokers** in private subnets (3+ AZs)
- **Spark clusters** in private subnets (same VPC as Kafka or VPC peering)
- **S3/GCS access** via VPC endpoints (no internet routing)
- **Bastion host or VPN** for administrative access
- **Security groups** allow only required traffic (Kafka: 9094 TLS, Spark: cluster-internal)

**Benefits:**

- Kafka and Spark not accessible from internet
- Network-level isolation even if credentials compromised
- Reduced data transfer costs (stay within cloud network)
- Compliance-friendly (data never leaves private network)

## 5. Kafka Security

### Authentication

Kafka supports multiple authentication mechanisms. Use IAM authentication (AWS MSK) or mTLS for production.

**Recommended: IAM Authentication (AWS MSK)**

```bash
# MSK cluster with IAM authentication
aws kafka create-cluster \
  --cluster-name production-kafka \
  --broker-node-group-info '{
    "ClientSubnets": ["subnet-abc123", "subnet-def456", "subnet-ghi789"],
    "InstanceType": "kafka.m5.large",
    "SecurityGroups": ["sg-kafka"],
    "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1000}}
  }' \
  --client-authentication '{
    "Sasl": {"Iam": {"Enabled": true}}
  }' \
  --encryption-info '{
    "EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": true},
    "EncryptionAtRest": {"DataVolumeKMSKeyId": "arn:aws:kms:..."}
  }'
```

**Client Configuration (Python):**

```python
from kafka import KafkaProducer
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

producer = KafkaProducer(
    bootstrap_servers=['b-1.kafka.amazonaws.com:9098'],
    security_protocol='SASL_SSL',
    sasl_mechanism='OAUTHBEARER',
    sasl_oauth_token_provider=MSKAuthTokenProvider(region='us-east-1'),
    ssl_check_hostname=True
)
```

**Benefits:**

- No credentials to manage (uses IAM roles)
- Short-lived tokens (15-minute expiration)
- Integrated with cloud IAM (fine-grained policies)

**Alternative: mTLS (Mutual TLS)**

For Confluent Cloud or Event Hubs:

```python
producer = KafkaProducer(
    bootstrap_servers=['kafka.confluent.cloud:9092'],
    security_protocol='SSL',
    ssl_cafile='/path/to/ca-cert',
    ssl_certfile='/path/to/client-cert.pem',
    ssl_keyfile='/path/to/client-key.pem'
)
```

**Never use SASL/PLAIN** (plaintext passwords) in production.

### Authorization (ACLs)

Kafka ACLs control who can read/write to topics. Implement least-privilege access.

**Kafka ACL Structure:**

```bash
# Grant read access to specific topic for consumer group
kafka-acls --add \
  --allow-principal User:spark-consumer \
  --operation Read \
  --topic user-events \
  --group spark-analytics

# Grant write access to producer
kafka-acls --add \
  --allow-principal User:api-producer \
  --operation Write \
  --topic user-events

# Deny all access by default (recommended)
kafka-acls --add \
  --deny-principal User:* \
  --operation All \
  --topic *
```

**Best Practices:**

- Default deny all (explicit allowlist)
- Separate principals for producers and consumers
- Topic-level permissions (never cluster-wide wildcards)
- Consumer groups have read-only access
- Producers have write-only access to specific topics
- No `User:*` or `--topic *` wildcards in production

**AWS MSK IAM Policy Example:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kafka-cluster:Connect",
        "kafka-cluster:DescribeTopic",
        "kafka-cluster:ReadData"
      ],
      "Resource": [
        "arn:aws:kafka:us-east-1:123456789012:cluster/production-kafka/*",
        "arn:aws:kafka:us-east-1:123456789012:topic/production-kafka/*/user-events",
        "arn:aws:kafka:us-east-1:123456789012:group/production-kafka/*/spark-analytics"
      ]
    }
  ]
}
```

**Critical:** Without ACLs, any authenticated user can read/write any topic.

### Encryption

**Encryption in Transit (TLS):**

Enable TLS for all client-broker and broker-broker communication.

```bash
# MSK: Enforce TLS
--encryption-info '{
  "EncryptionInTransit": {
    "ClientBroker": "TLS",      # TLS only (not TLS_PLAINTEXT)
    "InCluster": true            # Broker-to-broker encryption
  }
}'
```

**Encryption at Rest:**

Enable KMS encryption for data stored on Kafka broker disks.

```bash
# MSK: Enable KMS encryption
--encryption-info '{
  "EncryptionAtRest": {
    "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
  }
}'
```

**Field-Level Encryption (Application-Side):**

For highly sensitive data (PII, PHI, PCI), encrypt specific fields before sending to Kafka.

```python
from aws_encryption_sdk import encrypt, decrypt
import json

# Encrypt sensitive fields before producing to Kafka
def encrypt_sensitive_fields(event, kms_key_id):
    event['ssn'] = encrypt(
        source=event['ssn'],
        key_ids=[kms_key_id]
    )
    return json.dumps(event)

producer.send('user-events', encrypt_sensitive_fields(event, kms_key_id))
```

**Benefits:**

- Even with Kafka access, sensitive data is encrypted
- Encryption key separate from Kafka (KMS access required)
- Meets compliance requirements (HIPAA, PCI-DSS)

### Network Isolation

**Security Groups (AWS) / Firewall Rules (GCP, Azure):**

Restrict Kafka broker access to authorized sources only.

**Example Security Group (AWS MSK):**

| Type     | Protocol | Port | Source           | Purpose                     |
| -------- | -------- | ---- | ---------------- | --------------------------- |
| Inbound  | TCP      | 9094 | sg-spark-cluster | Spark consumers (TLS + IAM) |
| Inbound  | TCP      | 9094 | sg-api-servers   | API producers (TLS + IAM)   |
| Inbound  | TCP      | 9094 | sg-bastion       | Admin access (maintenance)  |
| Outbound | All      | All  | 0.0.0.0/0        | Allow outbound              |

**Best Practices:**

- Use security group IDs as sources (not CIDR ranges)
- Never allow `0.0.0.0/0` inbound on Kafka ports
- Separate security groups per environment (dev, staging, prod)
- TLS ports only (9094 for IAM, 9093 for mTLS)

**VPC Peering for Cross-VPC Access:**

If Spark and Kafka are in different VPCs:

```bash
# AWS: Create VPC peering connection
aws ec2 create-vpc-peering-connection \
  --vpc-id vpc-kafka \
  --peer-vpc-id vpc-spark

# Update route tables to allow traffic
aws ec2 create-route \
  --route-table-id rtb-spark \
  --destination-cidr-block 10.0.0.0/16 \
  --vpc-peering-connection-id pcx-abc123
```

## 6. Spark Security

### Authentication & Authorization

**IAM Roles for Data Access (Recommended):**

Grant Spark clusters IAM roles to access S3/GCS/Blob without access keys.

**AWS EMR with IAM Roles:**

```bash
# Create IAM role for EMR cluster
aws iam create-role \
  --role-name EMR-Spark-DataAccess \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach policy for S3 access
aws iam attach-role-policy \
  --role-name EMR-Spark-DataAccess \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Launch EMR cluster with IAM role
aws emr create-cluster \
  --name "Spark Processing Cluster" \
  --release-label emr-6.10.0 \
  --applications Name=Spark \
  --ec2-attributes '{
    "InstanceProfile": "EMR-Spark-DataAccess",
    "SubnetId": "subnet-private-1"
  }'
```

**Spark Configuration (No Access Keys):**

```python
# Spark automatically uses IAM role - no credentials needed
spark = SparkSession.builder \
    .appName("SecureSparkJob") \
    .config("spark.hadoop.fs.s3a.aws.credentials.provider",
            "com.amazonaws.auth.InstanceProfileCredentialsProvider") \
    .getOrCreate()

# Read from S3 (IAM role provides access)
df = spark.read.parquet("s3a://data-bucket/events/")
```

**GCP Dataproc with Workload Identity:**

```bash
# Grant service account access to GCS
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:spark-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

# Launch Dataproc cluster with service account
gcloud dataproc clusters create spark-cluster \
  --region=us-central1 \
  --service-account=spark-sa@PROJECT_ID.iam.gserviceaccount.com
```

**Databricks with Instance Profiles:**

```python
# Configure Databricks cluster with instance profile
# In Databricks UI: Cluster → Advanced Options → Instance Profile
# Select IAM role: arn:aws:iam::123456789012:instance-profile/databricks-spark-role
```

**Kerberos Authentication (Self-Managed Clusters):**

For self-managed Spark clusters, use Kerberos:

```bash
# Spark submit with Kerberos principal
spark-submit \
  --principal spark/hostname@REALM \
  --keytab /etc/security/keytabs/spark.keytab \
  --master yarn \
  --deploy-mode cluster \
  spark-job.py
```

**Never use hardcoded access keys or passwords in Spark configuration.**

### Encryption

**Encryption at Rest:**

Enable encryption for Spark shuffle data and RDD cache.

```python
spark = SparkSession.builder \
    .appName("EncryptedSparkJob") \
    .config("spark.io.encryption.enabled", "true") \
    .config("spark.io.encryption.keySizeBits", "256") \
    .config("spark.io.encryption.keygen.algorithm", "HmacSHA256") \
    .getOrCreate()
```

**Encryption in Transit:**

Enable SSL/TLS for Spark component communication.

```python
spark = SparkSession.builder \
    .config("spark.ssl.enabled", "true") \
    .config("spark.ssl.protocol", "TLSv1.2") \
    .config("spark.ssl.keyStore", "/path/to/keystore.jks") \
    .config("spark.ssl.keyStorePassword", "keystore-password") \
    .config("spark.ssl.trustStore", "/path/to/truststore.jks") \
    .config("spark.ssl.trustStorePassword", "truststore-password") \
    .getOrCreate()
```

**Shuffle Encryption:**

Encrypt data shuffled between Spark executors.

```python
spark = SparkSession.builder \
    .config("spark.network.crypto.enabled", "true") \
    .config("spark.network.crypto.keyLength", "256") \
    .getOrCreate()
```

### Network Security

**Security Groups for Spark Clusters:**

| Type     | Protocol | Port      | Source           | Purpose                     |
| -------- | -------- | --------- | ---------------- | --------------------------- |
| Inbound  | TCP      | 7077      | sg-spark-cluster | Spark master-worker         |
| Inbound  | TCP      | 7000-7100 | sg-spark-cluster | Block manager               |
| Inbound  | TCP      | 4040      | sg-bastion       | Spark UI (admin only)       |
| Inbound  | TCP      | 18080     | sg-bastion       | History server (admin only) |
| Outbound | All      | All       | 0.0.0.0/0        | Allow outbound              |

**Critical:** Never expose Spark UI (4040) or History Server (18080) to the internet. Access via VPN or bastion host only.

### Secrets Management Integration

Store database credentials, API keys, and encryption keys in external vaults.

**AWS Secrets Manager Integration:**

```python
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

# Retrieve database credentials
db_creds = get_secret('prod/spark/postgres-credentials')

# Use in Spark job
df.write \
    .format("jdbc") \
    .option("url", f"jdbc:postgresql://{db_creds['host']}:5432/analytics") \
    .option("dbtable", "events") \
    .option("user", db_creds['username']) \
    .option("password", db_creds['password']) \
    .save()
```

**GCP Secret Manager Integration:**

```python
from google.cloud import secretmanager

def get_secret_gcp(project_id, secret_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode('UTF-8')

api_key = get_secret_gcp('my-project', 'api-key')
```

## 7. Data Security & Compliance

### Field-Level Encryption for PII/PHI

Encrypt sensitive fields (SSN, credit card, health records) before storing in Kafka or S3.

**Envelope Encryption Pattern:**

```python
from aws_encryption_sdk import EncryptionSDKClient, StrictAwsKmsMasterKeyProvider

# Initialize encryption client
kms_key_id = 'arn:aws:kms:us-east-1:123456789012:key/abc-123'
client = EncryptionSDKClient()
kms_provider = StrictAwsKmsMasterKeyProvider(key_ids=[kms_key_id])

# Encrypt sensitive field
def encrypt_field(plaintext):
    ciphertext, _ = client.encrypt(
        source=plaintext,
        key_provider=kms_provider
    )
    return ciphertext

# Decrypt when needed (requires KMS permissions)
def decrypt_field(ciphertext):
    plaintext, _ = client.decrypt(
        source=ciphertext,
        key_provider=kms_provider
    )
    return plaintext

# Usage in Spark job
from pyspark.sql.functions import udf
from pyspark.sql.types import BinaryType

encrypt_udf = udf(encrypt_field, BinaryType())

df = df.withColumn("ssn_encrypted", encrypt_udf(df.ssn)) \
       .drop("ssn")  # Remove plaintext column
```

**Benefits:**

- Even with S3/Kafka access, data is encrypted
- Decryption requires separate KMS permissions
- Meets HIPAA, PCI-DSS, GDPR encryption requirements

### Data Masking & Tokenization

Mask sensitive data for non-production environments or analytics.

**Data Masking (Spark SQL):**

```python
from pyspark.sql.functions import sha2, concat, lit

# Hash email addresses for analytics (irreversible)
df = df.withColumn("email_hash", sha2(df.email, 256))

# Mask credit card (show last 4 digits only)
df = df.withColumn("cc_masked",
    concat(lit("****-****-****-"), df.credit_card.substr(-4, 4))
)

# Redact SSN completely
df = df.withColumn("ssn_redacted", lit("***-**-****"))
```

**Tokenization (Reversible):**

For cases where you need to re-identify data later:

```python
# Store mapping in separate encrypted table
token_map = {}

def tokenize(value):
    if value not in token_map:
        token_map[value] = generate_random_token()
    return token_map[value]

tokenize_udf = udf(tokenize, StringType())
df = df.withColumn("ssn_token", tokenize_udf(df.ssn))
```

### Audit Logging

**Kafka Audit Logging:**

Enable broker audit logs to track topic access.

```bash
# MSK: Enable CloudWatch Logs for broker logs
aws kafka update-monitoring \
  --cluster-arn arn:aws:kafka:us-east-1:123456789012:cluster/production-kafka \
  --current-version K1X5R2ABCDEFGH \
  --logging-info '{
    "BrokerLogs": {
      "CloudWatchLogs": {
        "Enabled": true,
        "LogGroup": "/aws/msk/production-kafka"
      }
    }
  }'
```

**What Gets Logged:**

- Client connections (IP addresses, principals)
- Topic access (reads, writes)
- ACL changes
- Authentication failures

**Spark Audit Logging:**

Enable event logging for Spark jobs.

```python
spark = SparkSession.builder \
    .config("spark.eventLog.enabled", "true") \
    .config("spark.eventLog.dir", "s3a://audit-logs/spark-events/") \
    .config("spark.history.fs.logDirectory", "s3a://audit-logs/spark-events/") \
    .getOrCreate()
```

**What Gets Logged:**

- Job submissions (user, application ID)
- Stage completions (data read/written)
- Executor metrics (CPU, memory usage)
- Failures and exceptions

**Forward to SIEM:**

Send logs to centralized SIEM (Splunk, ELK, cloud logging) for correlation and alerting.

### Compliance Requirements

**GDPR (General Data Protection Regulation):**

- Right to deletion (delete user data from Kafka topics, S3, warehouses)
- Data residency (store data in EU regions only)
- Breach notification (72 hours)
- Encryption required (field-level encryption for PII)

**HIPAA (Health Insurance Portability and Accountability Act):**

- PHI encryption (field-level encryption with KMS)
- Access logging (track all PHI access)
- BAA with cloud provider (Business Associate Agreement)
- 6-year retention for medical records (S3 lifecycle policies)

**PCI-DSS (Payment Card Industry Data Security Standard):**

- Cardholder data encryption (field-level, never store CVV)
- Access restrictions (least privilege ACLs)
- Quarterly key rotation (rotate KMS keys)
- Network segmentation (separate Kafka topics for payment data)

**CCPA (California Consumer Privacy Act):**

- Consumer data access (provide data on request)
- Right to deletion (purge from all pipeline stages)
- Opt-out of sale (flag in event streams)

## 8. Schema Management

### Schema Registry Security

Schema Registry stores Avro/Protobuf/JSON schemas for Kafka topics. Secure it to prevent schema poisoning.

**Confluent Schema Registry with Authentication:**

```bash
# Enable authentication (basic auth or mTLS)
schema.registry.url=https://schema-registry.kafka.svc.cluster.local:8081
schema.registry.basic.auth.credentials.source=USER_INFO
schema.registry.basic.auth.user.info=spark-consumer:password
```

**Schema Registry ACLs:**

```bash
# Grant read access to consumers
kafka-acls --add \
  --allow-principal User:spark-consumer \
  --operation Read \
  --resource-type Subject \
  --resource-name user-events-value

# Grant write access to producers only
kafka-acls --add \
  --allow-principal User:api-producer \
  --operation Write \
  --resource-type Subject \
  --resource-name user-events-value
```

**AWS MSK Schema Registry (Native):**

```python
from aws_schema_registry import SchemaRegistryClient

# Producer with schema registry
registry_client = SchemaRegistryClient(
    region_name='us-east-1',
    registry_name='production-schemas'
)

producer = KafkaProducer(
    bootstrap_servers=['b-1.kafka.amazonaws.com:9098'],
    value_serializer=lambda v: registry_client.serialize(v, 'user-events')
)
```

### Schema Validation

Validate data against schemas before producing to Kafka to prevent malformed data.

**Producer-Side Validation:**

```python
from confluent_kafka import avro

# Define Avro schema
value_schema = avro.loads('''
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    {"name": "user_id", "type": "string"},
    {"name": "event_type", "type": "string"},
    {"name": "timestamp", "type": "long"}
  ]
}
''')

# Producer validates against schema
producer = AvroProducer({
    'bootstrap.servers': 'kafka:9092',
    'schema.registry.url': 'http://schema-registry:8081'
}, default_value_schema=value_schema)
```

**Consumer-Side Validation:**

```python
# Spark validates schema on read
df = spark.read \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "user-events") \
    .load() \
    .selectExpr("CAST(value AS STRING) as json") \
    .select(from_json("json", expected_schema).alias("data")) \
    .select("data.*")
```

### Backward/Forward Compatibility

Use schema evolution rules to prevent breaking changes.

**Compatibility Modes:**

- **BACKWARD** (default): New schema can read old data (add optional fields)
- **FORWARD**: Old schema can read new data (remove fields)
- **FULL**: Both backward and forward compatible
- **NONE**: No compatibility checks (dangerous)

**Example: Add Optional Field (Backward Compatible):**

```json
// Old schema
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    {"name": "user_id", "type": "string"},
    {"name": "event_type", "type": "string"}
  ]
}

// New schema (backward compatible)
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    {"name": "user_id", "type": "string"},
    {"name": "event_type", "type": "string"},
    {"name": "metadata", "type": ["null", "string"], "default": null}  // Optional
  ]
}
```

**Set Compatibility Mode:**

```bash
# Set BACKWARD compatibility for all schemas
curl -X PUT http://schema-registry:8081/config \
  -H "Content-Type: application/json" \
  -d '{"compatibility": "BACKWARD"}'
```

## 9. Access Control & IAM

### Kafka Topic ACLs

Implement least-privilege access per topic and consumer group.

**Example ACL Structure:**

```bash
# Producers (write-only to specific topics)
kafka-acls --add \
  --allow-principal User:api-producer \
  --operation Write \
  --topic user-events

kafka-acls --add \
  --allow-principal User:cdc-connector \
  --operation Write \
  --topic database-changes

# Consumers (read-only from specific topics)
kafka-acls --add \
  --allow-principal User:spark-analytics \
  --operation Read \
  --topic user-events \
  --group spark-consumer-group

kafka-acls --add \
  --allow-principal User:ml-pipeline \
  --operation Read \
  --topic user-events \
  --group ml-feature-extraction

# Deny all by default
kafka-acls --add \
  --deny-principal User:* \
  --operation All \
  --topic *
```

**Best Practices:**

- One principal per application/job
- Read or write access, never both (separation of duties)
- Topic-level permissions (no wildcards like `--topic *`)
- Consumer groups unique per application
- Regular audit of ACL rules (quarterly review)

### Spark Job Permissions

Grant Spark jobs minimum required permissions for data access.

**AWS IAM Policy for Spark (Least Privilege):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::input-data-bucket",
        "arn:aws:s3:::input-data-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::output-data-bucket/spark-output/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/spark/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": ["arn:aws:kms:us-east-1:123456789012:key/data-encryption-key"]
    }
  ]
}
```

**What This Allows:**

- Read from input S3 bucket
- Write to specific output path only
- Retrieve secrets from Secrets Manager
- Decrypt data with specific KMS key

**What This Denies:**

- Cannot write to input bucket (prevents data corruption)
- Cannot read from other buckets
- Cannot access other secrets
- Cannot use other KMS keys

### Cross-Account Access

For multi-account architectures (dev/staging/prod in separate accounts):

**AWS Cross-Account S3 Access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SPARK-ACCOUNT-ID:role/EMR-Spark-Role"
      },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::central-data-lake",
        "arn:aws:s3:::central-data-lake/*"
      ]
    }
  ]
}
```

**Spark Configuration for Cross-Account:**

```python
# Assume role in different account
spark = SparkSession.builder \
    .config("spark.hadoop.fs.s3a.assumed.role.arn",
            "arn:aws:iam::DATA-ACCOUNT-ID:role/DataLakeAccess") \
    .config("spark.hadoop.fs.s3a.assumed.role.session.name", "spark-session") \
    .getOrCreate()

df = spark.read.parquet("s3a://central-data-lake/events/")
```

### Workload Identity Patterns

**AWS IRSA (IAM Roles for Service Accounts) - Kubernetes:**

If running Spark on Kubernetes:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spark-driver
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/SparkDriverRole

---
apiVersion: spark.apache.org/v1beta2
kind: SparkApplication
metadata:
  name: spark-job
spec:
  driver:
    serviceAccount: spark-driver
```

**GCP Workload Identity:**

```bash
# Bind Kubernetes service account to GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  spark-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT_ID.svc.id.goog[default/spark-driver]"
```

## 10. Monitoring & Observability

### Kafka Metrics

Monitor Kafka broker and topic health for performance and security issues.

**Key Metrics to Monitor:**

**Broker Metrics:**

- `kafka.server:type=BrokerTopicMetrics,name=MessagesInPerSec` - Ingest rate
- `kafka.network:type=RequestMetrics,name=TotalTimeMs,request=Produce` - Producer latency
- `kafka.server:type=ReplicaManager,name=UnderReplicatedPartitions` - Replication lag

**Consumer Lag:**

- `kafka.consumer:type=consumer-fetch-manager-metrics,client-id=*,topic=*,partition=*` - Lag per partition
- Alert if lag > 10,000 messages or increasing over time

**Security Metrics:**

- `kafka.server:type=BrokerTopicMetrics,name=FailedFetchRequestsPerSec` - Unauthorized read attempts
- `kafka.server:type=BrokerTopicMetrics,name=FailedProduceRequestsPerSec` - Unauthorized write attempts
- `kafka.network:type=RequestMetrics,name=RequestsPerSec,request=SaslAuthenticate` - Authentication attempts

**CloudWatch Alarms (AWS MSK):**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name kafka-high-consumer-lag \
  --alarm-description "Alert when consumer lag exceeds 10000" \
  --metric-name EstimatedMaxTimeLag \
  --namespace AWS/Kafka \
  --statistic Maximum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 10000 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:kafka-alerts
```

### Spark Metrics

Monitor Spark job performance and failures.

**Key Metrics:**

**Job Metrics:**

- `spark.job.duration` - Job execution time (alert if >10min for streaming jobs)
- `spark.job.failedStages` - Failed stages (alert on any failure)
- `spark.executor.failedTasks` - Task failures (alert if >5% failure rate)

**Resource Metrics:**

- `spark.executor.memory.used` - Memory usage (alert at >80%)
- `spark.executor.diskSpaceUsed` - Disk usage (alert at >90%)
- `spark.executor.totalCores` - CPU utilization

**Streaming Metrics:**

- `spark.streaming.receivers.recordsReceived` - Records ingested from Kafka
- `spark.streaming.waitingBatches` - Backlog (alert if increasing)
- `spark.streaming.processingDelay` - Processing lag (alert if >batch interval)

**Prometheus Integration:**

```python
spark = SparkSession.builder \
    .config("spark.metrics.conf.*.sink.prometheus.class",
            "org.apache.spark.metrics.sink.PrometheusServlet") \
    .config("spark.metrics.conf.*.sink.prometheus.path", "/metrics") \
    .config("spark.ui.prometheus.enabled", "true") \
    .getOrCreate()
```

**Grafana Dashboard:**

Use pre-built Spark dashboards:

- [Spark Monitoring Dashboard](https://grafana.com/grafana/dashboards/12644)
- Custom queries for security events (failed auth, unauthorized access)

### Centralized Logging

Forward Kafka and Spark logs to centralized SIEM for security analysis.

**Fluentd Configuration (Kubernetes):**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/kafka/*.log
      pos_file /var/log/kafka.log.pos
      tag kafka.*
      format json
    </source>

    <match kafka.**>
      @type elasticsearch
      host elasticsearch.logging.svc.cluster.local
      port 9200
      index_name kafka-logs
    </match>
```

**CloudWatch Logs Insights Queries:**

```sql
-- Failed authentication attempts
fields @timestamp, @message
| filter @message like /AuthenticationException/
| stats count() by bin(5m)

-- Unauthorized topic access
fields @timestamp, principal, topic
| filter @message like /TOPIC_AUTHORIZATION_FAILED/
| stats count() by principal, topic
```

### Security Alerting

Configure alerts for security events.

**Critical Alerts:**

1. **Unauthorized Access Attempts** (Kafka ACL denials, Spark authentication failures)
2. **Unusual Data Volume** (sudden 10x increase in topic throughput - potential exfiltration)
3. **Schema Changes** (schema registry modifications - potential schema poisoning)
4. **Consumer Lag Spike** (sudden lag increase - potential DoS or resource exhaustion)
5. **Failed Jobs** (Spark job failures - potential malicious code injection)
6. **Secret Access** (secrets accessed from unexpected IPs or at unusual hours)

**Example Alert (CloudWatch Alarm):**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name kafka-unauthorized-access \
  --alarm-description "Alert on Kafka ACL denials" \
  --metric-name FailedFetchRequestsPerSec \
  --namespace AWS/Kafka \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
```

## 11. Attack Scenarios Prevented

This guide's security controls prevent real-world data pipeline attacks.

**Unauthorized Topic Access**

- Attack: Compromised credentials used to read sensitive Kafka topics (PII, financial transactions)
- Mitigated by: Kafka ACLs (topic-level permissions), IAM authentication (short-lived tokens), network isolation (private subnets), audit logging (track all access)

**Data Exfiltration via Spark Jobs**

- Attack: Malicious Spark job reads entire dataset and writes to attacker-controlled S3 bucket
- Mitigated by: IAM policies (write access to specific output paths only), network isolation (VPC endpoints), audit logging (track S3 writes), anomaly detection (alert on unusual data volume)

**Man-in-the-Middle Attacks**

- Attack: Intercepting unencrypted Kafka traffic to read sensitive events
- Mitigated by: TLS encryption in transit (client-broker and broker-broker), mTLS authentication (mutual certificate verification), network isolation (traffic never leaves VPC)

**Schema Poisoning**

- Attack: Modified schema in Schema Registry causes data corruption or application crashes
- Mitigated by: Schema Registry ACLs (write access for producers only), schema validation (compatibility checks), versioning (rollback to previous schema), audit logging

**Credential Theft from Spark Jobs**

- Attack: Hardcoded access keys in Spark code stolen from GitHub or logs
- Mitigated by: IAM roles (no access keys), Secrets Manager integration (credentials retrieved at runtime), secret scanning (TruffleHog blocks commits), audit logging (detect unusual secret access)

**Kafka Broker Compromise**

- Attack: Attacker gains access to Kafka broker and reads all topic data
- Mitigated by: Encryption at rest (KMS encryption on broker disks), field-level encryption (sensitive data encrypted before Kafka), network isolation (brokers not internet-accessible), multi-AZ deployment (limits blast radius)

**Spark Cluster Takeover**

- Attack: Compromised Spark cluster used to run malicious jobs or access sensitive data
- Mitigated by: Network isolation (private subnets), IAM roles (least privilege), job authentication (Kerberos or IAM), audit logging (track job submissions), resource limits (prevent resource exhaustion)

**Consumer Group Impersonation**

- Attack: Attacker creates consumer group with same name to intercept events
- Mitigated by: Kafka ACLs (consumer group permissions), IAM authentication (verified principals), audit logging (track consumer group creation), network isolation (authorized sources only)

**Unencrypted Data at Rest**

- Attack: Stolen S3 snapshots or Kafka broker disks expose plaintext sensitive data
- Mitigated by: S3 encryption at rest (SSE-KMS), Kafka encryption at rest (KMS), field-level encryption (PII/PHI encrypted with separate keys), IAM access controls (limit who can access storage)

**Insider Threat (Platform Engineer with Full Access)**

- Attack: Malicious insider with Kafka/Spark admin access exfiltrates data
- Mitigated by: Field-level encryption (admin cannot decrypt without KMS access), audit logging (track all access), separation of duties (different teams for data platform vs security), break-glass procedures (emergency access only)

## 12. References

### Apache Projects

- [Apache Kafka](https://kafka.apache.org/)
- [Apache Spark](https://spark.apache.org/)
- [Confluent Schema Registry](https://docs.confluent.io/platform/current/schema-registry/)

### Managed Services

- [AWS MSK (Managed Streaming for Kafka)](https://aws.amazon.com/msk/)
- [AWS EMR (Elastic MapReduce)](https://aws.amazon.com/emr/)
- [GCP Dataproc](https://cloud.google.com/dataproc)
- [Azure HDInsight](https://azure.microsoft.com/en-us/services/hdinsight/)
- [Databricks](https://databricks.com/)
- [Confluent Cloud](https://www.confluent.io/confluent-cloud/)

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/)
- [Google Tink](https://github.com/google/tink)

### Kafka Security

- [Kafka Security Documentation](https://kafka.apache.org/documentation/#security)
- [Confluent Security Best Practices](https://docs.confluent.io/platform/current/security/index.html)
- [AWS MSK Security Best Practices](https://docs.aws.amazon.com/msk/latest/developerguide/security-best-practices.html)

### Spark Security

- [Spark Security Documentation](https://spark.apache.org/docs/latest/security.html)
- [Databricks Security Best Practices](https://docs.databricks.com/security/index.html)

### Standards & Compliance

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GDPR](https://gdpr.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [CCPA](https://oag.ca.gov/privacy/ccpa)
