# Data Pipeline Security Guide

**Last Updated:** September 22, 2026

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
   - [Spark Encryption](#spark-encryption)
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

- **Uber (2016)**: Attackers reused leaked passwords to log in to engineers' GitHub accounts (no MFA), found a hardcoded AWS access key in a private repository, and used it to download unencrypted database backups from S3, exposing 57M riders and drivers
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

| Service Category                  | AWS                               | GCP                              | Azure                         | Multi-Cloud               |
| --------------------------------- | --------------------------------- | -------------------------------- | ----------------------------- | ------------------------- |
| **Managed Kafka** (required)      | MSK (Managed Streaming for Kafka) | Managed Service for Apache Kafka | Event Hubs (Kafka-compatible) | Confluent Cloud           |
| **Managed Spark** (required)      | EMR (Elastic MapReduce)           | Dataproc                         | HDInsight, Databricks         | Databricks                |
| **Object Storage** (required)     | S3                                | Cloud Storage (GCS)              | Blob Storage                  | -                         |
| **Data Warehouse**                | Redshift, Athena                  | BigQuery                         | Synapse Analytics             | Snowflake                 |
| **Schema Registry**               | Glue Schema Registry, Confluent   | Confluent Schema Registry        | Confluent Schema Registry     | Confluent Schema Registry |
| **Secrets Management** (required) | Secrets Manager                   | Secret Manager                   | Key Vault                     | HashiCorp Vault           |
| **Key Management** (required)     | KMS                               | Cloud KMS                        | Key Vault                     | HashiCorp Vault           |
| **Logging & SIEM** (required)     | CloudWatch Logs, CloudTrail       | Cloud Logging                    | Monitor                       | Splunk, ELK Stack, Loki   |

**Notes:**

- **Managed Kafka**: MSK, GCP Managed Service for Apache Kafka, Confluent Cloud, or Event Hubs (Kafka-compatible). Never run self-managed Kafka in production.
- **Managed Spark**: EMR, Dataproc (branded Managed Service for Apache Spark since April 2026; `gcloud dataproc` and the API keep the old name), Databricks. Avoid running Spark on self-managed clusters.
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

- ❌ You have <50k events/day (use SQS + Lambda or Pub/Sub + Cloud Run functions)
- ❌ Events don't need replay (use simple queues)
- ❌ Single consumer per event type (use SQS, Pub/Sub, Service Bus)
- ❌ Simple transformations (map, filter) (use Lambda, Cloud Run functions)
- ❌ Your team is <20 engineers (operational complexity too high)
- ❌ Budget is <$800/month for data infrastructure

**Simpler Alternatives:**

| Use Case                 | Instead of Kafka + Spark                    | Why                               |
| ------------------------ | ------------------------------------------- | --------------------------------- |
| Simple async jobs        | SQS + Lambda                                | Serverless, $0-50/month, zero ops |
| Event notifications      | SNS + Lambda, Pub/Sub + Cloud Run functions | Built-in fan-out, managed         |
| Log aggregation          | CloudWatch Logs, Cloud Logging, Kinesis     | Purpose-built, cheaper            |
| ETL (batch only)         | AWS Glue, Dataflow, Azure Data Factory      | Managed, serverless               |
| Simple stream processing | Managed Service for Apache Flink, Dataflow  | Simpler than Spark                |
| Small-scale analytics    | BigQuery direct inserts, Redshift COPY      | No intermediate streaming layer   |

**Example: Event-Driven Architecture Without Kafka**

```
API → SNS Topic → [Lambda 1 (Email), Lambda 2 (Analytics), Lambda 3 (Webhook)]
```

- **Cost:** ~$10-50/month for millions of events
- **Operational Complexity:** Zero (fully managed)
- **When to migrate to Kafka:** When you need event replay or Lambda timeout limits (15 min) become a constraint

### Cost Comparison

**Monthly Costs (Production Workloads):**

**Simple Alternative (SQS + Lambda):**

- SQS: $0.40 per million requests (~$10-30 for typical usage)
- Lambda: $0.20 per million requests (~$20-50 for 1GB, 3s avg)
- **Total: $30-80/month** for millions of events

**Kafka + Spark Stack (Managed Services):**

- **AWS MSK** (3 brokers, kafka.m5.large, 100 GB each): ~$490/month ($0.21/broker-hour + $0.10/GB-month, us-east-1)
- **AWS EMR** (3 nodes, m5.xlarge, spot instances): $400-600/month
- **S3 Storage** (500GB): $12/month
- **Data Transfer**: $20-50/month
- **Secrets Manager**: $1-3/month
- **CloudWatch/Logging**: $10-30/month
- **Total: $930-1,190/month**

**Databricks Alternative (Managed Spark + Delta Lake):**

- **Databricks** (Premium tier, spot instances): $600-1,000/month
- **MSK or Confluent Cloud** (3 brokers): $490+/month
- **S3/GCS Storage**: $12-25/month
- **Total: $1,100-1,500+/month**

**Reality Check:** Kafka + Spark costs 10-50x more than SQS + Lambda for most workloads. Only adopt when you have specific requirements (event replay, complex transformations, >100k events/sec) that justify the cost and operational complexity.

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

**Managed Kafka (MSK, GCP Managed Service for Apache Kafka, Confluent Cloud, Event Hubs):**

- Multi-AZ deployment (3 availability zones minimum)
- Encryption at rest (KMS/CMEK)
- Encryption in transit (TLS 1.2+)
- Private subnets (no public internet access)
- IAM authentication or mTLS (not SASL/PLAIN)
- KRaft metadata mode, never ZooKeeper: Kafka 4.0 (March 2025) removed ZooKeeper entirely, 3.9 is the last release that can migrate a ZooKeeper cluster, and GCP's Managed Service for Apache Kafka is KRaft-only. Start new clusters in KRaft mode: a 4.x version, or `3.9.x.kraft` on MSK.

**MSK Express brokers:** For new MSK clusters, choose Express brokers (`express.m7g.large` and up) over Standard brokers. Storage is fully managed and pay-as-you-go (no EBS sizing, no disk-full pages), each broker delivers up to 3x the throughput of a Standard broker, partition moves and scaling run up to 20x faster, and recovery from a broker failure is about 90% quicker. Clusters are always 3-AZ, have no maintenance windows, and ship with MSK's best-practice guardrails and client throughput quotas. Trade-offs: select instance sizes only, Kafka 3.6/3.8/3.9/4.2 only (KRaft from 3.9), and Kafka Streams and KIP-932 queues are not yet fully supported. Use Standard brokers only when you need a version or feature Express does not offer.

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
- **Security groups** allow only required traffic (Kafka: 9098 IAM or 9094 mTLS, Spark: cluster-internal)

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
  --kafka-version "3.9.x.kraft" \
  --number-of-broker-nodes 3 \
  --broker-node-group-info '{
    "ClientSubnets": ["subnet-abc123", "subnet-def456", "subnet-ghi789"],
    "InstanceType": "kafka.m5.large",
    "SecurityGroups": ["sg-kafka"],
    "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}}
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
try:
    from kafka.net.sasl.oauth import AbstractTokenProvider  # kafka-python 3.x
except ImportError:
    from kafka.sasl.oauth import AbstractTokenProvider  # kafka-python 2.1-2.3
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider


class MSKTokenProvider(AbstractTokenProvider):
    def __init__(self, region):
        self.region = region

    def token(self):
        token, _ = MSKAuthTokenProvider.generate_auth_token(self.region)
        return token


producer = KafkaProducer(
    bootstrap_servers=['b-1.kafka.amazonaws.com:9098'],
    security_protocol='SASL_SSL',
    sasl_mechanism='OAUTHBEARER',
    sasl_oauth_token_provider=MSKTokenProvider('us-east-1'),
    ssl_check_hostname=True
)
```

**Benefits:**

- No credentials to manage (uses IAM roles)
- Short-lived tokens (15-minute expiration)
- Integrated with cloud IAM (fine-grained policies)

**Alternative: mTLS (Mutual TLS)**

For MSK with TLS client authentication (port 9094), or Confluent Cloud Dedicated clusters (and AWS Enterprise/Freight clusters) with your own CA uploaded:

```python
producer = KafkaProducer(
    bootstrap_servers=['b-1.kafka.amazonaws.com:9094'],
    security_protocol='SSL',
    ssl_cafile='/path/to/ca-cert',
    ssl_certfile='/path/to/client-cert.pem',
    ssl_keyfile='/path/to/client-key.pem'
)
```

Event Hubs does not accept client certificates: use Microsoft Entra ID (`SASL_SSL` + `OAUTHBEARER`, port 9093). Confluent Cloud clusters without mTLS use OAuth (`OAUTHBEARER`) or API keys (SASL/PLAIN over TLS).

**Never use SASL/PLAIN** (plaintext passwords) in production.

### Authorization (ACLs)

Kafka ACLs control who can read/write to topics. Implement least-privilege access.

**Kafka ACL Structure:**

```bash
# BOOTSTRAP = broker list for your listener; admin.properties = TLS/SASL client settings
# Grant read access to specific topic for consumer group
kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:spark-consumer \
  --operation Read \
  --topic user-events \
  --group spark-analytics

# Grant write access to producer
kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:api-producer \
  --operation Write \
  --topic user-events

# Default deny: do not add a DENY ACL for User:* - DENY beats every ALLOW
# and locks out all clients. Enable an authorizer (KRaft: authorizer.class.name=
# org.apache.kafka.metadata.authorizer.StandardAuthorizer) and keep
# allow.everyone.if.no.acl.found=false (the Apache default). MSK sets it to true,
# so override it in the MSK cluster configuration; principals without an ALLOW get nothing.
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
        "kafka-cluster:ReadData",
        "kafka-cluster:DescribeGroup",
        "kafka-cluster:AlterGroup"
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

For Spark Structured Streaming, set `.option("groupIdPrefix", "spark-analytics")` (or `kafka.group.id`) and use `group/production-kafka/*/spark-analytics*` so the IAM group resource matches.

**Critical:** Pick the control that matches your auth method. With MSK IAM auth, Kafka ACLs are ignored: the IAM policy above is the only authorization layer, and nothing is allowed until a policy grants it. With mTLS or SASL/SCRAM, MSK sets `allow.everyone.if.no.acl.found=true` by default, so without ACLs any authenticated client can read/write any topic; set it to `false` and use the `kafka-acls` grants above.

### Encryption

**Encryption in Transit (TLS):**

Enable TLS for all client-broker and broker-broker communication.

```bash
# MSK: enforce TLS client-broker (not TLS_PLAINTEXT) and broker-to-broker
# (fragment for aws kafka create-cluster; JSON values cannot contain comments)
--encryption-info '{
  "EncryptionInTransit": {
    "ClientBroker": "TLS",
    "InCluster": true
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

TLS protects the wire and KMS protects the disk; neither protects the payload from anyone holding a topic Read ACL. For PII, PHI and cardholder data, encrypt the sensitive fields in the producer before the record reaches Kafka, using a KMS key that Kafka principals cannot decrypt. The envelope-encryption code and the Spark UDF live in [Field-Level Encryption for PII/PHI](#field-level-encryption-for-piiphi).

### Network Isolation

**Security Groups (AWS) / Firewall Rules (GCP, Azure):**

Restrict Kafka broker access to authorized sources only.

**Example Security Group (AWS MSK):**

| Type     | Protocol | Port | Source           | Purpose                    |
| -------- | -------- | ---- | ---------------- | -------------------------- |
| Inbound  | TCP      | 9098 | sg-spark-cluster | Spark consumers (IAM)      |
| Inbound  | TCP      | 9098 | sg-api-servers   | API producers (IAM)        |
| Inbound  | TCP      | 9098 | sg-bastion       | Admin access (maintenance) |
| Outbound | All      | All  | 0.0.0.0/0        | Allow outbound             |

**Best Practices:**

- Use security group IDs as sources (not CIDR ranges)
- Never allow `0.0.0.0/0` inbound on Kafka ports
- Separate security groups per environment (dev, staging, prod)
- Encrypted client ports only: 9098 (IAM), 9094 (mTLS), 9096 (SASL/SCRAM); never 9092 (plaintext)

**VPC Peering for Cross-VPC Access:**

If Spark and Kafka are in different VPCs:

```bash
# AWS: Create VPC peering connection (CIDRs must not overlap)
aws ec2 create-vpc-peering-connection \
  --vpc-id vpc-kafka \
  --peer-vpc-id vpc-spark

# Accepter VPC owner must accept it
aws ec2 accept-vpc-peering-connection \
  --vpc-peering-connection-id pcx-abc123

# Routes in BOTH VPCs
aws ec2 create-route \
  --route-table-id rtb-spark \
  --destination-cidr-block 10.0.0.0/16 \
  --vpc-peering-connection-id pcx-abc123
aws ec2 create-route \
  --route-table-id rtb-kafka \
  --destination-cidr-block 10.1.0.0/16 \
  --vpc-peering-connection-id pcx-abc123
```

For MSK, prefer multi-VPC private connectivity (PrivateLink): no peering or route tables, overlapping CIDRs allowed, and it supports IAM auth across accounts.

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

# Attach the least-privilege policy from "Spark Job Permissions" (section 9)
aws iam put-role-policy \
  --role-name EMR-Spark-DataAccess \
  --policy-name spark-data-access \
  --policy-document file://spark-data-access.json

# EC2 needs an instance profile; create-role does not make one
aws iam create-instance-profile --instance-profile-name EMR-Spark-DataAccess
aws iam add-role-to-instance-profile \
  --instance-profile-name EMR-Spark-DataAccess \
  --role-name EMR-Spark-DataAccess

# Launch EMR cluster (service role: AmazonEMRServicePolicy_v2 plus iam:PassRole
# on EMR-Spark-DataAccess; tag subnet and security groups as that policy requires)
aws emr create-cluster \
  --name "Spark Processing Cluster" \
  --release-label emr-7.14.0 \
  --applications Name=Spark \
  --service-role EMR-Service-Role \
  --instance-type m5.xlarge \
  --instance-count 3 \
  --tags for-use-with-amazon-emr-managed-policies=true \
  --ec2-attributes '{
    "InstanceProfile": "EMR-Spark-DataAccess",
    "SubnetId": "subnet-private-1"
  }'
```

**Spark Configuration (No Access Keys):**

```python
from pyspark.sql import SparkSession

# Spark automatically uses the instance/pod IAM role - no credentials needed.
# On EMR the native s3:// connector needs no config; for s3a:// the default
# chain already includes IAMInstanceCredentialsProvider. Pin it only if you
# want to forbid env-var/static keys (SDK v1 class names are deprecated):
spark = SparkSession.builder \
    .appName("SecureSparkJob") \
    .config("spark.hadoop.fs.s3a.aws.credentials.provider",
            "org.apache.hadoop.fs.s3a.auth.IAMInstanceCredentialsProvider") \
    .getOrCreate()

# Read from S3 (IAM role provides access)
df = spark.read.parquet("s3a://data-bucket/events/")
```

**GCP Dataproc with a Dedicated VM Service Account:**

```bash
# Required for any custom Dataproc VM service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:spark-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/dataproc.worker"

# Read access to the input bucket only, not every bucket in the project
gcloud storage buckets add-iam-policy-binding gs://input-data-bucket \
  --member="serviceAccount:spark-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

# Launch Dataproc cluster with service account
gcloud dataproc clusters create spark-cluster \
  --region=us-central1 \
  --service-account=spark-sa@PROJECT_ID.iam.gserviceaccount.com
```

**Databricks with Unity Catalog:**

```sql
-- Storage credential (IAM role) registered once in Catalog Explorer; access is granted per path
CREATE EXTERNAL LOCATION events_raw
  URL 's3://data-bucket/events/'
  WITH (STORAGE CREDENTIAL spark_data_role);

GRANT READ FILES ON EXTERNAL LOCATION events_raw TO `spark-jobs`;
```

Databricks documents instance profiles as a legacy data access pattern; keep them only for workspaces not yet on Unity Catalog.

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

### Spark Encryption

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

**Encryption in Transit (RPC and Shuffle):**

`spark.network.crypto.*` encrypts driver-executor RPC and shuffle traffic, but only when RPC authentication (`spark.authenticate`) is also on. Set both at submit time (`--conf`) or in the EMR security configuration.

```python
spark = SparkSession.builder \
    .config("spark.authenticate", "true") \
    .config("spark.network.crypto.enabled", "true") \
    .config("spark.network.crypto.keyLength", "256") \
    .getOrCreate()
```

**Web UI TLS:**

`spark.ssl.*` secures the web UIs, not RPC (Spark 4.x adds a separate `spark.ssl.rpc.enabled`). Load keystore passwords from the secrets manager, never as literals.

```python
tls = get_secret('prod/spark/keystore')  # see Secrets Management Integration

spark = SparkSession.builder \
    .config("spark.ssl.enabled", "true") \
    .config("spark.ssl.protocol", "TLSv1.2") \
    .config("spark.ssl.keyStore", "/path/to/keystore.jks") \
    .config("spark.ssl.keyStorePassword", tls['keystore_password']) \
    .config("spark.ssl.trustStore", "/path/to/truststore.jks") \
    .config("spark.ssl.trustStorePassword", tls['truststore_password']) \
    .getOrCreate()
```

### Network Security

**Security Groups for Spark Clusters:**

| Type     | Protocol | Port          | Source           | Purpose                                      |
| -------- | -------- | ------------- | ---------------- | -------------------------------------------- |
| Inbound  | TCP      | All (0-65535) | sg-spark-cluster | Driver, executors, shuffle (7077 standalone) |
| Inbound  | TCP      | 4040          | sg-bastion       | Spark UI (admin only)                        |
| Inbound  | TCP      | 18080         | sg-bastion       | History server (admin only)                  |
| Outbound | All      | All           | 0.0.0.0/0        | Allow outbound                               |

`spark.driver.port` and `spark.blockManager.port` are random by default: allow all TCP from the cluster's own security group, or pin both ports and open only those. EMR's managed security groups already allow intra-cluster traffic; on Dataproc, add a firewall rule allowing ingress from the cluster's own subnet or network tag.

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

kms_key_id = 'arn:aws:kms:us-east-1:123456789012:key/abc-123'
_client = None
_cmm = None


def _get_client():
    # Created once per executor process, never pickled from the driver.
    # Data key caching keeps this at a handful of KMS calls instead of one per row.
    global _client, _cmm
    if _client is None:
        from aws_encryption_sdk import (
            CachingCryptoMaterialsManager,
            LocalCryptoMaterialsCache,
        )
        _client = EncryptionSDKClient()
        provider = StrictAwsKmsMasterKeyProvider(key_ids=[kms_key_id])
        _cmm = CachingCryptoMaterialsManager(
            master_key_provider=provider,
            cache=LocalCryptoMaterialsCache(capacity=100),
            max_age=300.0,          # seconds
            max_messages_encrypted=10000,
        )
    return _client, _cmm


# Encrypt sensitive field
def encrypt_field(plaintext):
    client, cmm = _get_client()
    ciphertext, _ = client.encrypt(source=plaintext, materials_manager=cmm)
    return ciphertext

# Decrypt when needed (requires KMS permissions)
def decrypt_field(ciphertext):
    client, cmm = _get_client()
    plaintext, _ = client.decrypt(source=ciphertext, materials_manager=cmm)
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
- Supports HIPAA, PCI-DSS and GDPR encryption controls (with KMS key management; none of them mandates field-level encryption specifically)

### Data Masking & Tokenization

Mask sensitive data for non-production environments or analytics.

**Data Masking (Spark SQL):**

```python
from pyspark.sql.functions import concat, lit

# Keyed hash (HMAC) for joinable pseudonyms. A plain SHA-256 of an email is
# reversible by hashing candidate addresses, so the key lives in Secrets Manager
import hmac, hashlib
from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

hmac_key = get_secret('prod/spark/pseudonym-key')['key'].encode()
email_hmac = udf(
    lambda v: hmac.new(hmac_key, v.encode(), hashlib.sha256).hexdigest() if v else None,
    StringType(),
)
df = df.withColumn("email_hash", email_hmac(df.email))

# Mask credit card (show last 4 digits only)
df = df.withColumn("cc_masked",
    concat(lit("****-****-****-"), df.credit_card.substr(-4, 4))
)

# Redact SSN completely
df = df.withColumn("ssn_redacted", lit("***-**-****"))

# Drop the originals, or the "masked" dataset still carries full PAN, SSN and email
df = df.drop("credit_card", "ssn", "email")
```

**Tokenization (Reversible):**

For cases where you need to re-identify data later:

Do not tokenize inside a UDF with an in-memory dict: every executor gets its own copy, tokens differ per partition and per run, and the mapping is lost when the job ends. Keep the vault as a table and join against it.

```python
import hmac, hashlib
from pyspark.sql.functions import col, udf

# Token vault: (ssn, token) in a separate, KMS-encrypted table with its own IAM policy
def read_vault():
    return spark.read.format("jdbc").options(**vault_jdbc_opts).load()  # columns: ssn, token

_token_key = None


@udf("string")
def ssn_token(ssn):
    # Deterministic HMAC token. The key is fetched on the executor, so it never
    # appears in the query plan, the Spark UI or the event logs (a lit() would)
    global _token_key
    if _token_key is None:
        _token_key = get_secret('prod/spark/token-key')['key'].encode()
    return hmac.new(_token_key, ssn.encode(), hashlib.sha256).hexdigest() if ssn else None


# Tokens for SSNs not yet in the vault
new_tokens = (
    df.select("ssn").where(col("ssn").isNotNull()).distinct()
      .join(read_vault(), "ssn", "left_anti")
      .withColumn("token", ssn_token(col("ssn")))
)
new_tokens.write.format("jdbc").options(**vault_jdbc_opts).mode("append").save()

# Re-read the vault (now including the new tokens), swap SSN for its token, drop plaintext
df = df.join(read_vault(), "ssn", "left") \
       .withColumnRenamed("token", "ssn_token") \
       .drop("ssn")
```

Managed alternatives: AWS Glue DataBrew PII transforms (DETERMINISTIC_ENCRYPT), Google Cloud Sensitive Data Protection (formerly Cloud DLP) deterministic encryption, or a vault product (Skyflow, Basis Theory).

**Multi-Tenant Data Isolation:**

For SaaS platforms processing data from multiple customers in shared pipelines, tenant boundaries must be enforced at every stage to prevent cross-tenant data leakage.

**Critical tenant_id requirements:**

- **Kafka topics**: Key messages by tenant_id for per-tenant ordering, but a key is not an access boundary: Kafka ACLs stop at the topic, so any consumer of a shared topic reads every tenant. Use per-tenant topics with prefixed ACLs when tenants need hard isolation
- **Spark processing**: Always include tenant_id in JOIN conditions and GROUP BY clauses
- **Storage**: Write to tenant-specific S3 prefixes or separate tables

```python
from pyspark.sql.functions import col

# VULNERABLE - joins without tenant_id boundary
orders = spark.read.parquet("s3://data/orders/")
customers = spark.read.parquet("s3://data/customers/")
result = orders.join(customers, "customer_id")  # ⚠️ Crosses tenant boundaries!

# SAFE - explicit tenant isolation
result = orders.join(
    customers,
    (orders.customer_id == customers.customer_id) &
    (orders.tenant_id == customers.tenant_id)  # ✓ Enforces tenant boundary
)

# SAFE - filter by tenant before processing
tenant_orders = orders.filter(col("tenant_id") == "customer_123")
tenant_customers = customers.filter(col("tenant_id") == "customer_123")
result = tenant_orders.join(tenant_customers, "customer_id")
```

The vulnerability occurs when joins or aggregations use shared identifiers (user_id, order_id) without including tenant_id in the condition. A misconfigured join can cause customer A's data to appear in customer B's analytics. Always partition by tenant_id and include it in all multi-dataset operations.

**Tenant isolation validation:**

- Schema Registry: Enforce tenant_id as required field in all event schemas
- Spark job testing: Run with interleaved multi-tenant test data, verify results segregate correctly
- Monitoring: Alert on unexpected cross-tenant data patterns (tenant A's job writing to tenant B's S3 prefix)

### Audit Logging

**Kafka Audit Logging:**

Enable broker and authorizer logs. Kafka has no per-message access log, so these record connections and authorization decisions, not every read.

```bash
# MSK: deliver broker and authorizer logs to CloudWatch Logs
aws kafka update-monitoring \
  --cluster-arn arn:aws:kafka:us-east-1:123456789012:cluster/production-kafka/abcd1234-ab12-cd34-ef56-abcdef123456-2 \
  --current-version K1X5R2ABCDEFGH \
  --logging-info '{
    "BrokerLogs": {
      "CloudWatchLogs": {
        "Enabled": true,
        "LogGroup": "/aws/msk/production-kafka"
      }
    },
    "AuthorizerLogs": {
      "CloudWatchLogs": {
        "Enabled": true,
        "LogGroup": "/aws/msk/production-kafka-authorizer"
      }
    }
  }'
```

**What Gets Logged:**

- Broker logs (INFO): client connections, authentication failures, broker errors
- Authorizer logs: authorization decisions, including denied topic and group access
- CloudTrail (IAM access control only): MSK API calls and topic admin actions (`CreateTopic`, `AlterTopic`, `DeleteTopic`, config changes)
- Not logged: individual reads and writes. For PHI access trails, log in the consuming application

**Spark Audit Logging:**

Enable event logging for Spark jobs.

```python
spark = SparkSession.builder \
    .config("spark.eventLog.enabled", "true") \
    .config("spark.eventLog.dir", "s3a://audit-logs/spark-events/") \
    .getOrCreate()
```

Point the History Server at the same path with `spark.history.fs.logDirectory` in its own `spark-defaults.conf` (it is a daemon setting, not a job setting).

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
- Transfer rules (data may leave the EEA only under Chapter V safeguards such as adequacy decisions or SCCs; EU-only regions simplify this but are not mandated)
- Breach notification (to the supervisory authority within 72 hours of becoming aware, Art. 33)
- Security of processing (Art. 32 names encryption and pseudonymisation as appropriate measures; field-level encryption for PII is a strong way to meet it)

**HIPAA (Health Insurance Portability and Accountability Act):**

- PHI encryption (field-level encryption with KMS)
- Access logging (track all PHI access; Kafka does not log individual reads, so log it in the consuming application)
- BAA with cloud provider (Business Associate Agreement)
- 6-year retention for HIPAA Security Rule documentation (policies, risk assessments, audit records; 45 CFR 164.316(b)(2)(i); enforce with S3 lifecycle policies); medical-record retention comes from state law

**PCI-DSS (Payment Card Industry Data Security Standard):**

- Cardholder data encryption (field-level, never store CVV)
- Access restrictions (least privilege ACLs)
- Key rotation at the end of each key's documented cryptoperiod (v4.0.1 Req 3.7.4, per industry guidance such as NIST SP 800-57; no "quarterly" rule). Yearly automatic KMS rotation is a sensible default, not a PCI mandate; AWS KMS rotation is configurable from 90 to 2,560 days, plus on-demand
- Network segmentation (isolate the cardholder data environment: a dedicated Kafka cluster and Spark jobs for payment data; separate topics on a shared cluster put the whole cluster in PCI scope)

**CCPA (California Consumer Privacy Act):**

- Consumer data access (provide data on request)
- Right to deletion (purge from all pipeline stages)
- Opt-out of sale (flag in event streams)

## 8. Schema Management

### Schema Registry Security

Schema Registry stores Avro/Protobuf/JSON schemas for Kafka topics. Secure it to prevent schema poisoning.

**Confluent Schema Registry with Authentication:**

```properties
# Enable authentication (basic auth or mTLS); inject the password at runtime, never commit it
schema.registry.url=https://schema-registry.kafka.svc.cluster.local:8081
basic.auth.credentials.source=USER_INFO
basic.auth.user.info=spark-consumer:<password-from-secrets-manager>
```

**Schema Registry ACLs:**

`kafka-acls` does not cover Schema Registry. On Confluent Platform, subject ACLs come from the Schema Registry Security Plugin (`sr-acl-cli`, a commercial component); Confluent Cloud uses RBAC role bindings.

```bash
# Grant read access to consumers
sr-acl-cli --config schema-registry.properties --add \
  -s user-events-value -p spark-consumer -o SUBJECT_READ

# Grant write access to the CI principal that registers schemas
sr-acl-cli --config schema-registry.properties --add \
  -s user-events-value -p schema-ci -o SUBJECT_WRITE
```

Set `auto.register.schemas=false` on producers so applications can only use schemas that CI registered. AWS Glue Schema Registry is authorized with IAM instead: grant `glue:CreateSchema` and `glue:RegisterSchemaVersion` only to the CI role, `glue:GetSchemaByDefinition` to producers and `glue:GetSchemaVersion` to consumers.

**AWS Glue Schema Registry (used with MSK):**

AWS's official Glue Schema Registry SerDes are Java (plus a C# port); for Python use the community `aws-glue-schema-registry` package (IAM-authenticated through boto3, so no registry password to manage).

```python
import boto3
from kafka import KafkaProducer
try:
    from kafka.net.sasl.oauth import AbstractTokenProvider  # kafka-python 3.x
except ImportError:
    from kafka.sasl.oauth import AbstractTokenProvider  # kafka-python 2.1-2.3
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider
from aws_schema_registry import SchemaRegistryClient
from aws_schema_registry.adapter.kafka import KafkaSerializer
from aws_schema_registry.avro import AvroSchema


class MSKTokenProvider(AbstractTokenProvider):
    def token(self):
        token, _ = MSKAuthTokenProvider.generate_auth_token('us-east-1')
        return token


glue = boto3.client('glue', region_name='us-east-1')
registry_client = SchemaRegistryClient(glue, registry_name='production-schemas')

producer = KafkaProducer(
    bootstrap_servers=['b-1.kafka.amazonaws.com:9098'],
    security_protocol='SASL_SSL',
    sasl_mechanism='OAUTHBEARER',
    sasl_oauth_token_provider=MSKTokenProvider(),
    value_serializer=KafkaSerializer(registry_client),
)

with open('user_event.avsc') as f:
    schema = AvroSchema(f.read())
producer.send('user-events', value=(event, schema))  # value must be a (data, schema) tuple
```

### Schema Validation

Validate data against schemas before producing to Kafka to prevent malformed data.

**Producer-Side Validation:**

```python
from confluent_kafka import Producer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serialization import MessageField, SerializationContext

# Define Avro schema
value_schema_str = '''
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    {"name": "user_id", "type": "string"},
    {"name": "event_type", "type": "string"},
    {"name": "timestamp", "type": "long"}
  ]
}
'''

registry = SchemaRegistryClient({
    'url': 'https://schema-registry:8081',
    'basic.auth.user.info': f"{sr_user}:{sr_password}",  # from Secrets Manager
})
serialize = AvroSerializer(registry, value_schema_str, conf={'auto.register.schemas': False})

producer = Producer({
    'bootstrap.servers': 'kafka:9094',
    'security.protocol': 'SSL',
})

# Serializer validates the record against the schema before it leaves the producer
producer.produce(
    'user-events',
    value=serialize(event, SerializationContext('user-events', MessageField.VALUE)),
)
```

`confluent_kafka.avro.AvroProducer` is deprecated and `SerializingProducer` is experimental; call the serializers directly as above.

**Consumer-Side Validation:**

```python
from pyspark.sql.functions import from_json
from pyspark.sql.types import StructType, StructField, StringType, LongType

expected_schema = StructType([
    StructField("user_id", StringType(), nullable=False),
    StructField("event_type", StringType(), nullable=False),
    StructField("timestamp", LongType(), nullable=False),
])

# from_json silently returns nulls for bad records in its default PERMISSIVE mode;
# FAILFAST makes schema violations fail the batch instead of leaking through
df = spark.read \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9094") \
    .option("kafka.security.protocol", "SSL") \
    .option("subscribe", "user-events") \
    .load() \
    .selectExpr("CAST(value AS STRING) as json") \
    .select(from_json("json", expected_schema, {"mode": "FAILFAST"}).alias("data")) \
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

**Old schema:**

```json
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    { "name": "user_id", "type": "string" },
    { "name": "event_type", "type": "string" }
  ]
}
```

**New schema (backward compatible; the added field is optional with a default):**

```json
{
  "type": "record",
  "name": "UserEvent",
  "fields": [
    { "name": "user_id", "type": "string" },
    { "name": "event_type", "type": "string" },
    { "name": "metadata", "type": ["null", "string"], "default": null }
  ]
}
```

**Set Compatibility Mode:**

```bash
# Set BACKWARD compatibility for all schemas (admin credentials, over TLS)
curl -X PUT https://schema-registry:8081/config \
  -u "$SR_ADMIN_USER:$SR_ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"compatibility": "BACKWARD"}'
```

## 9. Access Control & IAM

### Kafka Topic ACLs

Implement least-privilege access per topic and consumer group. ACL mechanics and the cluster-wide default-deny setting live in [Authorization (ACLs)](#authorization-acls); this section shows the per-application layout.

**Example ACL Structure:**

```bash
# Producers (write-only to specific topics)
kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:api-producer \
  --operation Write \
  --topic user-events

kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:cdc-connector \
  --operation Write \
  --topic database-changes

# Consumers (read-only from specific topics)
kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:spark-analytics \
  --operation Read \
  --topic user-events \
  --group spark-consumer-group

kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config admin.properties \
  --add \
  --allow-principal User:ml-pipeline \
  --operation Read \
  --topic user-events \
  --group ml-feature-extraction
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
      "Action": ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::output-data-bucket"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
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
      "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
      "Resource": [
        "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      ]
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
        "AWS": "arn:aws:iam::SPARK-ACCOUNT-ID:role/EMR-Spark-DataAccess"
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

With the bucket policy above, `EMR-Spark-DataAccess` reads the bucket directly. Grant the same `s3:GetObject`/`s3:ListBucket` on `central-data-lake` in that role's own IAM policy too (cross-account access needs both), and no extra Spark config is needed:

```python
spark = SparkSession.builder.getOrCreate()
df = spark.read.parquet("s3a://central-data-lake/events/")
```

Do not set `fs.s3a.assumed.role.arn` on its own: S3A ignores it unless `fs.s3a.aws.credentials.provider` is `org.apache.hadoop.fs.s3a.auth.AssumedRoleCredentialProvider`, and that provider authenticates to STS with long-lived keys (`fs.s3a.assumed.role.credentials.provider`, default `fs.s3a.access.key`/`secret.key`; Hadoop documents that EC2 instance credentials cannot be used), which is a poor fit for EMR. If the data account must expose a role to assume instead (`DataLakeAccess` trusting `EMR-Spark-DataAccess`, which needs `sts:AssumeRole` on it), use EMRFS role mappings in the EMR security configuration or S3 Access Grants.

### Workload Identity Patterns

**AWS EKS Pod Identity - Kubernetes:**

If running Spark on EKS, bind the driver's service account to an IAM role with EKS Pod Identity (AWS's recommended mechanism; no OIDC provider or ServiceAccount annotation, but the Spark image needs an AWS SDK recent enough to support it). The role trusts `pods.eks.amazonaws.com` with `sts:AssumeRole` and `sts:TagSession`, and the cluster needs the `eks-pod-identity-agent` add-on. Keep IRSA (the `eks.amazonaws.com/role-arn` annotation) for non-EKS clusters.

```bash
aws eks create-pod-identity-association \
  --cluster-name production-eks \
  --namespace default \
  --service-account spark-driver \
  --role-arn arn:aws:iam::123456789012:role/SparkDriverRole
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spark-driver

---
apiVersion: sparkoperator.k8s.io/v1beta2
kind: SparkApplication
metadata:
  name: spark-job
spec:
  type: Python
  mode: cluster
  sparkVersion: "3.5.8"
  image: registry.example.com/spark-job:1.0.0
  mainApplicationFile: local:///opt/app/spark-job.py
  driver:
    serviceAccount: spark-driver
  executor:
    instances: 2
    serviceAccount: spark-driver # executors read S3 too
```

**GCP Workload Identity Federation for GKE:**

```bash
# Bind Kubernetes service account to GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  spark-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT_ID.svc.id.goog[default/spark-driver]"

# Required: annotate the Kubernetes ServiceAccount
kubectl annotate serviceaccount spark-driver \
  --namespace default \
  iam.gke.io/gcp-service-account=spark-sa@PROJECT_ID.iam.gserviceaccount.com
```

Simpler: grant roles directly to the Kubernetes ServiceAccount principal (`principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/default/sa/spark-driver`); no Google service account or annotation needed.

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

- `kafka.server:type=socket-server-metrics,listener=*,networkProcessor=*` attribute `failed-authentication-rate` - Failed authentication attempts
- `kafka.network:type=RequestMetrics,name=RequestsPerSec,request=SaslAuthenticate` - Authentication attempts
- ACL denials have no broker metric: `FailedFetchRequestsPerSec` and `FailedProduceRequestsPerSec` count unexpected broker errors, and authorization failures never reach them. Count denials from the authorizer log (`kafka.authorizer.logger`; MSK authorizer logs) instead (see Security Alerting)

**CloudWatch Alarms (AWS MSK):**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name kafka-high-consumer-lag \
  --alarm-description "Alert when consumer lag exceeds 10000 messages" \
  --metric-name SumOffsetLag \
  --namespace AWS/Kafka \
  --dimensions '[{"Name":"Cluster Name","Value":"production-kafka"},{"Name":"Consumer Group","Value":"ml-feature-extraction"},{"Name":"Topic","Value":"user-events"}]' \
  --statistic Maximum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 10000 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:kafka-alerts
```

Spark Structured Streaming does not commit offsets to Kafka (they live in its checkpoint), so MSK emits no lag metrics for Spark consumers; alert on `inputRate-total` vs `processingRate-total` instead.

### Spark Metrics

Monitor Spark job performance and failures.

**Key Metrics:**

**Job Metrics:**

- `DAGScheduler.stage.failedStages` (driver) - Failed stages (alert on any increase)
- `failedTasks` / `totalTasks` per executor (`/api/v1/applications/{id}/executors`) - Task failures (alert if >5%)

**Resource Metrics:**

- `memoryUsed` / `maxMemory` per executor - Storage memory (alert at >80%)
- `diskUsed` per executor - Disk used for cached blocks

**Streaming Metrics (Structured Streaming, requires `spark.sql.streaming.metricsEnabled=true`):**

- `inputRate-total` - Records ingested per second from Kafka
- `processingRate-total` - Records processed per second (alert if below `inputRate-total`)
- `latency` - Micro-batch duration (alert if > trigger interval)

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

- [Apache Spark - Performance Metrics (Grafana dashboard 7890)](https://grafana.com/grafana/dashboards/7890-spark-performance-metrics/)
- Custom queries for security events (failed auth, unauthorized access)

### Centralized Logging

Forward Kafka and Spark logs to centralized SIEM for security analysis.

**Fluentd Configuration (Kubernetes):**

For self-managed brokers only; MSK delivers broker logs to CloudWatch Logs, S3 or Firehose.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/kafka/server.log,/var/log/kafka/kafka-authorizer.log
      pos_file /var/log/fluentd/kafka.log.pos
      tag kafka.*
      <parse>
        @type regexp
        expression /^\[(?<time>[^\]]+)\] (?<level>\w+) (?<message>.*)$/
        time_format %Y-%m-%d %H:%M:%S,%L
      </parse>
    </source>

    <match kafka.**>
      @type elasticsearch
      host elasticsearch.logging.svc.cluster.local
      port 9200
      scheme https
      ssl_verify true
      user "#{ENV['ES_USER']}"
      password "#{ENV['ES_PASSWORD']}"
      index_name kafka-logs
    </match>
```

**CloudWatch Logs Insights Queries:**

Enable MSK **authorizer logs** (`AuthorizerLogs` in `--logging-info`, alongside `BrokerLogs`) so ACL decisions land in their own log group; broker logs only carry INFO-level application output. Logs Insights is not SQL: comments start with `#`, and fields such as principal/topic must be extracted with `parse`.

```text
# Failed authentication attempts (broker log group)
fields @timestamp, @message
| filter @message like /AuthenticationException|Failed authentication/
| stats count() by bin(5m)

# Unauthorized topic access (authorizer log group)
fields @timestamp, @message
| filter @message like /Denied/
| parse @message /Principal = (?<principal>[^ ]+) is Denied [Oo]peration = (?<operation>[^ ]+) .* on resource = (?<resource>[^ ]+)/
| stats count() by principal, operation, resource
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

MSK publishes no ACL-denial metric, so derive one from the authorizer log group.

```bash
# Turn authorizer "is Denied" log lines into a custom metric
aws logs put-metric-filter \
  --log-group-name /aws/msk/production-kafka-authorizer \
  --filter-name kafka-authz-denied \
  --filter-pattern '"is Denied"' \
  --metric-transformations \
    metricName=KafkaAuthzDenied,metricNamespace=Security/Kafka,metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name kafka-unauthorized-access \
  --alarm-description "Alert on Kafka ACL denials" \
  --metric-name KafkaAuthzDenied \
  --namespace Security/Kafka \
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
- Mitigated by: Kafka ACLs (topic-level permissions), IAM authentication (short-lived tokens), network isolation (private subnets), audit logging (authentication failures and authorizer decisions; Kafka keeps no per-message read log)

**Data Exfiltration via Spark Jobs**

- Attack: Malicious Spark job reads entire dataset and writes to attacker-controlled S3 bucket
- Mitigated by: IAM policies (write access to specific output paths only), an S3 VPC endpoint policy limited to your organization's buckets (`aws:ResourceOrgID`) with no general internet egress from Spark subnets, audit logging (track S3 writes), anomaly detection (alert on unusual data volume)

**Man-in-the-Middle Attacks**

- Attack: Intercepting unencrypted Kafka traffic to read sensitive events
- Mitigated by: TLS encryption in transit (client-broker and broker-broker), mTLS authentication (mutual certificate verification), network isolation (traffic never leaves VPC)

**Schema Poisoning**

- Attack: Modified schema in Schema Registry causes data corruption or application crashes
- Mitigated by: Schema Registry ACLs (read-only for applications, write only for the CI principal), `auto.register.schemas=false` on producers, schema validation (compatibility checks), versioning (rollback to previous schema), audit logging

**Credential Theft from Spark Jobs**

- Attack: Hardcoded access keys in Spark code stolen from GitHub or logs
- Mitigated by: IAM roles (no access keys), Secrets Manager integration (credentials retrieved at runtime), secret scanning (TruffleHog blocks commits), audit logging (detect unusual secret access)

**Kafka Broker Compromise**

- Attack: Attacker gains access to Kafka broker and reads all topic data
- Mitigated by: field-level encryption (sensitive fields stay ciphertext even on the broker), network isolation (brokers not internet-accessible), managed brokers (no shell access on MSK), audit logging. Disk encryption at rest does not help here: a running broker reads its volumes decrypted, and multi-AZ replicas carry the same data

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
- Mitigated by: Field-level encryption (admin cannot decrypt without KMS access), audit logging (CloudTrail records every KMS `Decrypt` and admin API call), separation of duties (different teams for data platform vs security), break-glass procedures (emergency access only)

## 12. References

### Apache Projects

- [Apache Kafka](https://kafka.apache.org/)
- [Apache Spark](https://spark.apache.org/)
- [Confluent Schema Registry](https://docs.confluent.io/platform/current/schema-registry/)
- [Apache Kafka 4.0.0 Release Announcement](https://kafka.apache.org/blog/2025/03/18/apache-kafka-4.0.0-release-announcement/)
- [Apache Kafka 3.9.0 Release Announcement (final ZooKeeper release)](https://kafka.apache.org/blog/2024/11/06/apache-kafka-3.9.0-release-announcement/)

### Managed Services

- [AWS MSK (Managed Streaming for Kafka)](https://aws.amazon.com/msk/)
- [Amazon MSK Pricing](https://aws.amazon.com/msk/pricing/)
- [Amazon MSK Express brokers](https://docs.aws.amazon.com/msk/latest/developerguide/msk-broker-types-express.html)
- [AWS EMR (Elastic MapReduce)](https://aws.amazon.com/emr/)
- [GCP Managed Service for Apache Spark (formerly Dataproc)](https://cloud.google.com/products/managed-service-for-apache-spark)
- [GCP Managed Service for Apache Kafka](https://docs.cloud.google.com/managed-service-for-apache-kafka/docs/overview)
- [Azure HDInsight](https://azure.microsoft.com/en-us/products/hdinsight/)
- [Databricks](https://www.databricks.com/)
- [Confluent Cloud](https://www.confluent.io/confluent-cloud/)

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/)
- [Google Tink](https://github.com/tink-crypto/tink)

### Kafka Security

- [Kafka Security Documentation](https://kafka.apache.org/documentation/#security)
- [Confluent Security Best Practices](https://docs.confluent.io/platform/current/security/index.html)
- [Security in Amazon MSK](https://docs.aws.amazon.com/msk/latest/developerguide/security.html)

### Spark Security

- [Spark Security Documentation](https://spark.apache.org/docs/latest/security.html)
- [Databricks Security Best Practices](https://docs.databricks.com/aws/en/security)

### Standards & Compliance

- [OWASP Top 10](https://owasp.org/projects/top-ten)
- [GDPR](https://gdpr.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [CCPA](https://oag.ca.gov/privacy/ccpa)

### Incident Reports

- [FTC revised complaint: Uber Technologies (2016 breach)](https://www.ftc.gov/system/files/documents/cases/152_3054_c-4662_uber_technologies_revised_complaint.pdf)
