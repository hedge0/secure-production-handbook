# Object Storage Security Guide

**Last Updated:** September 22, 2026

A cloud-agnostic guide for securing production object storage (S3, GCS, Azure Blob Storage) with defense-in-depth security, compliance, and disaster recovery. This guide includes industry best practices and lessons learned from real-world implementations.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [External Services](#external-services)
3. [Access Control](#3-access-control)
   - [Bucket Policies vs IAM Policies](#bucket-policies-vs-iam-policies)
   - [Public Access Blocks (CRITICAL)](#public-access-blocks-critical)
   - [Pre-Signed URLs for Temporary Access](#pre-signed-urls-for-temporary-access)
   - [DNS and Subdomain Takeover Prevention](#dns-and-subdomain-takeover-prevention)
   - [VPC Endpoints for Private Access](#vpc-endpoints-for-private-access)
   - [Cross-Account Access](#cross-account-access)
4. [Encryption](#4-encryption)
   - [Server-Side Encryption](#server-side-encryption)
   - [Enforce Encryption on Upload](#enforce-encryption-on-upload)
   - [Encryption in Transit](#encryption-in-transit)
   - [Key Rotation](#key-rotation)
5. [Versioning & Data Protection](#5-versioning--data-protection)
   - [Versioning](#versioning)
   - [Object Lock (WORM)](#object-lock-worm)
   - [MFA Delete](#mfa-delete)
6. [Lifecycle Management & Compliance](#6-lifecycle-management--compliance)
   - [Storage Classes](#storage-classes)
   - [Lifecycle Policies](#lifecycle-policies)
   - [Compliance Requirements](#compliance-requirements)
7. [Audit Logging & Monitoring](#7-audit-logging--monitoring)
   - [Server Access Logs](#server-access-logs)
   - [Object-Level Logging](#object-level-logging)
   - [Alerting](#alerting)
8. [Attack Scenarios Prevented](#8-attack-scenarios-prevented)
9. [References](#9-references)

## 1. Overview

This guide outlines production-ready patterns for securing object storage (S3, GCS, Azure Blob Storage) for backups, user uploads, compliance data, and data lakes. Misconfigured object storage is one of the most common causes of data breaches in cloud environments.

**Common Use Cases:**

- Database backups and disaster recovery
- User file uploads (documents, images, videos)
- Application logs and audit trails
- Data lakes for analytics
- Static website hosting
- CI/CD artifact storage

**Real-World Breaches:**

- **Capital One (2019)**: An SSRF bug in a misconfigured WAF on EC2 let the attacker pull an over-privileged IAM role's credentials from the instance metadata service (IMDSv1) and copy ~106M credit applications (100M US, 6M Canada) out of 700+ private S3 buckets - a role and IMDS failure, not a public bucket
- **Accenture (2017)**: Four public S3 buckets (137GB in the largest) exposed plaintext passwords and cloud platform keys, including AWS KMS keys
- **Verizon (2017)**: A vendor's (NICE Systems) public S3 bucket exposed 14M customer records, including account PINs

**Core Principles:**

- **Default Deny**: Block public access by default, allow explicitly when needed
- **Least Privilege**: Grant minimum required permissions
- **Defense in Depth**: Multiple layers (IAM, bucket policies, encryption, logging)
- **Encryption Everywhere**: At-rest and in-transit
- **Audit Everything**: Log all access for compliance and threat detection

## 2. Prerequisites

### Required Tools

- **AWS CLI**: For S3 management
- **gcloud CLI**: For GCS management
- **Azure CLI**: For Azure Blob Storage management

### External Services

Cloud-agnostic service options for object storage, key management, and logging.

| Service Category              | AWS                     | GCP                 | Azure                |
| ----------------------------- | ----------------------- | ------------------- | -------------------- |
| **Object Storage** (required) | S3                      | Cloud Storage (GCS) | Blob Storage         |
| **Key Management** (required) | KMS                     | Cloud KMS           | Key Vault            |
| **Logging & SIEM** (required) | CloudTrail, CloudWatch  | Cloud Logging       | Monitor              |
| **Cold Storage** (compliance) | S3 Glacier Deep Archive | Archive Storage     | Archive Blob Storage |

## 3. Access Control

Access control is the most critical aspect of object storage security. Misconfigured permissions are one of the most common causes of cloud data breaches.

### Bucket Policies vs IAM Policies

**Use IAM Policies When:**

- Controlling what actions a user/service can perform across multiple buckets
- Managing permissions for internal users and services
- Example: "This Lambda function can read from any bucket in the account"

**Use Bucket Policies When:**

- Controlling access to a specific bucket from multiple sources
- Granting cross-account access
- Enforcing encryption requirements on uploads
- Example: "Only these accounts can access this specific bucket"

**AWS S3 Example - Bucket Policy (Deny Public Access):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRead",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-private-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalAccount": "123456789012"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

**Best Practice:** Use both IAM policies (for users/services) and bucket policies (for bucket-specific rules) together.

### Public Access Blocks (CRITICAL)

**Always enable public access blocks** to prevent accidental exposure - at the account (or organization) level, not just per bucket (see S3 defaults below).

**AWS S3 - Enable Public Access Block:**

```bash
aws s3api put-public-access-block \
  --bucket my-private-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**GCP Cloud Storage - Public Access Prevention:**

```bash
# --public-access-prevention is the Block Public Access equivalent;
# --uniform-bucket-level-access only disables object ACLs
gcloud storage buckets update gs://my-bucket \
  --public-access-prevention \
  --uniform-bucket-level-access
```

Enforce it for every project with the `storage.publicAccessPrevention` organization policy constraint.

**Azure Blob Storage - Disable Public Access:**

```bash
az storage account update \
  --name mystorageaccount \
  --resource-group myresourcegroup \
  --allow-blob-public-access false
```

**What Public Access Block Prevents:**

- Accidental public ACLs on objects
- Bucket policies that grant public access
- Anonymous public access to buckets

**When to Allow Public Access:**

- Static website hosting - and even then, prefer a private bucket behind CloudFront/CDN with origin access control
- Public datasets (carefully configure with specific public prefixes only)

**S3 Defaults Since 2023 (and Why You Still Set Them):**

- **Encryption**: Every new object gets SSE-S3 since January 5, 2023 - you cannot turn it off
- **Public access and ACLs**: Since April 2023, new buckets ship with all four Block Public Access settings on and ACLs disabled (Object Ownership `BucketOwnerEnforced`)
- **SSE-C**: Since April 2026, blocked on new buckets and on existing buckets in accounts with no SSE-C objects

Defaults are not controls. They only cover buckets created after the change, and anyone with `s3:PutBucketPublicAccessBlock` can switch a bucket's off. Turn Block Public Access on at the account level - S3 applies the most restrictive of account and bucket settings, so one call covers every bucket, old and new. On AWS Organizations, attach an S3 Block Public Access policy at the root or OU instead (since November 2025): new accounts inherit it and it overrides account-level settings.

```bash
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### Pre-Signed URLs for Temporary Access

Use pre-signed URLs to grant temporary access to private objects without changing bucket permissions.

**AWS S3 - Generate Pre-Signed URL (Python):**

```python
import boto3
from botocore.config import Config

# Pin SigV4 and the bucket's region: without an explicit signature_version,
# boto3 still presigns SigV2 URLs in us-east-1 and other legacy regions
s3_client = boto3.client(
    's3',
    region_name='us-east-1',
    config=Config(signature_version='s3v4', s3={'addressing_style': 'virtual'}),
)

# Generate URL valid for 1 hour
url = s3_client.generate_presigned_url(
    'get_object',
    Params={
        'Bucket': 'my-private-bucket',
        'Key': 'user-uploads/document.pdf'
    },
    ExpiresIn=3600  # 1 hour
)
```

**GCP Cloud Storage - Signed URL:**

```python
from datetime import timedelta

import google.auth
from google.auth.transport.requests import Request
from google.cloud import storage

# GCE, GKE and Cloud Run credentials carry no private key: sign through the
# IAM signBlob API instead of shipping a key file (the service account needs
# roles/iam.serviceAccountTokenCreator on itself)
credentials, project = google.auth.default()
credentials.refresh(Request())

client = storage.Client(credentials=credentials, project=project)
blob = client.bucket('my-bucket').blob('document.pdf')

url = blob.generate_signed_url(
    version='v4',
    expiration=timedelta(hours=1),
    method='GET',
    service_account_email=credentials.service_account_email,
    access_token=credentials.token,
)
```

**Use Cases:**

- User file downloads (documents, images)
- File uploads from client applications
- Temporary access for external partners
- Avoiding credentials in client-side code

**Security Notes:**

- Keep expiration times short (minutes to hours, not days); SigV4 caps URLs at 7 days, and a URL signed with role/STS credentials stops working when those credentials expire, whatever `ExpiresIn` says
- URLs are bearer tokens - anyone with the URL has access
- Consider IP restrictions for sensitive data

### DNS and Subdomain Takeover Prevention

When using custom domains (CNAMEs) pointing to object storage, coordinate bucket lifecycle with DNS carefully to prevent subdomain takeover attacks.

**The vulnerability:** If you delete a bucket while DNS still points to it, an attacker can register the same bucket name (now available) and serve malicious content on your domain.

```text
# Vulnerable sequence (S3 routes on the Host header, so the bucket name
# must equal the hostname for a CNAME to work at all):
# 1. You have: assets.example.com → CNAME → assets.example.com.s3.us-east-1.amazonaws.com
# 2. You delete bucket: assets.example.com
# 3. DNS still has the CNAME
# 4. Any AWS account creates a bucket named assets.example.com
# 5. Attacker now serves content on http://assets.example.com
#    (plain HTTP; S3 never holds a certificate for your domain)
```

**Prevention strategies:**

- Before deleting buckets, scan DNS zones for references (automated check in IaC teardown)
- Use CloudFront with Origin Access Control (OAC) instead of direct S3 CNAMEs - point DNS at CloudFront distributions you control
- Maintain bucket name inventory with associated DNS records
- Implement "bucket parking" - keep critical bucket names registered but empty (an empty bucket is free; the first 2,000 buckets per account carry no bucket fee)
- Create new buckets in your S3 account regional namespace (`<prefix>-<account-id>-<region>-an`, March 2026): no other account can ever create those names, even after you delete the bucket. Enforce it with the `s3:x-amz-bucket-namespace` condition key in an SCP

**CloudFront OAC pattern (recommended):**

```text
# Point DNS at CloudFront (you control), not S3 bucket (can be reclaimed)
assets.example.com → CNAME → d123456abcdef.cloudfront.net

# CloudFront origin points to S3
# This removes the DNS dangle, not the origin dangle: if the origin bucket is deleted,
# anyone can recreate it and CloudFront serves their content with your certificate.
# Delete or repoint the distribution in the same change, or use an account regional bucket name.
```

### VPC Endpoints for Private Access

Use VPC endpoints to access object storage privately without traversing the internet.

**AWS S3 - VPC Endpoint:**

```bash
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-12345678 \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids rtb-12345678
```

**Then restrict bucket access to VPC endpoint:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-1a2b3c4d"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/break-glass-admin"
        }
      }
    }
  ]
}
```

This Deny blocks every request that does not arrive through the endpoint, including the console, CI runners outside the VPC and the admin who applied it. Keep a break-glass role exempt (as above) or you will lock yourself out of the bucket.

**GCP Cloud Storage - Private Service Connect:**

```bash
# 1. Reserve the endpoint IP
gcloud compute addresses create my-psc-address \
  --global \
  --purpose=PRIVATE_SERVICE_CONNECT \
  --addresses=10.0.0.5 \
  --network=my-vpc

# 2. Create the endpoint itself (nothing is reachable until this exists)
gcloud compute forwarding-rules create mypscendpoint \
  --global \
  --network=my-vpc \
  --address=my-psc-address \
  --target-google-apis-bundle=all-apis
```

**Azure Blob Storage - Private Endpoint:** Create a private endpoint with target sub-resource `blob` (private DNS zone `privatelink.blob.core.windows.net`). It does not close the public endpoint - also run `az storage account update --public-network-access Disabled`.

**Benefits:**

- Traffic never leaves cloud provider's network
- Reduced data transfer costs
- Better security (no internet exposure)

### Cross-Account Access

Grant access to buckets from other AWS accounts, GCP projects, or Azure subscriptions on the resource side: S3 bucket policies, GCS bucket-level IAM bindings, or Azure RBAC role assignments on the storage account or container. Use specific IAM roles (not account root), grant least privilege, require MFA for sensitive operations, and log all cross-account access.

## 4. Encryption

Encrypt all data at rest and in transit. Most cloud providers encrypt by default, but you should verify and configure appropriately.

### Server-Side Encryption

**Encryption Options:**

**SSE-S3 / SSE-GCS (Managed Keys):**

- Cloud provider manages encryption keys
- Simplest option, enabled by default
- Good for most use cases

**SSE-KMS / CMEK (Customer-Managed Keys):**

- You control key rotation and access policies
- Audit key usage in CloudTrail/Cloud Logging
- Common choice for HIPAA and PCI-DSS audits (key use is logged); neither mandates customer-managed keys

**SSE-C / CSEK (Customer-Provided Keys):**

- You provide encryption key with each request
- You manage key storage and rotation
- Rare use case (extreme control requirements)
- Blocked by default on new S3 buckets since April 2026. Attackers have used it to ransom S3 data (see [Enforce Encryption on Upload](#enforce-encryption-on-upload)), so add `"BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}` to older buckets' encryption config too unless you need it

**AWS S3 - Enable Default Encryption (KMS):**

```bash
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

**When to Use Each:**

- **SSE-S3/SSE-GCS**: Default for most buckets
- **SSE-KMS/CMEK**: Compliance requirements, audit trails, PHI/PII data
- **SSE-C/CSEK**: Extreme security requirements (rare)

### Enforce Encryption on Upload

The classic "deny `PutObject` without an encryption header" policy is obsolete. S3 has encrypted every new object since January 2023, so that policy now only breaks clients that rely on the bucket default. Enforce two things instead:

- **The right key**: Set the bucket default to your KMS key (above), deny uploads that name any other key, and deny uploads that set an encryption header without naming a key (otherwise `aws:kms` alone lands under the AWS managed `aws/s3` key and `AES256` under SSE-S3)
- **No SSE-C unless you chose it on purpose**: In January 2025, attackers with leaked access keys (the Codefinger campaign) used `CopyObject` with SSE-C to re-encrypt victims' objects under keys only they held. S3 blocks SSE-C on new buckets since April 2026, but existing buckets in accounts that hold SSE-C objects still allow it

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOtherKmsKeys",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "false"
        },
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        }
      }
    },
    {
      "Sid": "DenyHeaderWithoutKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "false",
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "true"
        }
      }
    },
    {
      "Sid": "DenySSEC",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption-customer-algorithm": "false"
        }
      }
    }
  ]
}
```

Uploads without encryption headers fall back to the bucket default key; uploads that set a header must name your key, and SSE-C gets `AccessDenied`. Versioning is your recovery path: an SSE-C overwrite leaves the previous version readable.

### Encryption in Transit

Always use HTTPS/TLS for object storage access.

**Enforce HTTPS Only (AWS S3):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

**Best Practices:**

- Always use HTTPS endpoints (`https://s3.amazonaws.com`, not `http://`)
- Enforce TLS 1.2 or higher
- Deny non-HTTPS access via bucket policy

### Key Rotation

Rotate encryption keys at the end of each documented cryptoperiod, and immediately on suspected compromise.

**AWS KMS - Enable Automatic Key Rotation:**

```bash
# Default period is 365 days; --rotation-period-in-days accepts 90-2560
aws kms enable-key-rotation \
  --key-id 12345678-1234-1234-1234-123456789012 \
  --rotation-period-in-days 365

# Rotate immediately after an incident (does not change the schedule)
aws kms rotate-key-on-demand --key-id 12345678-1234-1234-1234-123456789012
```

Rotation replaces only the key material; old material stays available for decryption and the key ARN never changes.

**GCP Cloud KMS - Automatic Rotation:**

```bash
# Rotate every 365 days; omit --next-rotation-time to start one period from now
gcloud kms keys update my-key \
  --location=us \
  --keyring=my-keyring \
  --rotation-period=365d \
  --next-rotation-time=2026-10-01T00:00:00Z

# Manual / incident rotation: create a new primary version
gcloud kms keys versions create \
  --location=us \
  --keyring=my-keyring \
  --key=my-key \
  --primary

# New encryptions use new version, old data still decryptable
```

**Rotation Frequency:**

- **Automated rotation**: Annually (AWS KMS default)
- **Manual rotation**: On demand after security incidents or suspected key compromise
- **Compliance requirements**: PCI DSS v4.0.1 Req 3.7.4 requires rotation at the end of each documented cryptoperiod (NIST SP 800-57); HIPAA sets no interval - document yours (annual KMS rotation is a defensible default)

## 5. Versioning & Data Protection

### Versioning

Enable versioning to protect against accidental deletion and ransomware.

**AWS S3 - Enable Versioning:**

```bash
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled
```

**GCP Cloud Storage - Enable Versioning:**

```bash
gcloud storage buckets update gs://my-bucket --versioning
```

**How Versioning Works:**

- Every object modification creates a new version
- Simple deletes create a delete marker (object recoverable)
- Old versions remain until deleted by version ID or expired by a lifecycle rule; attackers with `s3:DeleteObjectVersion` or `s3:PutLifecycleConfiguration` can do both (Codefinger set 7-day expirations), so deny them to workload roles or add Object Lock
- Cost: You pay for storage of all versions

**Use Cases:**

- Accidental deletion recovery
- Ransomware protection (restore previous versions)
- Compliance (maintain history of changes)

### Object Lock (WORM)

Object Lock provides Write-Once-Read-Many (WORM) protection for compliance.

**AWS S3 - Enable Object Lock:**

```bash
# New bucket: enable at creation (also turns on versioning)
aws s3api create-bucket \
  --bucket my-compliance-bucket \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Existing bucket: enable versioning first, then the
# put-object-lock-configuration call below turns Object Lock on.
# Once enabled it cannot be disabled and versioning cannot be suspended.

# Set default retention
aws s3api put-object-lock-configuration \
  --bucket my-compliance-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'
```

**Retention Modes:**

**COMPLIANCE Mode:**

- No one can delete or modify (not even root user)
- Cannot shorten retention period
- Use for: Regulatory WORM requirements (SEC 17a-4, FINRA, CFTC)

**GOVERNANCE Mode:**

- Users with special permissions can delete
- Retention period can be shortened
- Use for: Internal policies, testing

**Legal Hold:**

- Indefinite retention until removed
- Independent of retention period
- Use for: Litigation, investigations

**Use Cases:**

- Financial records (7-year retention)
- Healthcare records (state retention laws; HIPAA documentation 6 years)
- Audit logs (SOC 2, PCI-DSS)

**Azure Blob Storage:** Immutable storage gives the same WORM model - time-based retention policies and legal holds, per container or (with versioning) per blob version. Unlocked policies are for testing only; lock it (`az storage container immutability-policy lock`) for SEC 17a-4(f)-grade retention, after which it can be extended (up to five times) but never shortened or deleted.

### MFA Delete

Require multi-factor authentication to delete objects or disable versioning.

**AWS S3 - Enable MFA Delete:**

```bash
# Must be done by root account with MFA
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789012:mfa/root-account-mfa-device 123456"
```

**Benefits:**

- Prevents accidental deletion by compromised credentials
- Additional layer of protection for critical data
- Compliance requirement for some regulations

**Limitation:** S3 doesn't support lifecycle configurations on buckets with MFA delete enabled. For buckets that need the lifecycle rules in section 6, use Object Lock instead.

## 6. Lifecycle Management & Compliance

### Storage Classes

Different storage classes optimize cost for different access patterns.

**AWS S3 Storage Classes:**

| Class                         | Access Pattern             | Cost (relative) | Retrieval Time |
| ----------------------------- | -------------------------- | --------------- | -------------- |
| S3 Standard                   | Frequent access            | High            | Instant        |
| S3 Intelligent-Tiering        | Unknown/changing access    | Auto-optimized  | Instant        |
| S3 Standard-IA                | Infrequent access          | Medium          | Instant        |
| S3 Glacier Instant Retrieval  | Archive, instant retrieval | Low             | Instant        |
| S3 Glacier Flexible Retrieval | Archive, rare retrieval    | Very Low        | Minutes-hours  |
| S3 Glacier Deep Archive       | Long-term archive          | Lowest          | 12-48 hours    |

**GCP Cloud Storage Classes:**

| Class    | Access Pattern              | Cost (relative) |
| -------- | --------------------------- | --------------- |
| Standard | Frequent access             | High            |
| Nearline | Infrequent (once/month)     | Medium          |
| Coldline | Rare (once/quarter)         | Low             |
| Archive  | Long-term archive (once/yr) | Lowest          |

### Lifecycle Policies

Automatically transition objects to cheaper storage classes over time.

**AWS S3 - Lifecycle Policy:**

```json
{
  "Rules": [
    {
      "Id": "Archive old logs",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "logs/"
      },
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER_IR"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
```

**GCP Cloud Storage - Lifecycle Configuration:**

```json
{
  "lifecycle": {
    "rule": [
      {
        "action": {
          "type": "SetStorageClass",
          "storageClass": "NEARLINE"
        },
        "condition": {
          "age": 30,
          "matchesPrefix": ["logs/"]
        }
      },
      {
        "action": {
          "type": "Delete"
        },
        "condition": {
          "age": 2555,
          "matchesPrefix": ["logs/"]
        }
      }
    ]
  }
}
```

**Common Patterns:**

- **Active data**: Standard (0-30 days)
- **Recent backups**: Standard-IA (30-90 days)
- **Old backups**: Glacier (90-365 days)
- **Compliance archives**: Deep Archive (1+ years)
- **Log retention**: Transition to archive, delete after 7 years
- **Small objects**: Since September 2024, lifecycle rules skip transitions for objects under 128 KB unless the rule sets its own `ObjectSizeGreaterThan` filter, so small log files stay in Standard (usually cheaper anyway once per-object transition fees are counted)

### Compliance Requirements

**GDPR (General Data Protection Regulation):**

- Right to deletion (delete user data on request)
- Transfers outside the EEA need an adequacy decision or safeguards (Chapter V); pinning regions is the simple way to comply, not a GDPR mandate
- Breach notification (to the supervisory authority within 72 hours of becoming aware, Art. 33)
- Use versioning + Object Lock for audit trails, but keep personal data out of locked buckets unless a legal retention duty applies (Art. 17(3)(b)); erasure must delete every object version, not just add a delete marker

**HIPAA (Health Insurance Portability and Accountability Act):**

- Encrypt all PHI (addressable under the current Security Rule, required under the proposed 2025 update; SSE-KMS/CMEK is the usual choice for its key-access audit trail)
- Business Associate Agreement (BAA) with cloud provider
- Access logging and audit trails
- 6-year retention for Security Rule documentation, incl. audit records (45 CFR 164.316(b)(2)(i)); medical-record retention is set by state law

**PCI-DSS (Payment Card Industry Data Security Standard):**

- Encrypt cardholder data (SSE-KMS/CMEK)
- Restrict access (principle of least privilege)
- Log all access to cardholder data
- Key rotation at the end of each documented cryptoperiod (Req 3.7.4)

**SOC 2 (System and Organization Controls):**

- Access controls and logging
- Encryption at rest and in transit
- Regular access reviews
- Incident response procedures

## 7. Audit Logging & Monitoring

### Server Access Logs

Enable access logs to track requests to your buckets. Delivery is best-effort, so use CloudTrail data events when you need a complete audit record. The destination bucket needs a bucket policy granting `s3:PutObject` to `logging.s3.amazonaws.com` (ACLs are disabled by default, and only the console adds the policy for you), must use SSE-S3 rather than SSE-KMS default encryption, and can't have Object Lock enabled.

**AWS S3 - Enable Server Access Logging:**

```bash
aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-logs-bucket",
      "TargetPrefix": "s3-access-logs/"
    }
  }'
```

**GCP Cloud Storage - Enable Usage Logs:**

Google recommends Cloud Audit Logs for most cases; enable Data Access audit logs (`DATA_READ`, `DATA_WRITE`) for Cloud Storage, since they're off by default. Usage logs also need `roles/storage.objectCreator` on the log bucket for `cloud-storage-analytics@google.com`:

```bash
gcloud storage buckets update gs://my-bucket \
  --log-bucket=gs://my-logs-bucket \
  --log-object-prefix=gcs-logs/
```

**What Gets Logged:**

- Requester account/IP address
- Bucket and object key
- Request type (GET, PUT, DELETE)
- Response status code
- Error codes
- Bytes sent
- Request/response time

### Object-Level Logging

Enable CloudTrail (AWS) or Cloud Logging (GCP) for detailed API-level logging.

**AWS S3 - CloudTrail Data Events:**

```bash
aws cloudtrail put-event-selectors \
  --trail-name my-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::my-bucket/"]
    }]
  }]'
```

**What CloudTrail Logs:**

- GetObject, PutObject, DeleteObject operations
- IAM principal (who made the request)
- Source IP address
- Request parameters
- Response elements

**Cost Note:** Object-level logging can be expensive for high-traffic buckets. Consider enabling only for sensitive buckets.

### Alerting

Set up alerts for suspicious activity.

**AWS EventBridge Rule - Detect Public Access Changes:**

There is no `AWS/S3` CloudWatch metric for Block Public Access, so a metric alarm never fires. Alert on the CloudTrail management events that change it instead:

```bash
aws events put-rule \
  --name s3-public-access-config-change \
  --event-pattern '{
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["s3.amazonaws.com"],
      "eventName": [
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock",
        "PutBucketPolicy", "PutBucketAcl"
      ]
    }
  }'

aws events put-targets \
  --rule s3-public-access-config-change \
  --targets "Id=security-alerts,Arn=arn:aws:sns:us-east-1:123456789012:security-alerts"
```

EventBridge only sees these events while a CloudTrail trail is logging, and the SNS topic policy must allow `events.amazonaws.com` to publish. For continuous drift detection, add the AWS Config managed rules `s3-bucket-level-public-access-prohibited` and `s3-account-level-public-access-blocks-periodic`, and use IAM Access Analyzer for external-access findings.

**Key Alerts to Configure:**

- Bucket policy changes (especially public access grants)
- Object deletions in versioned buckets
- Failed authentication attempts
- Access from unexpected IP addresses/regions
- Large data downloads (potential exfiltration)

**Data Exfiltration Detection:**

Large data downloads often indicate compromised credentials or insider threats. With S3 data events enabled (see [Object-Level Logging](#object-level-logging)), CloudTrail records every object-level call with its transfer size (`additionalEventData.bytesTransferredOut`); buckets without data events are invisible here. The queries below are CloudWatch Logs Insights, so the trail must also deliver to a CloudWatch Logs log group.

**Pattern 1: Volume-based anomalies**

Alert when a single IAM principal downloads significantly more data than their baseline:

```text
# CloudWatch Logs Insights: principals that pulled > 10 GB in the selected time range
filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
| stats sum(additionalEventData.bytesTransferredOut) as totalBytes
    by userIdentity.principalId, requestParameters.bucketName
| filter totalBytes > 10737418240
| sort totalBytes desc
```

Establish baseline download volumes per user/service (e.g., analytics job downloads 5GB daily). Alert when downloads exceed 3-5x baseline within 24 hours, indicating potential data exfiltration or compromised service account.

**Pattern 2: Access pattern anomalies**

```text
# GetObject outside 09:00-17:59 UTC, or from outside your known ranges
# (replace 203.0.113.0/24 with your office/VPN/NAT CIDR)
fields @timestamp, userIdentity.principalId, sourceIPAddress,
       requestParameters.bucketName, requestParameters.key,
       toInt(formatDate(@timestamp, "%H", "UTC")) as hourUtc
| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
| filter hourUtc < 9 or hourUtc > 17
    or not isIpInSubnet(sourceIPAddress, "203.0.113.0/24")
```

Normal users access objects during business hours from expected locations. Late-night bulk downloads from new IPs/regions suggest compromised credentials being exploited by attackers.

**Pattern 3: Sequential enumeration**

Attackers often enumerate bucket contents before bulk download:

```text
# One principal lists a bucket and pulls 100+ objects in the same hour.
# CloudTrail has no "ListBucket" event (that is the IAM action name).
filter eventSource = "s3.amazonaws.com"
  and eventName in ["ListObjects", "ListObjectsV2", "ListObjectVersions", "GetObject"]
| fields startsWith(eventName, "List") as isList, if(eventName = "GetObject", 1, 0) as isGet
| stats sum(isList) as lists, sum(isGet) as gets by userIdentity.principalId, bin(1h)
| filter lists > 0 and gets >= 100
```

Legitimate users access specific known objects. Attackers list bucket contents (`ListObjects`/`ListObjectsV2` in CloudTrail), identify sensitive files, then systematically download hundreds of objects.

**Automated Response:**

When exfiltration detected:

1. **Immediate**: Suspend IAM credentials, revoke active sessions (STS)
2. **Investigate**: Analyze CloudTrail for what was accessed, from where, when
3. **Contain**: Add an explicit bucket-policy Deny for everyone except the incident response role (MFA Delete guards against deletion, not reads)
4. **Notify**: Security team, compliance (GDPR 72-hour breach notification if PII accessed)

## 8. Attack Scenarios Prevented

This guide's security controls prevent real-world object storage attacks commonly seen in production environments.

**Public Bucket Exposure**

- Attack: Misconfigured bucket permissions expose sensitive data publicly
- Mitigated by: Public access blocks enabled by default, bucket policies with explicit deny, regular access reviews, CloudTrail logging

**Ransomware / Malicious Deletion**

- Attack: Attacker deletes or encrypts objects, demands ransom for recovery
- Mitigated by: Versioning enabled (recover previous versions), Object Lock (WORM prevents deletion), MFA delete (requires 2FA), cross-region replication

**Data Exfiltration**

- Attack: Compromised credentials used to download large amounts of sensitive data
- Mitigated by: VPC endpoints (private network access), CloudTrail logging (detect unusual downloads), alerts on large data transfers, least privilege IAM policies

**Subdomain Takeover via Object Storage**

- Attack: Attacker claims abandoned bucket name, serves malicious content on your domain
- Mitigated by: Remove DNS records and CloudFront origins before deleting the buckets they point to, create new buckets in the account regional namespace (names other accounts can't claim), maintain bucket name inventory

**Credential Leakage**

- Attack: Access keys leaked in GitHub, logs, or client-side code
- Mitigated by: Use IAM roles instead of access keys, pre-signed URLs for temporary access, secret scanning (TruffleHog), rotate any unavoidable static keys on suspected compromise or staff departure and otherwise on a documented risk-based schedule

## 9. References

### Object Storage Services

- [AWS S3](https://aws.amazon.com/s3/)
- [GCP Cloud Storage](https://cloud.google.com/storage)
- [Azure Blob Storage](https://azure.microsoft.com/en-us/products/storage/blobs/)
- [S3 Block Public Access and ACLs Disabled by Default (April 2023)](https://aws.amazon.com/about-aws/whats-new/2022/12/amazon-s3-automatically-enable-block-public-access-disable-access-control-lists-buckets-april-2023/)
- [S3 Default Encryption FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html)
- [S3 Block Public Access (Account and Organization Level)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure Storage Private Endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints)
- [Azure Immutable Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview)

### Key Management

- [AWS KMS](https://aws.amazon.com/kms/)
- [GCP Cloud KMS](https://cloud.google.com/security/products/security-key-management)
- [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/)
- [S3: Requiring SSE-KMS with a Bucket Policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#require-sse-kms)
- [S3: Blocking SSE-C for a Bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
- [AWS: Preventing Unintended Encryption of S3 Objects](https://aws.amazon.com/blogs/security/preventing-unintended-encryption-of-amazon-s3-objects/)

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [IAM Access Analyzer](https://aws.amazon.com/iam/access-analyzer/)
- [GCP Asset Inventory](https://cloud.google.com/asset-inventory)

### Compliance & Standards

- [GDPR](https://gdpr.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2/)

### Incident Reports

- [Capital One Hack: What We Can Learn (KrebsOnSecurity)](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/)
- [Accenture Cloud Leak (UpGuard)](https://www.upguard.com/breaches/cloud-leak-accenture)
- [Verizon Cloud Leak (UpGuard)](https://www.upguard.com/breaches/verizon-cloud-leak)
- [Codefinger: Ransomware Encrypting S3 Buckets with SSE-C (Halcyon)](https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c)
- [Verizon Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/)
