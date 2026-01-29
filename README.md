# Secure Production Handbook

Battle-tested security guides for production systems. Cloud-agnostic patterns for AWS, GCP, and Azure.

## Guides

- **[API Security Design Guide](api_security_design_guide.md)** - REST APIs, edge protection, authentication, rate limiting
- **[Database Security Guide](database_security_guide.md)** - PostgreSQL, encryption, backups, high availability
- **[Kubernetes Security Guide](kubernetes_security_guide.md)** - Network policies, secrets management, GitOps
- **[Object Storage Security Guide](object_storage_security_guide.md)** - S3/GCS/Blob Storage, access control, compliance
- **[Data Pipeline Security Guide](data_pipeline_security_guide.md)** - Kafka and Spark security
- **[React Frontend Security Guide](react_frontend_security_guide.md)** - Client-side security, authentication patterns
- **[SLSA Build Pipeline Guide](slsa_build_pipeline_guide.md)** - Supply chain security, SLSA Level 3 compliance

## Key Recommendations

**Start simple.** Most teams should use serverless (Lambda/Cloud Run) + managed databases ($30-100/month) instead of Kubernetes ($500-2000+/month).

**Always use managed services for:**

- Databases (RDS, Cloud SQL, Azure Database)
- Kubernetes control plane (EKS, GKE, AKS)
- Secrets (Secrets Manager, Secret Manager, Key Vault)
- Logging (CloudWatch, Cloud Logging, Monitor)

**Only use complex solutions when you have proven requirements:**

- Kubernetes: 50+ microservices, dedicated platform team (3-5+ engineers)
- Kafka + Spark: >100k events/second, event replay required

## Cloud Provider Support

| Service        | AWS             | GCP            | Azure                   |
| -------------- | --------------- | -------------- | ----------------------- |
| Kubernetes     | EKS             | GKE            | AKS                     |
| Databases      | RDS             | Cloud SQL      | Database for PostgreSQL |
| Object Storage | S3              | Cloud Storage  | Blob Storage            |
| Secrets        | Secrets Manager | Secret Manager | Key Vault               |
| Logging        | CloudWatch      | Cloud Logging  | Monitor                 |
