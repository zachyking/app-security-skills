---
name: infrastructure-security
description: Cloud and deployment security - network hardening, IAM, storage, secrets, TLS, containers. Use for Terraform, Kubernetes, Docker, AWS/Azure/GCP.
---

# infrastructure-security

Secure cloud infrastructure, deployment configurations, and operational security.

## When to Use

- Writing Infrastructure as Code (Terraform, CloudFormation, Pulumi, etc.)
- Configuring cloud services (AWS, Azure, GCP)
- Setting up Kubernetes or container deployments
- Configuring CI/CD pipelines
- Writing Dockerfiles or docker-compose files
- Setting up networking, firewalls, or security groups
- Configuring logging, monitoring, or alerting

## Instructions

### Network Security

**Restrict network access to minimum required.**

Never expose management ports to the internet:
- SSH (22)
- RDP (3389)
- Database ports (3306, 5432, 1433, 27017, 6379)

```hcl
# INSECURE - Terraform: Open to world
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # DANGEROUS: Open to internet
}

# SECURE - Restricted to specific IPs or VPN
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  description = "SSH from internal network"
}
```

```yaml
# INSECURE - Kubernetes: Service exposed to all
apiVersion: v1
kind: Service
metadata:
  name: database
spec:
  type: LoadBalancer  # Exposed to internet
  ports:
    - port: 5432

# SECURE - Internal ClusterIP only
apiVersion: v1
kind: Service
metadata:
  name: database
spec:
  type: ClusterIP  # Internal only
  ports:
    - port: 5432
```

**Network isolation patterns:**
```hcl
# VPC with public/private subnet separation
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false  # Private subnet
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true  # Only for public-facing resources
}

# Database should be in private subnet only
resource "aws_db_instance" "main" {
  db_subnet_group_name   = aws_db_subnet_group.private.name
  publicly_accessible    = false  # Critical: No public access
}
```

### IAM / Access Control

**Apply least privilege principle to all access.**

```hcl
# INSECURE - Overly permissive IAM policy
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"        # DANGEROUS: Full access
      Resource = "*"
    }]
  })
}

# SECURE - Minimal required permissions
resource "aws_iam_policy" "app_s3_access" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = "arn:aws:s3:::my-app-bucket/*"  # Specific bucket only
    }]
  })
}
```

```yaml
# Kubernetes RBAC - Least privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: app-namespace
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]  # Read only, specific namespace
```

**Service account best practices:**
```hcl
# Use dedicated service accounts, not root/admin
resource "google_service_account" "app" {
  account_id   = "app-service-account"
  display_name = "Application Service Account"
}

# Bind minimal roles
resource "google_project_iam_member" "app_storage" {
  project = var.project
  role    = "roles/storage.objectViewer"  # Read-only
  member  = "serviceAccount:${google_service_account.app.email}"
}
```

### Storage Security

**Storage should be private by default, encrypted at rest.**

```hcl
# INSECURE - Public bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls       = false  # DANGEROUS
  block_public_policy     = false  # DANGEROUS
  ignore_public_acls      = false  # DANGEROUS
  restrict_public_buckets = false  # DANGEROUS
}

# SECURE - Private with encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.id
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"  # Protect against accidental deletion
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}
```

### Secrets Management

**Never store secrets in code, config files, or container images.**

```hcl
# INSECURE - Secret in Terraform
resource "aws_db_instance" "main" {
  password = "MySecretPassword123!"  # DANGEROUS: In state file
}

# SECURE - Use secret manager
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

```yaml
# INSECURE - Kubernetes secret in plain text
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    env:
    - name: DB_PASSWORD
      value: "MySecretPassword"  # DANGEROUS: Visible in manifests

# SECURE - Use external secrets or sealed secrets
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-credentials
  data:
  - secretKey: password
    remoteRef:
      key: /prod/db/password
```

```dockerfile
# INSECURE - Secrets in Docker image
ENV API_KEY=sk-1234567890

# SECURE - Pass at runtime
# In docker-compose or kubernetes, mount secrets
# Never bake secrets into images
```

### Logging & Monitoring

**Enable comprehensive audit logging.**

```hcl
# AWS CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name               = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_log_file_validation   = true  # Tamper detection

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

# Enable VPC Flow Logs
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}
```

```yaml
# Kubernetes audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Metadata
  resources:
  - group: ""
    resources: ["pods", "services"]
```

### TLS/HTTPS Configuration

**Enforce TLS 1.2+ with strong cipher suites.**

```hcl
# AWS ALB - Modern TLS only
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"  # TLS 1.3 preferred
  certificate_arn   = aws_acm_certificate.main.arn
}

# Redirect HTTP to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

```nginx
# Nginx secure TLS configuration
server {
    listen 443 ssl http2;

    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

### Container Security

**Build secure container images.**

```dockerfile
# INSECURE Dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY . /app
USER root  # Running as root
CMD ["python3", "/app/main.py"]

# SECURE Dockerfile
FROM python:3.11-slim-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim-bookworm
# Create non-root user
RUN useradd -r -s /bin/false appuser
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --chown=appuser:appuser . .
USER appuser  # Run as non-root
# No shell access
ENTRYPOINT ["python3"]
CMD ["main.py"]
```

```yaml
# Kubernetes Pod Security
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
```

### CI/CD Security

**Secure your deployment pipeline.**

```yaml
# GitHub Actions - Secure workflow
name: Deploy
on:
  push:
    branches: [main]

permissions:
  contents: read  # Minimum required permissions
  id-token: write # For OIDC auth

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Use OIDC instead of long-lived credentials
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/GitHubActions
          aws-region: us-east-1

      # Pin action versions with SHA
      - uses: actions/setup-node@b39b52d1213e96004bfcb1c61a8a6fa8ab84f3e8
        with:
          node-version: '20'

      # Scan for secrets before deploy
      - name: Scan for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
```

## Security Checklist

### Network
- [ ] No 0.0.0.0/0 rules on sensitive ports
- [ ] Database not publicly accessible
- [ ] Private subnets for backend services
- [ ] Network segmentation implemented

### IAM
- [ ] No wildcard (*) permissions
- [ ] Service accounts with minimal scope
- [ ] No long-lived credentials in code
- [ ] MFA enabled for human access

### Storage
- [ ] Buckets private by default
- [ ] Encryption at rest enabled
- [ ] Access logging enabled
- [ ] Versioning enabled for critical data

### Secrets
- [ ] Using secret manager service
- [ ] No secrets in terraform state
- [ ] No secrets in container images
- [ ] Secrets rotated regularly

### Logging
- [ ] Audit logging enabled
- [ ] Log integrity validation
- [ ] Centralized log collection
- [ ] Alerting configured

### TLS
- [ ] TLS 1.2+ only
- [ ] HTTP redirects to HTTPS
- [ ] HSTS headers set
- [ ] Valid certificates

### Containers
- [ ] Non-root user
- [ ] Read-only filesystem where possible
- [ ] No privileged containers
- [ ] Resource limits set
- [ ] Image scanning in CI/CD

## Anti-Patterns to Flag

1. **Public cloud storage** - S3/GCS buckets without access blocks
2. **Wide-open security groups** - 0.0.0.0/0 on any port
3. **Root containers** - Containers running as root user
4. **Hardcoded credentials** - Secrets in IaC or Dockerfiles
5. **Overprivileged IAM** - Wildcard actions or resources
6. **Missing encryption** - Unencrypted storage or transit
7. **Disabled audit logs** - CloudTrail/audit logs not enabled
8. **Long-lived credentials** - API keys instead of OIDC/IAM roles
9. **Outdated TLS** - TLS 1.0/1.1 still enabled
10. **Public databases** - RDS/Cloud SQL with public access
