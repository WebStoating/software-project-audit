# D08 Infrastructure and configuration — checklist

Questions: see methodology.md §4 D08. This file says how to answer them.

Inputs: inventory `iac_files`, `k8s_files`, `compose_files`, `dockerfiles`; Checkov, Hadolint and Trivy misconfiguration leads. The repository is the only view: never claim what is running in a cloud account. When no IaC/K8s/compose/Docker files exist, most checks are `not_applicable` with the reason "no declared infrastructure in the repository" — except INFRA-01 (still answer what lies outside) and INFRA-10/INFRA-11, which also apply to application code. Python vs JS/TS rarely matters here; the labels note where it does.

### INFRA-01
**How to check (Python):** List Terraform (`*.tf`), CDK (`cdk.json`, Python stacks), Pulumi (`Pulumi.yaml`), CloudFormation/SAM, Helm charts, K8s manifests, compose, `fly.toml`, `render.yaml`, `Procfile`, `app.yaml`. Note services referenced in code (`DATABASE_URL`, S3 buckets, queues) that no file declares.
**How to check (JS/TS):** Same plus `vercel.json`, `netlify.toml`, `serverless.yml`, `wrangler.toml`, CDK TypeScript stacks, `sst.config.ts`.
**Evidence to cite:** Declared resource files and the list of undeclared dependencies (from env reads and SDK calls).
**Scanner leads:** Checkov (its parsed-file list shows what was recognized); Trivy (config `Results[].Target` entries).
**Common false positives:** Resources managed in a separate infra repository; ask the user rather than reporting absence.

### INFRA-02
**How to check (Python):** IAM policies with `"Action": "*"`/`"Resource": "*"`, roles shared across services, `boto3` clients created with static keys, K8s ServiceAccounts with cluster-admin bindings.
**How to check (JS/TS):** Same in CDK TS (`grantReadWrite` on whole buckets, `iam.PolicyStatement` wildcards), serverless function roles.
**Evidence to cite:** Policy file:line and the workload using it.
**Scanner leads:** Checkov `CKV_AWS_*` (IAM wildcard, admin policies), `CKV_K8S_*` (RBAC), `CKV_AZURE_*`, `CKV_GCP_*`.
**Common false positives:** Wildcards scoped by conditions or on a single resource ARN pattern; bootstrap/deploy roles separate from runtime roles.

### INFRA-03
**How to check (Python):** Security groups with `0.0.0.0/0` on non-HTTP ports, load balancers without TLS listeners, `aws_db_instance.publicly_accessible`, K8s `Service` type `LoadBalancer`/`NodePort` for internal services, Ingress without TLS.
**How to check (JS/TS):** Same in CDK/Pulumi TS; edge config (`vercel.json` rewrites to internal hosts).
**Evidence to cite:** Resource file:line and the exposed port/path.
**Scanner leads:** Checkov `CKV_AWS_*` (security groups, TLS policy), `CKV_K8S_*`.
**Common false positives:** Public HTTP(S) on a load balancer is intended; bastion SG open to a known IP range.

### INFRA-04
**How to check (Python):** Storage resources: encryption flags (`storage_encrypted`, bucket SSE, KMS), versioning, backup retention, deletion protection, lifecycle rules.
**How to check (JS/TS):** Same in CDK/Pulumi TS (`removalPolicy: DESTROY` on data stores is a red flag).
**Evidence to cite:** Resource file:line per setting.
**Scanner leads:** Checkov `CKV_AWS_*` (encryption, versioning, backup, deletion protection).
**Common false positives:** Provider defaults that now encrypt by default (S3 SSE-S3 since 2023); dev stacks.

### INFRA-05
**How to check (Python):** Terraform workspaces/`tfvars` per environment, separate state backends, hardcoded account IDs/regions, CDK context per stage.
**How to check (JS/TS):** Same; `sst` stages, `serverless.yml` stages, Vercel projects per environment.
**Evidence to cite:** Parameterization file:line or the hardcoded values.
**Scanner leads:** none — manual.
**Common false positives:** Single-environment projects at early stage (record as `accepted_tradeoff` if stated).

### INFRA-06
**How to check (Python):** Replica counts, autoscaling bounds, single-AZ databases (`multi_az = false`), single Redis node, Lambda reserved concurrency, gunicorn worker counts against container CPU.
**How to check (JS/TS):** Same; Node cluster/PM2 settings vs CPU limits, serverless timeouts and memory.
**Evidence to cite:** Resource file:line and the stated availability requirement (from context or docs).
**Scanner leads:** Checkov (multi-AZ, HA-related checks).
**Common false positives:** No stated availability target: report the SPOF as information, not a defect.

### INFRA-07
**How to check (Python):** Oversized instance classes, NAT gateways per AZ in tiny stacks, provisioned IOPS, always-on GPU instances, log retention "never expire", paid API calls in loops (pairs with PERF-07).
**How to check (JS/TS):** Same; Vercel/Netlify function invocations per request, image optimization on every request, edge middleware on all paths.
**Evidence to cite:** Resource file:line and why the cost is plausible (scale from docs; do not invent prices without a source).
**Scanner leads:** none — manual.
**Common false positives:** Sizes justified by load measurements in docs.

### INFRA-08
**How to check (Python):** Is infrastructure applied by CI (`terraform plan/apply` job) or by hand? Remote state with locking? Drift detection (scheduled plan)? Manual console steps in docs?
**How to check (JS/TS):** Same (`cdk deploy`, `pulumi up`, `sst deploy` in workflows).
**Evidence to cite:** Workflow file:line or doc file:line describing manual steps.
**Scanner leads:** none — manual.
**Common false positives:** Small managed-platform apps where the platform config file is the whole infrastructure.

### INFRA-09
**How to check (Python):** Group Checkov/Hadolint/Trivy leads by resource (the same issue often appears once per tool); for each High/Critical-hinted lead, read the resource and context (provider default, compensating control, dev-only stack) before promoting it.
**How to check (JS/TS):** Same.
**Evidence to cite:** Lead ids with your verdict per lead group (confirmed, mitigated, not applicable).
**Scanner leads:** Checkov, Hadolint, Trivy misconfiguration checks.
**Common false positives:** Checkov checks for features irrelevant to the workload (e.g. S3 access logging on a public static assets bucket), example/test IaC folders.

### INFRA-10
**How to check (Python):** `FileSystemStorage`/`MEDIA_ROOT` uploads on local disk, `SESSION_ENGINE` file/locmem, `LocMemCache`, in-memory rate limiters, APScheduler in web processes, `/tmp` used as shared state.
**How to check (JS/TS):** `multer` disk storage, `express-session` MemoryStore (default), in-memory caches (`node-cache`, `Map` at module scope) assumed shared, `node-cron` in the server; Next.js writing to the filesystem at runtime.
**Evidence to cite:** File:line of the stateful component and the replica count or autoscaling config.
**Scanner leads:** none — manual.
**Common false positives:** Deliberately single-instance deployments documented as such; per-instance caches of immutable data.

### INFRA-11
**How to check (Python):** Committed `.env` (Gitleaks), passwords in compose `environment:`, K8s `Secret` manifests with base64 data in git, Terraform variables with defaults holding secrets, `aws_access_key_id` in config, references to Secrets Manager/SSM/Vault.
**How to check (JS/TS):** Same; `vercel env` usage, secrets in `serverless.yml`.
**Evidence to cite:** File:line and Gitleaks lead id (values redacted).
**Scanner leads:** Gitleaks; Checkov (`CKV_SECRET_*` is skipped by the runner — rely on Gitleaks), `CKV_K8S_*`, `CKV_AWS_*` for plaintext secrets in resources.
**Common false positives:** Local-only compose passwords for dev databases (still note if reused in deploy configs); sealed-secrets/SOPS-encrypted files.

### INFRA-12
**How to check (Python):** K8s `resources.limits`, `livenessProbe`/`readinessProbe`, `securityContext` (`runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`), compose `privileged: true`, `/var/run/docker.sock` mounts, `restart:` policy, Dockerfile `HEALTHCHECK`.
**How to check (JS/TS):** Same.
**Evidence to cite:** Manifest file:line per missing or unsafe setting.
**Scanner leads:** Checkov `CKV_K8S_*`, `CKV_DOCKER_2`, `CKV_DOCKER_3`; Hadolint DL3002; Trivy `DS-0002` (root user) and its Kubernetes checks.
**Common false positives:** CI-only compose files; sidecars that legitimately need extra capabilities (document why).

### INFRA-13
**How to check (Python):** Compose `ports: "5432:5432"`/`"6379:6379"` (binds all interfaces), admin UIs (pgAdmin, Flower, Redis Commander) published, `aws_s3_bucket_public_access_block` missing, Elasticsearch without auth.
**How to check (JS/TS):** Same; Mongo Express, Bull Board mounted without auth in the app.
**Evidence to cite:** File:line of the published port/ACL and whether that file is used beyond local dev.
**Scanner leads:** Checkov `CKV_AWS_*` (public buckets, public DB), `CKV_K8S_*`.
**Common false positives:** Local development compose files binding to `127.0.0.1`; public buckets for static website assets by design.
