# CloudLens — Multi-Cloud Operational Health & Cost Intelligence

CloudLens connects to your AWS or Azure account using read-only credentials, queries live resource utilisation metrics, and generates a prioritised HTML report showing exactly what is broken, what is a security risk, and what is wasting money — in under two minutes.

**No changes are made to any resource. Entirely read-only.**

---

## Quick Start

```bash
cd cloudlens
npm install

# AWS (default — last 28 days)
node cloudlens.js --region us-east-1 --output report.html

# Skip noisy services (e.g. per-device SNS topics on large accounts)
node cloudlens.js --region us-east-1 --exclude-service sns --output report.html

# Azure
node cloudlens.js --provider azure \
  --azure-subscription <sub-id> \
  --azure-tenant <tenant-id> \
  --azure-client-id <client-id> \
  --azure-client-secret <secret> \
  --output report.html
```

Open the generated `.html` file in any browser — no server, no login, no dependencies.

---

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `--provider` | `aws` \| `azure` | `aws` |
| `--days` | Analysis window in days (1–90) | `28` |
| `--output` | Path for the HTML report | `./cloudlens-report.html` |
| `--filter` | Only include resources whose name contains this string | _(all resources)_ |
| `--exclude-service` | Comma-separated services to skip | _(none)_ |
| **AWS** | | |
| `--region` | AWS region to scan | `us-east-1` |
| **Azure** | | |
| `--azure-subscription` | Azure Subscription ID | _(required for Azure)_ |
| `--azure-tenant` | Azure Tenant ID | |
| `--azure-client-id` | Service principal client ID | |
| `--azure-client-secret` | Service principal client secret | |
| `--azure-location` | Azure location to analyse | `eastus` |

### `--exclude-service` accepted values

`lambda`, `dynamodb`, `dynamo`, `sns`, `s3`, `eventbridge`, `events`, `sqs`, `pc`, `provisioned`, `ecs`, `fargate`, `nat`, `natgateway`, `apigw`, `apigateway`, `api`, `secrets`, `secretsmanager`, `cloudfront`, `cf`, `msk`, `kafka`, `sg`, `securitygroups`, `iam`

> **Tip:** Large accounts with per-device SNS topics (10K+) should always use `--exclude-service sns` — it significantly reduces scan time and removes noise from the report.

---

## Authentication

### AWS

Uses the AWS SDK default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. `~/.aws/credentials` profile (`AWS_PROFILE=my-profile`)
3. IAM role (EC2 / Lambda / ECS instance role)

#### Required IAM Permissions (read-only)

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudwatch:GetMetricData",
    "lambda:ListFunctions", "lambda:ListTags", "lambda:ListProvisionedConcurrencyConfigs",
    "dynamodb:ListTables", "dynamodb:DescribeTable",
    "sns:ListTopics", "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic",
    "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetPublicAccessBlock",
    "events:ListRules", "events:ListTargetsByRule",
    "logs:StartQuery", "logs:GetQueryResults",
    "sqs:ListQueues", "sqs:GetQueueAttributes",
    "ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices", "ecs:DescribeTaskDefinition",
    "ec2:DescribeNatGateways", "ec2:DescribeSecurityGroups",
    "apigateway:GET",
    "secretsmanager:ListSecrets",
    "cloudfront:ListDistributions", "cloudfront:GetDistribution",
    "kafka:ListClustersV2", "kafka:GetBootstrapBrokers",
    "iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"
  ],
  "Resource": "*"
}
```

> `ce:GetCostAndUsage` is **not required**. All cost estimates are derived locally from CloudWatch metrics using AWS public pricing constants.

### Azure

Uses a service principal with the built-in **Reader** role on the target subscription:

```bash
az ad sp create-for-rbac --name cloudlens-reader --role Reader \
  --scopes /subscriptions/<subscription-id>
```

Pass the output values via `--azure-tenant`, `--azure-client-id`, `--azure-client-secret`.

#### App Registrations (optional)

The **App Registrations** scanner reads Entra ID (Azure AD) app registration client secrets and certificate credentials — a tenant-directory resource, not a subscription resource, so the `Reader` role above does not cover it. It requires the Microsoft Graph **`Application.Read.All`** application permission, granted to the same service principal and admin-consented:

```bash
az ad app permission add --id <client-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 9a5d68dd-52b0-4cc2-bd40-abcf44112121=Role

az ad app permission admin-consent --id <client-id>
```

If this permission is not granted, the scanner is skipped like any other failed service — the rest of the scan is unaffected.

---

## What Gets Scanned

### AWS — 15 Services

| Service | Key Finding Types |
|---|---|
| **Lambda** | Abandoned (dead code), idle, high error rate, traffic anomaly, over-allocated memory, throttled, deprecated runtime, silent pipeline |
| **Provisioned Concurrency** | Idle (paying for warm instances never invoked), over-provisioned |
| **DynamoDB** | Idle tables, over-provisioned capacity, under-utilised throughput |
| **S3** | Public access block not configured, empty buckets |
| **Security Groups** | All-traffic open to internet (0.0.0.0/0), sensitive ports exposed (SSH, RDP, MySQL, Redis, etc.) |
| **IAM** | Stale access keys (>90 days unrotated), critical stale keys (>180 days) |
| **Secrets Manager** | Rotation disabled on actively-used secrets, stale/never-accessed secrets |
| **SNS** | Idle topics, low-activity topics |
| **EventBridge** | Silent pipelines (scheduler running, Lambda not receiving), idle rules |
| **SQS** | Dead-letter queue messages accumulating, stale messages |
| **ECS** | Idle services with zero running tasks |
| **NAT Gateway** | Idle gateways with no traffic |
| **API Gateway** | Idle stages (REST v1 and HTTP v2) |
| **CloudFront** | Idle distributions with no requests |
| **MSK** | Offline partitions, durability risk, disk critical, idle/under-utilised clusters |

### Azure — 17 Services

| Service | Key Finding Types |
|---|---|
| **Azure Functions** | Idle, deprecated runtime, high error rate |
| **App Service** | Idle plans, deprecated runtime |
| **Container Apps** | Idle environments |
| **Virtual Machines** | Deallocated (still charging storage), low CPU utilisation |
| **Blob Storage** | Empty containers, no lifecycle policy |
| **Cosmos DB** | Low RU/s utilisation, idle containers |
| **Service Bus** | Dead-letter queue accumulation, idle queues |
| **Event Grid** | Idle topics with no subscriptions |
| **Event Hubs** | Idle namespaces |
| **Key Vault** | Stale/expired secrets and certificates |
| **API Management** | Idle APIs with no traffic |
| **Log Analytics** | Workspaces with no retention policy |
| **NAT Gateway** | Idle gateways |
| **CDN** | Idle endpoints |
| **SQL Database** | Over-provisioned/under-utilised DTU/CPU |
| **SSL Certificates** | Expiring/expired App Service certificates |
| **App Registrations** | Expiring/expired client secrets and certificate credentials |

---

## Intelligence Features

### Cross-Service Pipeline Correlation

When an EventBridge rule and a Lambda function share a name prefix (≥ 20 characters) and both show zero activity over the analysis window, CloudLens correlates them into a single `PIPELINE_SILENT` finding:

> *"Rule `order-service-processOrders-rule` is ENABLED and scheduled but had zero invocations — target Lambda `order-service-processOrders` also shows no activity. The entire pipeline is silently stalled."*

This is invisible when looking at either service individually. It only surfaces when both are analysed together.

### Traffic Anomaly Detection

Compares invocations in the first half of the analysis window vs the second half. A function with ≥ 100 invocations in the earlier period that drops ≥ 80% in the recent period is flagged `ANOMALY_DROP`.

> Example: 2,400 invocations in days 1–14, 180 in days 15–28 = 92% drop → HIGH priority.

### Deprecated Runtime Detection

Flags Lambda functions on runtimes that AWS has stopped patching:

| Runtime | Status | Upgrade to |
|---|---|---|
| nodejs12.x, nodejs14.x, nodejs16.x, nodejs18.x, nodejs20.x | EOL | nodejs22.x |
| python3.7, python3.8, python3.9 | EOL | python3.13 |
| python3.10 | Deprecated | python3.13 |
| java8 | EOL | java21 |
| ruby2.7, ruby3.2 | EOL | ruby3.3 |
| dotnetcore3.1, dotnet5.0, dotnet6 | EOL | dotnet9 |
| go1.x, provided.al2 | EOL | provided.al2023 |

EOL runtimes → `HIGH`. Deprecated → `MEDIUM`.

### Security Scanning

**S3 Public Access** — Checks all four Block Public Access settings per bucket. Missing configuration = HIGH.

**Security Groups** — Flags ingress rules open to `0.0.0.0/0` or `::/0` on sensitive ports (SSH/22, RDP/3389, MySQL/3306, PostgreSQL/5432, MSSQL/1433, MongoDB/27017, Redis/6379, Elasticsearch/9200, 9300). All-traffic open (`-1` protocol) → always HIGH.

**IAM Access Keys** — Lists all IAM users and their active access keys. Keys older than 90 days → MEDIUM. Keys older than 180 days → HIGH.

**Secrets Manager Rotation** — Flags actively-used secrets with rotation disabled. Accessed within 30 days, no rotation → HIGH. Accessed within 90 days → MEDIUM.

---

## Report Features

The generated report is a fully self-contained HTML file — no server, no internet connection, no login required.

- **Summary bar** — resources scanned, total findings, HIGH / MEDIUM / LOW counts, recoverable savings
- **Findings by Service & Severity chart** — stacked horizontal bar showing HIGH / MEDIUM / LOW per service at a glance
- **Narrative bar** — plain-English summary of the most significant findings surfaced before the table
- **Category tabs** — Silent Pipelines, EOL Runtimes, Dead Code, Traffic Anomalies, High Error Rate, Idle Resources, Queue Issues, Security
- **Priority filter** — toggle HIGH / MEDIUM / LOW
- **Live search** — filter findings by resource name in real time
- **Expandable detail rows** — exact metrics, plain-English explanation of the risk, specific recommendation
- **Fix commands** — copy-pasteable remediation commands inside each finding
- **Alarm recommendations** — ready-to-run `aws cloudwatch put-metric-alarm` commands for each applicable finding
- **Fix Script export** — one click bundles all remediation commands into a downloadable bash script, ordered HIGH → LOW
- **CSV export** — all findings with priority, service, resource, type, details, savings, region

---

## Project Structure

```
cloudlens/
├── cloudlens.js                   # CLI entry point — orchestration + report write
├── package.json
├── cloudlens.md                   # This file
└── src/
    ├── config.js                  # Tunable thresholds
    ├── aws/
    │   ├── analyzer.js            # AWS orchestrator + pipeline correlation
    │   ├── cloudwatch.js          # Batched GetMetricData helper
    │   ├── runtimes.js            # EOL/deprecated runtime map
    │   ├── lambda.js
    │   ├── provisionedconcurrency.js
    │   ├── dynamodb.js
    │   ├── sns.js
    │   ├── s3.js                  # Storage metrics + public access block check
    │   ├── eventbridge.js
    │   ├── sqs.js
    │   ├── ecs.js
    │   ├── natgateway.js
    │   ├── apigateway.js
    │   ├── secretsmanager.js      # Rotation check + stale secret detection
    │   ├── cloudfront.js
    │   ├── msk.js
    │   ├── securitygroups.js      # Open ingress to internet detection
    │   ├── iam.js                 # Stale access key detection
    │   └── localcosts.js          # Pricing constants + cost aggregator
    ├── azure/
    │   ├── analyzer.js            # Azure orchestrator
    │   ├── functions.js
    │   ├── appservice.js
    │   ├── containerapps.js
    │   ├── virtualmachines.js
    │   ├── blobstorage.js
    │   ├── cosmosdb.js
    │   ├── servicebus.js
    │   ├── eventgrid.js
    │   ├── eventhubs.js
    │   ├── keyvault.js
    │   ├── apimanagement.js
    │   ├── loganalytics.js
    │   ├── natgateway.js
    │   └── localcosts.js
    └── report/
        └── generator.js           # Self-contained HTML report generator
```

---

## Tuning Thresholds

Edit `src/config.js`:

```js
thresholds: {
  lambda: {
    idleInvocations:          10,    // fewer invocations = IDLE
    memoryUtilizationLow:     0.50,  // < 50% configured = MEDIUM over-allocation
    memoryUtilizationVeryLow: 0.30   // < 30% configured = HIGH over-allocation
  },
  dynamodb: {
    idleConsumedUnits:      1,
    overProvisionedRatio:   0.10,    // < 10% utilisation = HIGH
    underutilisedRatio:     0.20     // < 20% utilisation = MEDIUM
  }
}

// Anomaly detection
ANOMALY_MIN_PREV_INVOCATIONS = 100   // minimum baseline invocations to qualify
ANOMALY_DROP_THRESHOLD       = 0.80  // 80%+ drop triggers ANOMALY_DROP
```

---

## Key Design Decisions

**Cross-service correlation** — The silent pipeline finding is only visible when EventBridge and Lambda are analysed together. Two separate IDLE findings miss the point. A correlated `PIPELINE_SILENT` finding tells you the entire data path is dark.

**Health-first, cost-second** — Savings on serverless stacks often look small in isolation. Operational failures (broken pipelines, high error rates, abandoned code with live permissions) have greater real-world impact and are surfaced first.

**No external dependencies at runtime** — The report is a single self-contained HTML file. No CDN calls, no third-party services, no data leaving the machine. Works in air-gapped environments.

**Local cost estimation** — All cost figures are derived from CloudWatch metrics and public AWS pricing constants. `ce:GetCostAndUsage` is not required and no billing data is accessed.

**Modular scanner architecture** — Each service is an independent file. Adding a new service does not touch anything else. The report generator is provider-agnostic — AWS and Azure findings share an identical shape.

**`--exclude-service` flag** — Accounts with per-device SNS topics (10K+ topics) would dominate every report and take hours to scan. The flag makes large accounts practical.

---

## Limitations

- Lambda memory analysis is capped at 50 functions (CloudWatch Logs Insights concurrency limit). Configurable via `lambdaMemoryAnalysisLimit` in `src/config.js`.
- Single AWS region per run. Use `--region` to target a specific region.
- Temporary session credentials expire — typically 1–8 hours depending on the role configuration.
- Cost estimates are approximations from CloudWatch metric averages, not actual billing. Actual costs may differ due to free tier, Savings Plans, or Reserved Instances.
- CloudFront metrics are always fetched from `us-east-1` regardless of `--region` (AWS platform constraint).

---

## Roadmap

- **Multi-region scan** — single run across all active AWS regions simultaneously
- **Scheduled runs + email digest** — cron-triggered scan with findings emailed to engineering leads, no dashboard login required
- **Historical trending** — track whether findings are increasing or decreasing over time
- **Custom scan profiles** — teams define their own thresholds and scope per run
- **RDS / Aurora** — idle instances, over-provisioned storage
- **Step Functions** — idle state machines
- **Kinesis Data Streams** — shard-hour cost even when idle
