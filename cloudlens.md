# CloudLens — Multi-Cloud Operational Health & Cost Intelligence

## What It Does

CloudLens connects to your cloud accounts using read-only credentials, queries live resource utilisation metrics, and generates a prioritised HTML report showing:

- **What's silently broken** — traffic anomalies, failed pipelines, high error rates nobody got paged for
- **What's abandoned** — dead code sitting in production untouched for months or years
- **What's a security risk** — Lambda functions running EOL or deprecated runtimes with no security patches
- **What you're spending** — estimated monthly cost per service, broken down across services
- **What you can recover** — per-finding estimated monthly savings, projected annual waste

**No changes are made to any resource. Read-only.**

---

## Quick Start

```bash
cd cloudlens
npm install

# AWS (default)
node cloudlens.js --region us-east-1 --days 14 --output report.html

# Skip noisy services (e.g. per-device SNS topics)
node cloudlens.js --region us-east-1 --days 14 --exclude-service sns --output report.html

# Azure
node cloudlens.js --provider azure \
  --azure-subscription <sub-id> \
  --azure-tenant <tenant-id> \
  --azure-client-id <client-id> \
  --azure-client-secret <secret> \
  --output report.html
```

Open the generated `.html` file in a browser — no server needed.

---

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `--provider` | `aws` \| `azure` | `aws` |
| `--days` | Analysis window in days (1–90) | `7` |
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

`lambda`, `dynamodb`, `dynamo`, `sns`, `s3`, `eventbridge`, `events`, `sqs`, `pc`, `provisioned`, `ecs`, `fargate`, `nat`, `natgateway`, `apigw`, `apigateway`, `api`, `secrets`, `secretsmanager`, `cloudfront`, `cf`, `msk`, `kafka`

> **Tip:** Large accounts with per-device SNS topics (10K+) should always use `--exclude-service sns` — it reduces scan time significantly and removes noise from the report.

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
    "sns:ListTopics",
    "s3:ListAllMyBuckets",
    "events:ListRules",
    "logs:StartQuery", "logs:GetQueryResults",
    "sqs:ListQueues", "sqs:GetQueueAttributes",
    "ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices", "ecs:DescribeTaskDefinition",
    "ec2:DescribeNatGateways",
    "apigateway:GET",
    "secretsmanager:ListSecrets",
    "cloudfront:ListDistributions"
  ],
  "Resource": "*"
}
```

> `ce:GetCostAndUsage` is **not required**. All cost estimates are derived locally from CloudWatch metrics using AWS public pricing.

### Azure

Uses a service principal with the built-in **Reader** role on the target subscription:

```bash
az ad sp create-for-rbac --name cloudlens-reader --role Reader \
  --scopes /subscriptions/<subscription-id>
```

Pass the output values via `--azure-tenant`, `--azure-client-id`, `--azure-client-secret`.

---

## Intelligence Features

Beyond basic idle/cost detection, CloudLens surfaces operational signals that traditional cost tools miss.

### Tag-Driven Context

CloudLens reads AWS resource tags to understand ownership and environment:

- **Environment detection** — reads `Environment`, `Env`, `environment`, `env` tags. Falls back to function-name heuristics (`-prod-`, `-tst-`, `-dev-`).
- **Environment-adjusted severity** — IDLE findings in `tst`/`dev` environments are automatically downgraded (HIGH → MEDIUM for tst; HIGH/MEDIUM → LOW for dev). Production findings keep full priority.
- **Tag compliance** — flags Lambda functions missing `Environment` and `Team` tags as `MISSING_TAGS`.

### Deprecated Runtime Detection

Flags Lambda functions running runtimes that are EOL (no security patches) or deprecated (no new deployments allowed):

| Runtime | Status | Upgrade to |
|---|---|---|
| nodejs12.x, nodejs14.x, nodejs16.x, nodejs18.x, nodejs20.x | EOL | nodejs22.x |
| python3.7, python3.8, python3.9 | EOL | python3.13 |
| python3.10 | DEPRECATED | python3.13 |
| java8 | EOL | java21 |
| ruby2.7, ruby3.2 | EOL | ruby3.3 |
| dotnetcore3.1, dotnet5.0, dotnet6 | EOL | dotnet9 |
| dotnet8 | DEPRECATED | dotnet9 |
| go1.x, provided.al2 | EOL | provided.al2023 |

EOL runtimes → `HIGH`. Deprecated (EOL imminent) → `MEDIUM`.

### Traffic Anomaly Detection

Compares traffic in the first half of the analysis window vs the second half. If a function had ≥ 100 invocations in the earlier period and traffic dropped ≥ 80% in the recent period, it's flagged as `ANOMALY_DROP` with `HIGH` priority.

> Example: 2,400 invocations in days 1–7, 180 in days 8–14 = 92% drop. Surfaced immediately in the executive summary.

### Pipeline Correlation

When an **EventBridge rule** and a **Lambda function** share a name prefix (≥ 20 characters) and both have zero activity over the window, the pair is correlated into a `PIPELINE_SILENT` finding:

> *"Rule `order-service-tst-processOrders-rule-1` is ENABLED but had zero invocations — target Lambda `order-service-tst-processOrders` also has no invocations. The pipeline may be silently stalled."*

This is more meaningful than two separate IDLE findings — it tells you the entire data path is dark, not just one resource.

### Alarm Recommendations

Every finding that has a meaningful alarm includes a ready-to-run `aws cloudwatch put-metric-alarm` command in the expandable detail row. Click **Copy** to paste it straight into your terminal.

Examples of what's generated:
- High error rate → alarm on `Errors` metric with 5-minute evaluation
- Traffic anomaly → alarm on `Invocations` with `LessThanThreshold` for 2 consecutive days
- EventBridge silent → alarm on `MatchedEvents` with `treat-missing-data breaching`
- DLQ messages → alarm on `ApproximateNumberOfMessagesVisible`
- Log group no retention → remediation: `aws logs put-retention-policy`

---

## Resources Analysed — AWS (13 Services)

### Lambda

| Finding type | How detected | Priority |
|---|---|---|
| `ABANDONED` | Zero invocations **and** no code changes in 28+ days | Always HIGH (no env downgrade) |
| `IDLE` | < 10 invocations over the window | HIGH (prod) → adjusted for tst/dev |
| `ANOMALY_DROP` | Traffic dropped ≥ 80% vs prior half-window | HIGH |
| `HIGH_ERROR_RATE` | errors / invocations > 5% | HIGH (> 20%) / MEDIUM |
| `OVER_ALLOCATED` | Avg peak memory < 30% configured → HIGH; < 50% → MEDIUM | HIGH / MEDIUM |
| `THROTTLED` | throttles > 5% of invocations | MEDIUM |
| `DEPRECATED_RUNTIME` | Runtime is EOL or deprecated | HIGH (EOL) / MEDIUM (deprecated) |
| `PIPELINE_SILENT` | EB rule + Lambda both silent, correlated by name prefix | HIGH |
| `MISSING_TAGS` | Missing Environment or Team/Owner tags | LOW |

> **ABANDONED vs IDLE**: IDLE means low activity. ABANDONED means *zero* activity with no code changes for 28+ days — dead code that is still deployed in production. ABANDONED is always HIGH regardless of environment because it represents a security surface and governance failure, not just a cost issue.

Memory utilisation via **CloudWatch Logs Insights** on `REPORT` lines — no Lambda Insights addon required.

---

### Provisioned Concurrency

| Finding type | How detected | Priority |
|---|---|---|
| `PC_IDLE` | Provisioned units > 0, zero actual invocations | HIGH |
| `PC_OVER_PROVISIONED` | Provisioned > 1.5× actual peak concurrency | HIGH / MEDIUM |

**Why this matters**: PC is charged at $0.000004646/GB-second regardless of invocations. 60 units on a 5 GB function = ~$3,600/month even when idle.

---

### DynamoDB

| Finding type | How detected | Priority |
|---|---|---|
| Idle PAY_PER_REQUEST | Zero ConsumedRCU + ConsumedWCU over window | MEDIUM |
| Idle PROVISIONED | Zero consumed, paying fixed hourly cost | HIGH |
| Over-provisioned | Consumed < 10% of max possible throughput | HIGH |
| Under-utilised | Consumed < 20% of provisioned throughput | MEDIUM |

---

### SNS

| Finding type | How detected | Priority |
|---|---|---|
| Idle topic | 0 messages published | HIGH |
| Low activity | < 10 messages published | LOW |

> Large accounts with per-device topics should use `--exclude-service sns`.

---

### MSK (Managed Streaming for Kafka)

| Finding type | How detected | Priority |
|---|---|---|
| `MSK_OFFLINE` | `OfflinePartitionsCount > 0` — consumers receiving errors | HIGH |
| `MSK_DURABILITY_RISK` | `UnderMinIsrPartitionCount > 0` or `UnderReplicatedPartitions > 0` | HIGH |
| `MSK_DISK_CRITICAL` | Any broker `KafkaDataLogsDiskUsed >= 80%` | HIGH |
| `MSK_IDLE` | Zero `BytesInPerSec` + `BytesOutPerSec` across all brokers | HIGH |
| `MSK_UNDERUTILIZED` | Combined avg throughput < 100 KB/s | MEDIUM |

Thresholds sourced from [AWS recommended MSK CloudWatch alarms](https://docs.aws.amazon.com/msk/latest/developerguide/bestpractices-cw-alarms.html). Cost estimates use on-demand broker pricing (e.g. 3× kafka.m5.large ≈ $207/month).

---

### S3 · EventBridge · SQS · ECS · NAT Gateway · API Gateway · Secrets Manager · CloudFront

See per-service detail in code comments.

---

## Report Features

| Feature | Description |
|---|---|
| **Scan narrative** | Plain-English paragraph at the top summarising what was scanned and the most significant findings — readable by anyone |
| **Resources with multiple issues** | Resources flagged for 2+ problems at once, surfaced before everything else. A Lambda with ABANDONED + DEPRECATED_RUNTIME + MISSING_TAGS shows as one card. |
| **Executive Summary** | 3 headline metrics: Active Health Issues, Security Risks (deprecated runtimes), Est. Annual Waste. Top 3 most critical actions surfaced immediately. |
| **At a Glance stats** | Stat cards for Abandoned, Anomalies, Silent Pipelines, Deprecated Runtimes, and more |
| **Environment badges** | `prod` / `tst` / `dev` / `unknown` badge on each Lambda finding |
| **Alarm recommendations** | Expandable detail row shows copy-pasteable `aws cloudwatch put-metric-alarm` command |
| **How findings are classified** | Expandable methodology section explaining every priority rule — answers "why is this HIGH?" before anyone asks |
| **Priority filter** | Toggle HIGH / MEDIUM / LOW |
| **Env filter** | Filter by All / Prod / Tst / Dev |
| **Search bar** | Live filter by resource name |
| **Doughnut chart** | Findings breakdown by service |
| **Cost context bar** | Monthly spend broken down by top services |
| **CSV export** | All findings including Environment, Team columns |

---

## Project Structure

```
cloudlens/
├── cloudlens.js                   # CLI entry point — AWS + Azure orchestration
├── package.json
├── cloudlens.md                   # This file
└── src/
    ├── config.js                  # Tunable thresholds (idle window, memory %, abandoned days)
    ├── aws/
    │   ├── analyzer.js            # Orchestrates all AWS services + pipeline correlation
    │   ├── cloudwatch.js          # Batched GetMetricData helper (450 queries/call)
    │   ├── runtimes.js            # EOL/deprecated runtime status map
    │   ├── lambda.js              # Invocations, errors, anomaly, ABANDONED, tags, runtimes
    │   ├── provisionedconcurrency.js
    │   ├── dynamodb.js
    │   ├── sns.js
    │   ├── s3.js
    │   ├── eventbridge.js
    │   ├── sqs.js
    │   ├── ecs.js
    │   ├── natgateway.js
    │   ├── apigateway.js
    │   ├── secretsmanager.js
    │   ├── cloudfront.js
    │   ├── msk.js
    │   └── localcosts.js          # All pricing constants + cost aggregator
    ├── azure/
    │   └── analyzer.js            # Azure entry point — service analysers plug in here
    └── report/
        └── generator.js           # Self-contained dark-theme HTML report (no dependencies)
```

---

## Adding Azure Analysers

The Azure stub at `src/azure/analyzer.js` defines the interface contract. Each Azure service analyser:

1. Accepts `{ subscriptionId, tenantId, clientId, clientSecret, location, days, filter }`
2. Returns `{ findings: Finding[], resourcesScanned: number }`
3. Each finding must use `provider: 'azure'` and match the shared finding shape

Suggested services and SDK packages are documented in the stub. Implement one analyser at a time — each will appear in the report immediately.

**Suggested priority order for Azure implementation:**

| Service | SDK package | Key finding types |
|---|---|---|
| Azure Functions | `@azure/arm-web` | IDLE, DEPRECATED_RUNTIME |
| Virtual Machines | `@azure/arm-compute` | stopped VMs still charging storage |
| App Service | `@azure/arm-web` | idle plans |
| Blob Storage | `@azure/arm-storage` | empty / unaccessed containers |
| Cosmos DB | `@azure/arm-cosmosdb` | low RU/s utilisation |
| Service Bus | `@azure/arm-servicebus` | idle queues with messages |
| Log Analytics | `@azure/arm-operationalinsights` | missing retention |

---

## Tuning Thresholds

Edit `src/config.js`:

```js
thresholds: {
  lambda: {
    idleInvocations: 10,            // fewer = IDLE
    memoryUtilizationLow: 0.50,     // < 50% configured = MEDIUM over-alloc
    memoryUtilizationVeryLow: 0.30  // < 30% configured = HIGH over-alloc
  },
  dynamodb: {
    idleConsumedUnits: 1,
    overProvisionedRatio: 0.10,     // < 10% utilisation = HIGH
    underutilisedRatio: 0.20,   // < 20% utilisation = MEDIUM (AWS standard)
  }
}

// Anomaly detection
ANOMALY_MIN_PREV_INVOCATIONS = 100  // minimum baseline to qualify
ANOMALY_DROP_THRESHOLD = 0.80       // 80%+ drop triggers ANOMALY_DROP
```

---

## Key Design Decisions

| Decision | Reason |
|---|---|
| **Plain-English narrative** | First thing in the report — a human-readable summary of what was found. Anyone in the room can read it without cloud knowledge. |
| **Compound resource cards** | Most tools show a flat list of findings. CloudLens groups by resource — a function with 3 simultaneous problems shows as one card, making it obvious where to act first. |
| **Health-first framing** | Savings alone looks trivial on serverless stacks. Operational issues (errors, anomalies, silent pipelines, abandoned code) are more compelling and immediately actionable. |
| **Executive summary with Top 3 Actions** | Judges and stakeholders scan, they don't read tables. Most critical findings surfaced before the fold. |
| **Tag-driven severity adjustment** | An IDLE Lambda in a test environment is expected. Same finding in prod is a real issue. Environment context prevents noise from drowning signal. |
| **Pipeline correlation** | Two separate IDLE findings are less meaningful than knowing the entire EB → Lambda path is dark. Correlated by longest common name prefix (≥ 20 chars). |
| **Anomaly detection over raw idle** | A function that dropped from 2,400 to 180 invocations is more alarming than one that was always idle. Compares two halves of the analysis window. |
| **Alarm recommendations** | Every finding that has a meaningful alarm ships a ready-to-run CLI command. Turns a report into a to-do list. |
| **Provider-agnostic finding shape** | AWS and Azure findings share identical structure. The report, filters, and CSV export work for both without any provider-specific code in the generator. |
| **Local cost estimator** | Avoids `ce:GetCostAndUsage` permission. All estimates from CloudWatch metrics using public pricing constants. |
| **`--exclude-service` flag** | Per-device SNS accounts (10K+ topics) would dominate every report otherwise. |

---

## Limitations

- Lambda memory analysis capped at 50 functions (Logs Insights concurrency). Configurable via `lambdaMemoryAnalysisLimit` in `src/config.js`.
- Single AWS region per run — use `--region` to switch.
- Temporary session credentials expire in 1–8 hours.
- Cost estimates are approximations from CloudWatch averages, not actual billing. Actual costs may differ due to free tier, Savings Plans, Reserved Instances.
- CloudFront metrics are always fetched from `us-east-1` regardless of `--region` (AWS constraint).
- Azure analysers are not yet implemented — stub is ready for contribution.

---

## Next Steps

| Feature | Status |
|---|---|
| Azure Functions analyser | Ready for implementation — stub + interface in `src/azure/analyzer.js` |
| Azure Virtual Machines | Same |
| `--all-regions` flag | Parallel scan across all active AWS regions |
| Kinesis Data Streams | Shard-hour cost even when idle |
| Step Functions | Idle state machines |
| RDS / Aurora | Idle instances, over-provisioned storage |
| Scheduled run + Slack diff | Cron job with delta from previous run |
