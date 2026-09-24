'use strict';

const { analyzeLambda }               = require('./lambda');
const { analyzeProvisionedConcurrency } = require('./provisionedconcurrency');
const { analyzeDynamoDB }             = require('./dynamodb');
const { analyzeSNS }                  = require('./sns');
const { analyzS3 }                    = require('./s3');
const { analyzeEventBridge }          = require('./eventbridge');
const { analyzeSQS }                  = require('./sqs');
const { analyzeECS }                  = require('./ecs');
const { analyzeNATGateways }          = require('./natgateway');
const { analyzeAPIGateway }           = require('./apigateway');
const { analyzeSecretsManager }       = require('./secretsmanager');
const { analyzeCloudFront }           = require('./cloudfront');
const { analyzeMSK }                  = require('./msk');
const { analyzeSecurityGroups }       = require('./securitygroups');
const { analyzeIAM }                  = require('./iam');
const { computeCostContext }          = require('./localcosts');

// Maps user-supplied aliases → canonical service name (lowercase)
const SERVICE_ALIASES = {
  lambda:               'lambda',
  dynamodb:             'dynamodb',
  dynamo:               'dynamodb',
  sns:                  'sns',
  s3:                   's3',
  eventbridge:          'eventbridge',
  events:               'eventbridge',
  sqs:                  'sqs',
  pc:                   'provisioned concurrency',
  provisioned:          'provisioned concurrency',
  'provisioned-concurrency': 'provisioned concurrency',
  ecs:                  'ecs',
  fargate:              'ecs',
  nat:                  'nat gateway',
  natgateway:           'nat gateway',
  'nat-gateway':        'nat gateway',
  apigw:                'api gateway',
  apigateway:           'api gateway',
  'api-gateway':        'api gateway',
  api:                  'api gateway',
  secrets:              'secrets manager',
  secretsmanager:       'secrets manager',
  'secrets-manager':    'secrets manager',
  cloudfront:           'cloudfront',
  cf:                   'cloudfront',
  msk:                  'msk',
  kafka:                'msk',
  'managed-kafka':      'msk',
  iam:                  'iam',
  sg:                   'security groups',
  'security-groups':    'security groups',
  securitygroups:       'security groups',
};

async function analyzeAWS({ days, region, filter, exclude = [], include = [] }) {
  const endTime   = new Date();
  const startTime = new Date(endTime.getTime() - days * 24 * 60 * 60 * 1000);

  const ctx = { region, startTime, endTime, days, filter };

  // Resolve aliases and build sets of canonical names to skip/keep
  const excluded = new Set(exclude.map(e => SERVICE_ALIASES[e] ?? e));
  const included = new Set(include.map(e => SERVICE_ALIASES[e] ?? e));

  const analysers = [
    { name: 'Lambda',                   fn: analyzeLambda                 },
    { name: 'Provisioned Concurrency',  fn: analyzeProvisionedConcurrency },
    { name: 'DynamoDB',                 fn: analyzeDynamoDB               },
    { name: 'SNS',                      fn: analyzeSNS                    },
    { name: 'S3',                       fn: analyzS3                      },
    { name: 'EventBridge',              fn: analyzeEventBridge            },
    { name: 'SQS',                      fn: analyzeSQS                    },
    { name: 'ECS',                      fn: analyzeECS                    },
    { name: 'NAT Gateway',              fn: analyzeNATGateways            },
    { name: 'API Gateway',              fn: analyzeAPIGateway             },
    { name: 'Secrets Manager',          fn: analyzeSecretsManager         },
    { name: 'CloudFront',               fn: analyzeCloudFront             },
    { name: 'MSK',                      fn: analyzeMSK                    },
    { name: 'Security Groups',          fn: analyzeSecurityGroups         },
    { name: 'IAM',                      fn: analyzeIAM                    },
  ].filter(({ name }) => (included.size === 0 || included.has(name.toLowerCase())) && !excluded.has(name.toLowerCase()));

  const findings = [];
  let resourcesScanned = 0;
  const spendByService = {};

  for (const { name, fn } of analysers) {
    try {
      const result = await fn(ctx);
      findings.push(...result.findings);
      resourcesScanned += result.resourcesScanned;
      if (result.estimatedMonthlyCost != null && result.estimatedMonthlyCost > 0) {
        spendByService[name] = result.estimatedMonthlyCost;
      }
    } catch (err) {
      console.warn(`  [WARN] ${name} analysis failed: ${err.message}`);
    }
  }

  correlatePipelineFindings(findings);

  const costContext = computeCostContext(findings, spendByService);

  return {
    findings,
    summary: { resourcesScanned, costContext },
  };
}

// ─── Pipeline correlation ─────────────────────────────────────────────────────
// When an EventBridge rule AND its likely target Lambda are both silent,
// enrich both findings to surface the relationship. Uses longest-common-prefix
// matching (≥20 chars) which reliably catches CDK/serverless auto-named pairs.

function longestCommonPrefixLength(a, b) {
  const len = Math.min(a.length, b.length);
  let i = 0;
  while (i < len && a[i] === b[i]) i++;
  return i;
}

function correlatePipelineFindings(findings) {
  const lambdaIdle = findings.filter(f => f.service === 'Lambda'      && f.type === 'IDLE');
  const ebIdle     = findings.filter(f => f.service === 'EventBridge' && f.type === 'IDLE');

  const MIN_PREFIX = 20;
  const usedLambdas = new Set();

  for (const ebFinding of ebIdle) {
    const ruleLower = ebFinding.resourceName.toLowerCase();
    let bestLambda = null;
    let bestLen    = MIN_PREFIX - 1;

    for (const lambdaFinding of lambdaIdle) {
      if (usedLambdas.has(lambdaFinding.resourceName)) continue;
      const fnLower = lambdaFinding.resourceName.toLowerCase();
      const prefLen = longestCommonPrefixLength(ruleLower, fnLower);
      if (prefLen > bestLen) {
        bestLen    = prefLen;
        bestLambda = lambdaFinding;
      }
    }

    if (bestLambda) {
      usedLambdas.add(bestLambda.resourceName);
      // Upgrade both to PIPELINE_SILENT and cross-reference
      ebFinding.type           = 'PIPELINE_SILENT';
      ebFinding.details        = `Automated pipeline completely silent — this rule is enabled and scheduled, but zero events are reaching target Lambda "${bestLambda.resourceName}". No alarm has fired. A broken workflow that conventional monitoring did not catch.`;
      ebFinding.correlatedWith = bestLambda.resourceName;

      bestLambda.details      += ` — its upstream EventBridge rule "${ebFinding.resourceName}" is also silent. This is a broken automated pipeline, not just an idle function.`;
      bestLambda.correlatedWith = ebFinding.resourceName;
    }
  }
}

module.exports = { analyzeAWS };
