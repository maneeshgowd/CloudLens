'use strict';

const {
  DynamoDBClient,
  ListTablesCommand,
  DescribeTableCommand,
} = require('@aws-sdk/client-dynamodb');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { thresholds } = require('../config');

async function listAllTables(client) {
  const tables = [];
  let lastEvaluatedTableName;

  do {
    const res = await client.send(new ListTablesCommand({
      ExclusiveStartTableName: lastEvaluatedTableName,
      Limit: 100,
    }));
    tables.push(...(res.TableNames || []));
    lastEvaluatedTableName = res.LastEvaluatedTableName;
  } while (lastEvaluatedTableName);

  return tables;
}

async function analyzeDynamoDB({ region, startTime, endTime, days, filter }) {
  const ddbClient = new DynamoDBClient({ region });
  const cwClient = new CloudWatchClient({ region });

  process.stdout.write('  DynamoDB: listing tables... ');
  let tableNames = await listAllTables(ddbClient);
  if (filter) {
    const needle = filter.toLowerCase();
    tableNames = tableNames.filter(n => n.toLowerCase().includes(needle));
  }
  console.log(`${tableNames.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (tableNames.length === 0) return { findings: [], resourcesScanned: 0 };

  // ── Describe each table to get billing mode and provisioned throughput ────
  process.stdout.write(`  DynamoDB: describing ${tableNames.length} tables... `);
  const tableDetails = await Promise.all(
    tableNames.map(name =>
      ddbClient.send(new DescribeTableCommand({ TableName: name }))
        .then(r => r.Table)
        .catch(() => null)
    )
  );
  console.log('done');

  // PAY_PER_REQUEST pricing (us-east-1)
  const PAY_READ_PER_MILLION  = 0.25;
  const PAY_WRITE_PER_MILLION = 1.25;

  const validTables = tableDetails.filter(Boolean);
  const provisioned = validTables.filter(t => {
    const billing = t.BillingModeSummary?.BillingMode;
    return !billing || billing === 'PROVISIONED';
  });
  const payPerRequest = validTables.filter(t => {
    return t.BillingModeSummary?.BillingMode === 'PAY_PER_REQUEST';
  });

  // ── CloudWatch: consumed capacity for ALL tables ───────────────────────────
  const allTables = [...provisioned, ...payPerRequest];
  const querySpecs = [];
  allTables.forEach((t, i) => {
    const dims = [{ Name: 'TableName', Value: t.TableName }];
    querySpecs.push(
      { id: metricId('dd', i, 'rcu'), namespace: 'AWS/DynamoDB', metricName: 'ConsumedReadCapacityUnits',  dimensions: dims, stat: 'Sum' },
      { id: metricId('dd', i, 'wcu'), namespace: 'AWS/DynamoDB', metricName: 'ConsumedWriteCapacityUnits', dimensions: dims, stat: 'Sum' }
    );
  });

  process.stdout.write(`  DynamoDB: fetching consumed capacity metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  // ── Generate findings ─────────────────────────────────────────────────────
  const findings = [];
  let totalMonthlyCost = 0;

  // PROVISIONED tables — check for over-provisioning
  provisioned.forEach((t, i) => {
    const provRCU = t.ProvisionedThroughput?.ReadCapacityUnits ?? 0;
    const provWCU = t.ProvisionedThroughput?.WriteCapacityUnits ?? 0;
    const consumedRCU = cwMetrics[metricId('dd', i, 'rcu')]?.sum ?? 0;
    const consumedWCU = cwMetrics[metricId('dd', i, 'wcu')]?.sum ?? 0;

    const windowSeconds  = days * 86400;
    const maxPossibleRCU = provRCU * windowSeconds;
    const maxPossibleWCU = provWCU * windowSeconds;
    const rcuUtil = maxPossibleRCU > 0 ? consumedRCU / maxPossibleRCU : 0;
    const wcuUtil = maxPossibleWCU > 0 ? consumedWCU / maxPossibleWCU : 0;
    const overallUtil = Math.max(rcuUtil, wcuUtil);

    const monthlyCost = parseFloat(estimateDDBMonthlyCost(provRCU, provWCU));
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'aws', service: 'DynamoDB',
      resourceName: t.TableName, resourceId: t.TableArn, region,
      metrics: {
        billingMode: 'PROVISIONED',
        provisionedRCU: provRCU, provisionedWCU: provWCU,
        consumedRCU: Math.round(consumedRCU), consumedWCU: Math.round(consumedWCU),
        rcuUtilisationPct: Math.round(rcuUtil * 100),
        wcuUtilisationPct: Math.round(wcuUtil * 100),
        estimatedMonthlyCostUsd: monthlyCost,
      },
    };

    if (consumedRCU < thresholds.dynamodb.idleConsumedUnits && consumedWCU < thresholds.dynamodb.idleConsumedUnits) {
      findings.push({ ...base, priority: 'HIGH', type: 'IDLE',
        details: `PROVISIONED table — ${provRCU} RCU / ${provWCU} WCU provisioned, zero consumed in last ${days} days ($${monthlyCost}/month wasted)`,
        recommendation: `Delete or switch to PAY_PER_REQUEST. Fixed cost of $${monthlyCost}/month is charged regardless of usage.`,
        estimatedCurrentCost: monthlyCost, estimatedMonthlySavings: monthlyCost,
      });
    } else if (overallUtil < thresholds.dynamodb.overProvisionedRatio) {
      findings.push({ ...base, priority: 'HIGH', type: 'OVER_PROVISIONED',
        details: `Using only ${Math.round(overallUtil * 100)}% of provisioned capacity — paying $${monthlyCost}/month for mostly idle throughput`,
        recommendation: `Reduce provisioned RCU/WCU to match actual usage, or switch to PAY_PER_REQUEST. Actual: RCU ${Math.round(rcuUtil * 100)}% / WCU ${Math.round(wcuUtil * 100)}%.`,
        estimatedCurrentCost: monthlyCost, estimatedMonthlySavings: parseFloat((monthlyCost * (1 - overallUtil)).toFixed(2)),
      });
    } else if (overallUtil < thresholds.dynamodb.underutilisedRatio) {
      findings.push({ ...base, priority: 'MEDIUM', type: 'OVER_PROVISIONED',
        details: `Using ${Math.round(overallUtil * 100)}% of provisioned capacity — $${monthlyCost}/month provisioned`,
        recommendation: `Consider Auto Scaling with a lower minimum or switch to PAY_PER_REQUEST. Current: ${provRCU} RCU / ${provWCU} WCU.`,
        estimatedCurrentCost: monthlyCost, estimatedMonthlySavings: null,
      });
    }
  });

  // PAY_PER_REQUEST tables — calculate actual cost, flag idle ones
  const payOffset = provisioned.length;
  payPerRequest.forEach((t, j) => {
    const i = payOffset + j;
    const consumedRCU = cwMetrics[metricId('dd', i, 'rcu')]?.sum ?? 0;
    const consumedWCU = cwMetrics[metricId('dd', i, 'wcu')]?.sum ?? 0;

    const monthlyRCU  = (consumedRCU / days) * 30;
    const monthlyWCU  = (consumedWCU / days) * 30;
    const monthlyCost = parseFloat(
      ((monthlyRCU / 1e6) * PAY_READ_PER_MILLION + (monthlyWCU / 1e6) * PAY_WRITE_PER_MILLION).toFixed(4)
    );
    totalMonthlyCost += monthlyCost;

    if (consumedRCU < thresholds.dynamodb.idleConsumedUnits && consumedWCU < thresholds.dynamodb.idleConsumedUnits) {
      findings.push({
        provider: 'aws', service: 'DynamoDB',
        resourceName: t.TableName, resourceId: t.TableArn, region,
        priority: 'MEDIUM', type: 'IDLE',
        details: `PAY_PER_REQUEST table — zero reads and writes in last ${days} days`,
        recommendation: `Verify this table is still needed. No cost while idle, but consider deleting if decommissioned to reduce clutter.`,
        metrics: { billingMode: 'PAY_PER_REQUEST', consumedRCU: 0, consumedWCU: 0 },
        estimatedCurrentCost: 0, estimatedMonthlySavings: null,
      });
    }
    // Active PAY_PER_REQUEST tables: cost goes into total but no waste finding needed
  });

  if (payPerRequest.length > 0 && provisioned.length === 0) {
    const payTotalCost = payPerRequest.reduce((sum, t, j) => {
      const i = payOffset + j;
      const rcu = (cwMetrics[metricId('dd', i, 'rcu')]?.sum ?? 0) / days * 30;
      const wcu = (cwMetrics[metricId('dd', i, 'wcu')]?.sum ?? 0) / days * 30;
      return sum + (rcu / 1e6) * PAY_READ_PER_MILLION + (wcu / 1e6) * PAY_WRITE_PER_MILLION;
    }, 0);
    console.log(`  DynamoDB: ${payPerRequest.length} PAY_PER_REQUEST tables — est. $${payTotalCost.toFixed(2)}/month in R/W costs`);
  }

  return { findings, resourcesScanned: tableNames.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

/** Rough estimate of DynamoDB provisioned throughput cost (USD/month, us-east-1 pricing) */
function estimateDDBMonthlyCost(rcu, wcu) {
  // ~$0.00013/RCU/hour, ~$0.00065/WCU/hour
  const rcuMonthly = rcu * 0.00013 * 24 * 30;
  const wcuMonthly = wcu * 0.00065 * 24 * 30;
  return (rcuMonthly + wcuMonthly).toFixed(2);
}

module.exports = { analyzeDynamoDB };
