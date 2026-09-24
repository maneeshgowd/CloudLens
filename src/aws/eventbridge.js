'use strict';

const { EventBridgeClient, ListRulesCommand } = require('@aws-sdk/client-eventbridge');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { thresholds, managedPrefixes } = require('../config');

async function listAllRules(client) {
  const rules = [];
  let nextToken;

  do {
    const res = await client.send(new ListRulesCommand({ NextToken: nextToken, Limit: 100 }));
    rules.push(...(res.Rules || []));
    nextToken = res.NextToken;
  } while (nextToken);

  return rules;
}

async function analyzeEventBridge({ region, startTime, endTime, days, filter }) {
  const ebClient = new EventBridgeClient({ region });
  const cwClient = new CloudWatchClient({ region });

  process.stdout.write('  EventBridge: listing rules... ');
  let rules = await listAllRules(ebClient);
  if (filter) {
    const needle = filter.toLowerCase();
    rules = rules.filter(r => r.Name.toLowerCase().includes(needle));
  }
  rules = rules.filter(r => !managedPrefixes.some(p => r.Name.toLowerCase().startsWith(p)));
  console.log(`${rules.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (rules.length === 0) return { findings: [], resourcesScanned: 0 };

  // Filter to only ENABLED rules — disabled rules won't fire by design
  const enabledRules = rules.filter(r => r.State === 'ENABLED');

  if (enabledRules.length === 0) {
    return { findings: [], resourcesScanned: rules.length };
  }

  // ── CloudWatch: rule invocations ──────────────────────────────────────────
  const querySpecs = enabledRules.map((r, i) => ({
    id: metricId('eb', i, 'inv'),
    namespace: 'AWS/Events',
    metricName: 'Invocations',
    dimensions: [{ Name: 'RuleName', Value: r.Name }],
    stat: 'Sum',
  }));

  process.stdout.write(`  EventBridge: fetching invocation metrics for ${enabledRules.length} enabled rules... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];

  enabledRules.forEach((r, i) => {
    const invocations = cwMetrics[metricId('eb', i, 'inv')]?.sum ?? 0;

    if (invocations < thresholds.eventbridge.idleInvocations) {
      findings.push({
        provider: 'aws',
        service: 'EventBridge',
        resourceName: r.Name,
        resourceId: r.Arn,
        region,
        priority: 'MEDIUM',
        type: 'IDLE',
        details: `Rule is ENABLED but had zero invocations in the last ${days} days`,
        recommendation: `Verify whether this rule's event pattern or schedule is still receiving events. If it's no longer needed, disable or delete it to avoid confusion.`,
        metrics: {
          invocations: 0,
          ruleType: r.ScheduleExpression ? 'Scheduled' : 'Event Pattern',
          schedule: r.ScheduleExpression || r.EventPattern || 'unknown',
        },
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-eb-silent-${r.Name.substring(0, 50)}" \\
  --namespace AWS/Events --metric-name MatchedEvents \\
  --dimensions Name=RuleName,Value="${r.Name}" \\
  --statistic Sum --period 86400 \\
  --threshold 1 --comparison-operator LessThanThreshold \\
  --evaluation-periods 1 --treat-missing-data breaching`,
      });
    }
  });

  return { findings, resourcesScanned: rules.length };
}

module.exports = { analyzeEventBridge };
