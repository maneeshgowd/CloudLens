'use strict';

const { CloudWatchLogsClient, DescribeLogGroupsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { PRICING } = require('./localcosts');

async function listLogGroups(client, filter) {
  const groups = [];
  let nextToken;

  do {
    const params = { limit: 50 };
    if (nextToken) params.nextToken = nextToken;
    // logGroupNamePattern does server-side case-sensitive substring filtering
    if (filter) params.logGroupNamePattern = filter;

    const res = await client.send(new DescribeLogGroupsCommand(params));
    groups.push(...(res.logGroups || []));
    nextToken = res.nextToken;
  } while (nextToken);

  return groups;
}

async function analyzeLogGroups({ region, startTime, endTime, days, filter }) {
  const logsClient = new CloudWatchLogsClient({ region });
  const cwClient   = new CloudWatchClient({ region });

  process.stdout.write('  Log Groups: listing... ');
  const groups = await listLogGroups(logsClient, filter);
  console.log(`${groups.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (groups.length === 0) return { findings: [], resourcesScanned: 0 };

  // Fetch incoming log event counts to detect inactive groups
  const querySpecs = groups.map((g, i) => ({
    id: metricId('lg', i, 'ev'),
    namespace: 'AWS/Logs',
    metricName: 'IncomingLogEvents',
    dimensions: [{ Name: 'LogGroupName', Value: g.logGroupName }],
    stat: 'Sum',
  }));

  process.stdout.write(`  Log Groups: fetching activity metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];
  let totalLogCost = 0;

  groups.forEach((g, i) => {
    const storedBytes    = g.storedBytes || 0;
    const storedGB       = storedBytes / 1073741824;
    const hasRetention   = !!g.retentionInDays;
    const incomingEvents = cwMetrics[metricId('lg', i, 'ev')]?.sum ?? 0;
    const currentCost    = storedGB * PRICING.cwLogs.storagePerGBMonth;

    // Estimate ongoing write cost: events/day × estimated avg log size (2 KB)
    const dailyEvents      = incomingEvents / days;
    const dailyIngestGB    = (dailyEvents * 2048) / 1073741824; // assume 2 KB avg per event
    const monthlyIngestCost = dailyIngestGB * 30 * PRICING.cwLogs.ingestPerGB;
    totalLogCost += currentCost + monthlyIngestCost;

    // ── No retention policy ────────────────────────────────────────────────
    if (!hasRetention) {
      const priority = storedGB > 1 ? 'HIGH' : storedGB > 0.01 ? 'MEDIUM' : 'LOW';
      // Savings = current storage cost (after retention is set + old logs expire, cost drops to just new writes)
      const savings = currentCost > 0 ? currentCost : (monthlyIngestCost > 0 ? monthlyIngestCost * 0.5 : null);

      findings.push({
        provider: 'aws',
        service: 'Log Groups',
        resourceName: g.logGroupName,
        resourceId: g.arn || g.logGroupName,
        region,
        priority,
        type: 'NO_RETENTION',
        details: `No retention policy — ${fmtBytes(storedBytes)} stored, ${Math.round(dailyEvents).toLocaleString()} events/day ingested`,
        recommendation: `Set a retention policy to prevent unbounded log accumulation. Logs older than the retention period are automatically deleted, capping ongoing storage costs.`,
        metrics: {
          storedBytes,
          retentionDays: 'None (infinite)',
          incomingEventsOverWindow: Math.round(incomingEvents),
          incomingEventsPerDay: Math.round(dailyEvents),
        },
        estimatedCurrentCost:    parseFloat((currentCost + monthlyIngestCost).toFixed(4)),
        estimatedMonthlySavings: savings > 0.0001 ? parseFloat(savings.toFixed(4)) : null,
        suggestedAlarm: `aws logs put-retention-policy \\
  --log-group-name "${g.logGroupName}" \\
  --retention-in-days 30`,
      });
    }

    // ── No incoming events in window — only flag if retention is set ──────
    if (hasRetention && incomingEvents === 0 && storedBytes > 0) {
      findings.push({
        provider: 'aws',
        service: 'Log Groups',
        resourceName: g.logGroupName,
        resourceId: g.arn || g.logGroupName,
        region,
        priority: 'LOW',
        type: 'IDLE',
        details: `No log events in the last ${days} days — ${fmtBytes(storedBytes)} stored, ${g.retentionInDays}-day retention set`,
        recommendation: `If the associated resource has been decommissioned, delete this log group to remove stored data costs.`,
        metrics: {
          storedBytes,
          retentionDays: g.retentionInDays,
          incomingEventsOverWindow: 0,
        },
        estimatedCurrentCost:    parseFloat(currentCost.toFixed(4)),
        estimatedMonthlySavings: currentCost > 0.0001 ? parseFloat(currentCost.toFixed(4)) : null,
      });
    }
  });

  return { findings, resourcesScanned: groups.length, estimatedMonthlyCost: parseFloat(totalLogCost.toFixed(4)) };
}

function fmtBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = { analyzeLogGroups };
