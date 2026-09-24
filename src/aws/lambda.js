'use strict';

const { LambdaClient, ListFunctionsCommand, ListTagsCommand } = require('@aws-sdk/client-lambda');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const {
  CloudWatchLogsClient,
  StartQueryCommand,
  GetQueryResultsCommand,
} = require('@aws-sdk/client-cloudwatch-logs');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { thresholds, abandonedIdleDays, logsInsightsMaxConcurrency, lambdaMemoryAnalysisLimit, managedPrefixes } = require('../config');
const { lambdaComputeCost } = require('./localcosts');
const { RUNTIME_STATUS } = require('./runtimes');

// At least one key from each group must be present on a function's tags
const REQUIRED_TAG_GROUPS = [
  ['Environment', 'environment', 'Env', 'env'],
  ['Team', 'team', 'Owner', 'owner', 'Squad', 'squad'],
];

// Minimum previous-window invocations to qualify for anomaly detection
const ANOMALY_MIN_PREV_INVOCATIONS = 100;
// Drop must be at least this severe (fraction) to flag
const ANOMALY_DROP_THRESHOLD = 0.80;

// ─── List all Lambda functions (paginated) ────────────────────────────────────

async function listAllFunctions(client) {
  const functions = [];
  let marker;
  do {
    const res = await client.send(new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }));
    functions.push(...(res.Functions || []));
    marker = res.NextMarker;
  } while (marker);
  return functions;
}

// ─── Batch-fetch tags for all functions (20 concurrent) ──────────────────────

async function batchFetchTags(client, functions, concurrency = 20) {
  const tagMap = new Map();
  for (let i = 0; i < functions.length; i += concurrency) {
    const batch = functions.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(fn =>
        client.send(new ListTagsCommand({ Resource: fn.FunctionArn }))
          .then(r => ({ arn: fn.FunctionArn, tags: r.Tags || {} }))
          .catch(() => ({ arn: fn.FunctionArn, tags: {} }))
      )
    );
    for (const { arn, tags } of results) tagMap.set(arn, tags);
  }
  return tagMap;
}

// ─── Detect environment from tags, falling back to function name heuristic ───

function detectEnvironment(tags, functionName) {
  const envTag = tags['Environment'] || tags['environment'] || tags['Env'] || tags['env'];
  if (envTag) return envTag.toLowerCase();

  const name = functionName.toLowerCase();
  if (/-prd-|-prod-|-production-/.test(name) || name.endsWith('-prod') || name.endsWith('-prd')) return 'prod';
  if (/-tst-|-test-|-staging-|-stg-/.test(name)) return 'tst';
  if (/-dev-/.test(name)) return 'dev';
  return 'unknown';
}

// ─── Extract team/owner from tags ─────────────────────────────────────────────

function detectTeam(tags) {
  const checks = [
    ['Team', 'Team'], ['team', 'Team'],
    ['Owner', 'Owner'], ['owner', 'Owner'],
    ['Squad', 'Squad'], ['squad', 'Squad'],
    ['Project', 'Project'], ['project', 'Project'],
  ];
  for (const [tagKey, label] of checks) {
    if (tags[tagKey]) return `${label}: ${tags[tagKey]}`;
  }
  return null;
}

// ─── Downgrade IDLE priority for non-prod environments ───────────────────────

function adjustIdlePriority(priority, environment) {
  if (environment === 'tst' || environment === 'test' || environment === 'staging' || environment === 'stg') {
    return priority === 'HIGH' ? 'MEDIUM' : priority;
  }
  if (environment === 'dev' || environment === 'development') {
    return priority === 'HIGH' || priority === 'MEDIUM' ? 'LOW' : priority;
  }
  return priority; // prod / unknown: unchanged
}

// ─── Check which required tag groups are completely absent ───────────────────

function missingTagGroups(tags) {
  return REQUIRED_TAG_GROUPS.filter(group => !group.some(key => key in tags));
}

// ─── CloudWatch Logs Insights — memory + cold start from REPORT lines ────────

const INSIGHTS_QUERY = `
  fields @memorySize, @maxMemoryUsed, @initDuration, @duration
  | filter @type = "REPORT"
  | stats
      avg(@maxMemoryUsed)  as avgMemUsed,
      max(@maxMemoryUsed)  as peakMemUsed,
      avg(@initDuration)   as avgColdStartMs,
      count()              as reportCount
`.trim();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function runInsightsQuery(logsClient, logGroupName, startTime, endTime) {
  let queryId;
  try {
    const res = await logsClient.send(new StartQueryCommand({
      logGroupName,
      startTime: Math.floor(startTime.getTime() / 1000),
      endTime:   Math.floor(endTime.getTime() / 1000),
      queryString: INSIGHTS_QUERY,
    }));
    queryId = res.queryId;
  } catch { return null; }

  for (let attempt = 0; attempt < 12; attempt++) {
    await sleep(2000);
    const res = await logsClient.send(new GetQueryResultsCommand({ queryId }));
    if (res.status === 'Complete') {
      const row = (res.results || [])[0];
      if (!row) return null;
      const get = f => parseFloat(row.find(r => r.field === f)?.value ?? '0') || 0;
      return {
        avgMemUsedMB:   get('avgMemUsed'),
        peakMemUsedMB:  get('peakMemUsed'),
        avgColdStartMs: get('avgColdStartMs'),
        reportCount:    get('reportCount'),
      };
    }
    if (res.status === 'Failed' || res.status === 'Cancelled') return null;
  }
  return null;
}

async function batchInsightsAnalysis(logsClient, functions, startTime, endTime, concurrency) {
  const results = new Map();
  for (let i = 0; i < functions.length; i += concurrency) {
    const batch = functions.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(fn =>
        runInsightsQuery(logsClient, `/aws/lambda/${fn.FunctionName}`, startTime, endTime)
          .then(data => ({ fn: fn.FunctionName, data }))
      )
    );
    for (const { fn, data } of batchResults) results.set(fn, data);
  }
  return results;
}

// ─── Main analyser ────────────────────────────────────────────────────────────

async function analyzeLambda({ region, startTime, endTime, days, filter }) {
  const lambdaClient = new LambdaClient({ region });
  const cwClient     = new CloudWatchClient({ region });
  const logsClient   = new CloudWatchLogsClient({ region });

  process.stdout.write('  Lambda: listing functions... ');
  let functions = await listAllFunctions(lambdaClient);
  if (filter) {
    const needle = filter.toLowerCase();
    functions = functions.filter(f => f.FunctionName.toLowerCase().includes(needle));
  }
  functions = functions.filter(f => !managedPrefixes.some(p => f.FunctionName.toLowerCase().startsWith(p)));
  console.log(`${functions.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (functions.length === 0) return { findings: [], resourcesScanned: 0 };

  // ── Tags ───────────────────────────────────────────────────────────────
  process.stdout.write(`  Lambda: fetching resource tags... `);
  const tagMap = await batchFetchTags(lambdaClient, functions);
  console.log('done');

  // ── Split window for anomaly detection ────────────────────────────────
  const halfDays = Math.max(1, Math.floor(days / 2));
  const midTime  = new Date(endTime.getTime() - halfDays * 24 * 60 * 60 * 1000);

  // ── CloudWatch metrics: main window + anomaly curr/prev in parallel ───
  const mainSpecs = [];
  functions.forEach((fn, i) => {
    const dims = [{ Name: 'FunctionName', Value: fn.FunctionName }];
    mainSpecs.push(
      { id: metricId('li', i, 'inv'), namespace: 'AWS/Lambda', metricName: 'Invocations', dimensions: dims, stat: 'Sum'     },
      { id: metricId('li', i, 'dur'), namespace: 'AWS/Lambda', metricName: 'Duration',    dimensions: dims, stat: 'Average' },
      { id: metricId('li', i, 'err'), namespace: 'AWS/Lambda', metricName: 'Errors',      dimensions: dims, stat: 'Sum'     },
      { id: metricId('li', i, 'thr'), namespace: 'AWS/Lambda', metricName: 'Throttles',   dimensions: dims, stat: 'Sum'     }
    );
  });

  const anomalyCurrSpecs = functions.map((fn, i) => ({
    id: metricId('ac', i, 'i'), namespace: 'AWS/Lambda', metricName: 'Invocations',
    dimensions: [{ Name: 'FunctionName', Value: fn.FunctionName }], stat: 'Sum',
  }));
  const anomalyPrevSpecs = functions.map((fn, i) => ({
    id: metricId('ap', i, 'i'), namespace: 'AWS/Lambda', metricName: 'Invocations',
    dimensions: [{ Name: 'FunctionName', Value: fn.FunctionName }], stat: 'Sum',
  }));

  process.stdout.write(`  Lambda: fetching CloudWatch metrics for ${functions.length} functions... `);
  const [cwMetrics, cwAnomalyCurr, cwAnomalyPrev] = await Promise.all([
    batchGetMetrics(cwClient, mainSpecs, startTime, endTime, 86400),
    batchGetMetrics(cwClient, anomalyCurrSpecs, midTime, endTime, 86400),
    batchGetMetrics(cwClient, anomalyPrevSpecs, startTime, midTime, 86400),
  ]);
  console.log('done');

  // ── Logs Insights — memory + cold start ───────────────────────────────
  const forInsights = functions.slice(0, lambdaMemoryAnalysisLimit);
  process.stdout.write(`  Lambda: running Logs Insights memory/cold-start analysis for ${forInsights.length} functions... `);
  const insightsData = await batchInsightsAnalysis(logsClient, forInsights, startTime, endTime, logsInsightsMaxConcurrency);
  console.log('done');

  // ── Generate findings ──────────────────────────────────────────────────
  const findings = [];
  let totalLambdaCost = 0;

  functions.forEach((fn, i) => {
    const invocations     = cwMetrics[metricId('li', i, 'inv')]?.sum ?? 0;
    const avgDurationMs   = cwMetrics[metricId('li', i, 'dur')]?.avg ?? 0;
    const errors          = cwMetrics[metricId('li', i, 'err')]?.sum ?? 0;
    const throttles       = cwMetrics[metricId('li', i, 'thr')]?.sum ?? 0;
    const configuredMemMB = fn.MemorySize || 128;
    const insights        = insightsData.get(fn.FunctionName);
    const ageDays         = fn.LastModified
      ? Math.floor((Date.now() - new Date(fn.LastModified).getTime()) / 86400000)
      : null;

    const invCurr = cwAnomalyCurr[metricId('ac', i, 'i')]?.sum ?? 0;
    const invPrev = cwAnomalyPrev[metricId('ap', i, 'i')]?.sum ?? 0;

    const tags        = tagMap.get(fn.FunctionArn) || {};
    const environment = detectEnvironment(tags, fn.FunctionName);
    const team        = detectTeam(tags);

    const monthlyInvocations = (invocations / days) * 30;
    const fnMonthlyCost = lambdaComputeCost(configuredMemMB, avgDurationMs, monthlyInvocations);
    totalLambdaCost += fnMonthlyCost;

    const base = {
      provider:     'aws',
      service:      'Lambda',
      resourceName: fn.FunctionName,
      resourceId:   fn.FunctionArn,
      region,
      environment,
      team,
      tags,
      metrics: {
        invocations:    Math.round(invocations),
        avgDurationMs:  Math.round(avgDurationMs),
        errors:         Math.round(errors),
        throttles:      Math.round(throttles),
        configuredMemMB,
        ...(ageDays !== null ? { lastModifiedDaysAgo: ageDays } : {}),
      },
    };

    // ── DEPRECATED RUNTIME ───────────────────────────────────────────────
    const runtimeInfo = RUNTIME_STATUS[fn.Runtime];
    if (runtimeInfo) {
      const isEOL = runtimeInfo.status === 'EOL';
      const eolContext = isEOL
        ? `${runtimeInfo.label} (${fn.Runtime}) has reached end-of-life. AWS no longer ships security patches for this runtime — any known CVEs in the runtime itself will remain unpatched indefinitely. AWS will eventually block new deployments on EOL runtimes, which means your next release could fail silently in CI/CD.`
        : `${runtimeInfo.label} (${fn.Runtime}) is deprecated for new deployments. AWS has flagged this runtime for removal and will not ship new security patches beyond critical fixes. Upgrade before it reaches EOL to avoid forced migrations under pressure.`;
      findings.push({
        ...base,
        priority: isEOL ? 'HIGH' : 'MEDIUM',
        type: 'DEPRECATED_RUNTIME',
        details: `${runtimeInfo.label} (${fn.Runtime}) is ${runtimeInfo.status} — unpatched CVEs, future deployments at risk`,
        recommendation: `${eolContext}\n\nSteps to fix:\n1. Update your CDK/SAM/serverless.yml — change runtime from ${fn.Runtime} to ${runtimeInfo.upgrade}\n2. Test locally — the function code rarely needs changes unless it uses APIs removed in the new runtime\n3. Deploy and verify the function still behaves correctly\n\nTarget: ${runtimeInfo.upgrade}`,
        metrics: { ...base.metrics, runtime: fn.Runtime, recommendedRuntime: runtimeInfo.upgrade },
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
        fixCommand: `aws lambda update-function-configuration \\\n  --function-name "${fn.FunctionName}" \\\n  --runtime ${runtimeInfo.upgrade}\n# If managed by CDK / SAM / Serverless Framework, update your IaC and redeploy instead`,
      });
    }

    // ── ANOMALY DROP ─────────────────────────────────────────────────────
    if (
      invPrev >= ANOMALY_MIN_PREV_INVOCATIONS &&
      invCurr < invPrev * (1 - ANOMALY_DROP_THRESHOLD) &&
      invocations >= thresholds.lambda.idleInvocations
    ) {
      const dropPct   = Math.round((1 - invCurr / invPrev) * 100);
      const threshold = Math.max(1, Math.round(invPrev * 0.3));
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'ANOMALY_DROP',
        details: `Traffic dropped ${dropPct}% — ${Math.round(invPrev)} invocations in previous ${halfDays}d vs ${Math.round(invCurr)} in last ${halfDays}d`,
        recommendation: `Investigate what changed in the last ${halfDays} days. Check recent deployments, upstream event sources, EventBridge rules, and CloudWatch Logs for errors.`,
        metrics: {
          ...base.metrics,
          [`invocationsPrev${halfDays}d`]: Math.round(invPrev),
          [`invocationsCurr${halfDays}d`]: Math.round(invCurr),
          trafficDropPct: dropPct,
        },
        estimatedMonthlySavings: null,
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-drop-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name Invocations \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Sum --period 86400 \\
  --threshold ${threshold} --comparison-operator LessThanThreshold \\
  --evaluation-periods 2 --treat-missing-data breaching`,
      });
    }

    // ── IDLE / ABANDONED ─────────────────────────────────────────────────
    if (invocations < thresholds.lambda.idleInvocations) {
      // ABANDONED: zero invocations AND code untouched for 28+ days → dead code, always HIGH
      const isAbandoned = invocations === 0 && ageDays !== null && ageDays >= abandonedIdleDays;

      const priority = isAbandoned
        ? 'HIGH'
        : adjustIdlePriority(invocations === 0 ? 'HIGH' : 'MEDIUM', environment);

      const type    = isAbandoned ? 'ABANDONED' : 'IDLE';
      const ageDisplay = ageDays !== null
        ? (ageDays >= 365 ? `~${(ageDays / 365).toFixed(1)} years` : `${ageDays} days`)
        : null;
      const details = isAbandoned
        ? `Zero invocations for ${days} days, last updated ${ageDisplay} ago — dead code still deployed with live IAM permissions and accumulating unpatched CVEs`
        : invocations === 0
          ? `No invocations in the last ${days} days${ageDisplay ? ` — last modified ${ageDisplay} ago` : ''}`
          : `Only ${Math.round(invocations)} invocations in the last ${days} days`;
      const recommendation = isAbandoned
        ? `This function is dead code deployed for ${ageDisplay} with no activity. Every deployed Lambda — active or not — holds IAM permissions and accumulates unpatched vulnerabilities as its runtime ages. Delete it and its CloudWatch log group to shrink your security surface.`
        : `Review whether this function is still needed. If it belongs to a decommissioned feature, delete it and its associated log group to reduce clutter.`;

      const idleFixCommand = isAbandoned
        ? `aws lambda delete-function --function-name "${fn.FunctionName}"\naws logs delete-log-group --log-group-name "/aws/lambda/${fn.FunctionName}"\n# Deletes the function and cleans up its log group`
        : `# Confirm this function is no longer needed, then:\naws lambda delete-function --function-name "${fn.FunctionName}"`;

      findings.push({
        ...base,
        priority,
        type,
        details,
        recommendation,
        estimatedMonthlySavings: null,
        fixCommand: idleFixCommand,
        suggestedAlarm: invocations === 0
          ? null
          : `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-idle-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name Invocations \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Sum --period 86400 \\
  --threshold 1 --comparison-operator LessThanThreshold \\
  --evaluation-periods 3 --treat-missing-data notBreaching`,
      });
    }

    // ── OVER-ALLOCATED MEMORY ─────────────────────────────────────────────
    if (insights && insights.reportCount > 5 && invocations >= thresholds.lambda.idleInvocations) {
      const utilisation = insights.avgMemUsedMB / configuredMemMB;
      const recommended = recommendedMemory(insights.peakMemUsedMB);

      base.metrics.avgMemUsedMB      = Math.round(insights.avgMemUsedMB);
      base.metrics.peakMemUsedMB     = Math.round(insights.peakMemUsedMB);
      base.metrics.memUtilisationPct = Math.round(utilisation * 100);
      if (insights.avgColdStartMs > 0) base.metrics.avgColdStartMs = Math.round(insights.avgColdStartMs);

      if (utilisation < thresholds.lambda.memoryUtilizationVeryLow || utilisation < thresholds.lambda.memoryUtilizationLow) {
        const currentCost   = lambdaComputeCost(configuredMemMB, avgDurationMs, monthlyInvocations);
        const optimisedCost = lambdaComputeCost(recommended, avgDurationMs, monthlyInvocations);
        const savings       = Math.max(0, currentCost - optimisedCost);

        findings.push({
          ...base,
          priority: utilisation < thresholds.lambda.memoryUtilizationVeryLow ? 'HIGH' : 'MEDIUM',
          type: 'OVER_ALLOCATED',
          details: `Configured ${configuredMemMB} MB — avg peak usage ${Math.round(insights.avgMemUsedMB)} MB (${Math.round(utilisation * 100)}% utilisation)`,
          recommendation: `Reduce memory from ${configuredMemMB} MB to ~${recommended} MB. Lambda cost = memory × duration × invocations, so this directly cuts the bill.`,
          estimatedCurrentCost:    parseFloat(currentCost.toFixed(4)),
          estimatedMonthlySavings: savings >= 0.0001 ? parseFloat(savings.toFixed(4)) : null,
          suggestedAlarm: null,
          fixCommand: `aws lambda update-function-configuration \\\n  --function-name "${fn.FunctionName}" \\\n  --memory-size ${recommended}\n# Reduces allocated memory from ${configuredMemMB} MB to ${recommended} MB`,
        });
      }
    }

    // ── HIGH ERROR RATE ───────────────────────────────────────────────────
    if (invocations >= 10 && errors / invocations > 0.05) {
      findings.push({
        ...base,
        priority: errors / invocations > 0.20 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `${Math.round((errors / invocations) * 100)}% error rate — ${Math.round(errors)} errors out of ${Math.round(invocations)} invocations`,
        recommendation: `Check CloudWatch Logs for this function to identify the root cause. High error rates mean compute cost with no useful work done.`,
        estimatedMonthlySavings: null,
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-errors-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name Errors \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Sum --period 300 \\
  --threshold 5 --comparison-operator GreaterThanThreshold \\
  --evaluation-periods 1`,
      });
    }

    // ── THROTTLING ────────────────────────────────────────────────────────
    if (throttles > 10 && invocations > 0 && throttles / invocations > 0.05) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'THROTTLED',
        details: `${Math.round(throttles)} throttle events — ${Math.round((throttles / invocations) * 100)}% of invocations were throttled`,
        recommendation: `Increase reserved concurrency, request a Lambda concurrency limit increase, or reduce the rate of triggers.`,
        estimatedMonthlySavings: null,
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-throttles-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name Throttles \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Sum --period 300 \\
  --threshold 0 --comparison-operator GreaterThanThreshold \\
  --evaluation-periods 1`,
      });
    }

    // ── MISSING TAGS ──────────────────────────────────────────────────────
    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      const missingLabels = missing.map(g => g[0]).join(', ');
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missingLabels}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing. In CDK:\nTags.of(myFunction).add('Environment', '${environment}');\nTags.of(myFunction).add('Team', 'your-team');`,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: functions.length, estimatedMonthlyCost: parseFloat(totalLambdaCost.toFixed(4)) };
}

function recommendedMemory(peakMB) {
  const target = peakMB * 1.25;
  for (let m = 128; m <= 10240; m += (m < 3008 ? 64 : 256)) {
    if (m >= target) return m;
  }
  return 10240;
}

module.exports = { analyzeLambda };
