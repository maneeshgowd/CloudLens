'use strict';

const { WebSiteManagementClient } = require('@azure/arm-appservice');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { getRuntimeStatus } = require('./runtimes');
const { functionsMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, adjustIdlePriority, resourceGroupFromId } = require('./tagging');

// Minimum previous-window invocations to qualify for anomaly detection — mirrors src/aws/lambda.js
const ANOMALY_MIN_PREV_INVOCATIONS = 100;
const ANOMALY_DROP_THRESHOLD = 0.80;

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeAzureFunctions({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const webClient = new WebSiteManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Azure Functions: listing function apps... ');
  const allApps = await listAll(webClient.webApps.list());
  let apps = allApps.filter(a => (a.kind || '').toLowerCase().includes('functionapp'));
  apps = apps.filter(a => (a.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    apps = apps.filter(a => a.name.toLowerCase().includes(needle));
  }
  apps = apps.filter(a => !azureManagedPrefixes.some(p => a.name.toLowerCase().startsWith(p)));
  console.log(`${apps.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (apps.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Azure Functions: fetching configuration for ${apps.length} apps... `);
  const configs = await Promise.all(apps.map(a => {
    const rg = resourceGroupFromId(a.id);
    return webClient.webApps.getConfiguration(rg, a.name).catch(() => ({}));
  }));
  console.log('done');

  // Split window for anomaly detection — mirrors src/aws/lambda.js's curr/prev half-window comparison
  const halfDays = Math.max(1, Math.floor(days / 2));
  const midTime = new Date(endTime.getTime() - halfDays * 24 * 60 * 60 * 1000);

  process.stdout.write(`  Azure Functions: fetching metrics for ${apps.length} apps... `);
  const [metricsMap, currMetricsMap, prevMetricsMap] = await Promise.all([
    batchGetResourceMetrics(monitorClient, apps, ['FunctionExecutionCount', 'Http5xx', 'Http429', 'Requests'], startTime, endTime),
    batchGetResourceMetrics(monitorClient, apps, ['FunctionExecutionCount'], midTime, endTime),
    batchGetResourceMetrics(monitorClient, apps, ['FunctionExecutionCount'], startTime, midTime),
  ]);
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  apps.forEach((app, i) => {
    const config = configs[i] || {};
    const metrics = metricsMap.get(app.id) || {};
    const executions = metrics.FunctionExecutionCount?.sum ?? 0;
    const requests = metrics.Requests?.sum ?? 0;
    const errors5xx = metrics.Http5xx?.sum ?? 0;
    const throttled429 = metrics.Http429?.sum ?? 0;
    const execCurr = currMetricsMap.get(app.id)?.FunctionExecutionCount?.sum ?? 0;
    const execPrev = prevMetricsMap.get(app.id)?.FunctionExecutionCount?.sum ?? 0;
    const tags = app.tags || {};
    const environment = detectEnvironment(tags, app.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(app.id);
    const isStopped = app.enabled === false || (app.state && app.state !== 'Running');

    const activityCount = Math.max(executions, requests);
    const monthlyExecutions = (activityCount / days) * 30;
    const monthlyCost = functionsMonthlyCost(monthlyExecutions);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Azure Functions',
      resourceName: app.name,
      resourceId: app.id,
      region: app.location,
      environment,
      team,
      tags,
      metrics: {
        executions: Math.round(executions),
        requests: Math.round(requests),
        http5xx: Math.round(errors5xx),
        http429: Math.round(throttled429),
        ...(isStopped ? { appState: app.state || 'Stopped', enabled: app.enabled !== false } : {}),
      },
    };

    // ── Deprecated runtime ─────────────────────────────────────────────────
    const runtimeInfo = getRuntimeStatus(config);
    if (runtimeInfo) {
      const isEOL = runtimeInfo.status === 'EOL';
      findings.push({
        ...base,
        priority: isEOL ? 'HIGH' : 'MEDIUM',
        type: 'DEPRECATED_RUNTIME',
        details: `${runtimeInfo.label} (${runtimeInfo.raw}) is ${runtimeInfo.status} — unpatched CVEs and future deployment risk`,
        recommendation: `Update the function app's runtime stack from ${runtimeInfo.raw} to ${runtimeInfo.upgrade}. Test locally, then redeploy via your CI/CD pipeline or IaC.`,
        metrics: { ...base.metrics, runtime: runtimeInfo.raw, recommendedRuntime: runtimeInfo.upgrade },
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
        fixCommand: `az functionapp config set --name "${app.name}" --resource-group "${rg}" --linux-fx-version "${runtimeInfo.upgrade}"\n# If this app is managed by IaC (Bicep/Terraform/ARM), update that source instead and redeploy.`,
      });
    }

    // ── Anomaly drop ────────────────────────────────────────────────────────
    // Substitute for src/aws/lambda.js's ANOMALY_DROP — same curr/prev half-window logic,
    // using FunctionExecutionCount since Azure Functions has no per-invocation Duration metric parity.
    if (
      execPrev >= ANOMALY_MIN_PREV_INVOCATIONS &&
      execCurr < execPrev * (1 - ANOMALY_DROP_THRESHOLD) &&
      activityCount >= thresholds.azure.functions.idleExecutions
    ) {
      const dropPct = Math.round((1 - execCurr / execPrev) * 100);
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'ANOMALY_DROP',
        details: `Execution volume dropped ${dropPct}% — ${Math.round(execPrev)} executions in previous ${halfDays}d vs ${Math.round(execCurr)} in last ${halfDays}d`,
        recommendation: `Investigate what changed in the last ${halfDays} days. Check recent deployments, upstream trigger sources (queues, event grid, timers), and Application Insights for errors.`,
        metrics: {
          ...base.metrics,
          [`executionsPrev${halfDays}d`]: Math.round(execPrev),
          [`executionsCurr${halfDays}d`]: Math.round(execCurr),
          trafficDropPct: dropPct,
        },
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-drop-${app.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${app.id}" \\\n  --condition "total FunctionExecutionCount < ${Math.max(1, Math.round(execPrev * 0.3))}" \\\n  --window-size 1d --evaluation-frequency 1d`,
      });
    }

    // ── Idle / Abandoned ──────────────────────────────────────────────────
    // Substitute for src/aws/lambda.js's ABANDONED (which uses code age via LastModified,
    // unavailable here) — an Azure Functions app that's been explicitly stopped/disabled
    // AND has zero activity is a stronger, still-real "dead resource" signal, always HIGH.
    if (activityCount < thresholds.azure.functions.idleExecutions) {
      const isAbandoned = activityCount === 0 && isStopped;
      const priority = isAbandoned
        ? 'HIGH'
        : adjustIdlePriority(activityCount === 0 ? 'HIGH' : 'MEDIUM', environment);
      const type = isAbandoned ? 'ABANDONED' : 'IDLE';
      const details = isAbandoned
        ? `App is ${app.state || 'stopped'}/disabled with zero executions in the last ${days} days — still deployed with live RBAC role assignments`
        : activityCount === 0
          ? `No executions in the last ${days} days`
          : `Only ${Math.round(activityCount)} executions in the last ${days} days`;
      const recommendation = isAbandoned
        ? `This function app is stopped and inactive. A stopped app still holds its managed identity role assignments, connection strings, and app settings — delete it if it's no longer needed to shrink your security surface.`
        : `Verify this function app is still needed. If it belongs to a decommissioned feature, delete it to reduce clutter and shrink RBAC surface area.`;

      findings.push({
        ...base,
        priority,
        type,
        details,
        recommendation,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `# Confirm this function app is no longer needed, then:\naz functionapp delete --name "${app.name}" --resource-group "${rg}"`,
        suggestedAlarm: activityCount === 0 ? null : `az monitor metrics alert create \\\n  --name "cloudlens-idle-${app.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${app.id}" \\\n  --condition "total FunctionExecutionCount < 1" \\\n  --window-size 1d --evaluation-frequency 1d`,
      });
    }

    // ── High error rate ───────────────────────────────────────────────────
    if (requests >= 10 && errors5xx / requests > 0.05) {
      findings.push({
        ...base,
        priority: errors5xx / requests > 0.20 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `${Math.round((errors5xx / requests) * 100)}% HTTP 5xx rate — ${Math.round(errors5xx)} errors out of ${Math.round(requests)} requests`,
        recommendation: `Check Application Insights / Log Stream for this function app to identify the root cause.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-errors-${app.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${app.id}" \\\n  --condition "total Http5xx > 5" \\\n  --window-size 5m --evaluation-frequency 5m`,
      });
    }

    // ── Throttled ─────────────────────────────────────────────────────────
    if (requests >= thresholds.azure.functions.throttleMinRequests && throttled429 / requests > thresholds.azure.functions.throttleRatio) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'THROTTLED',
        details: `${Math.round(throttled429)} HTTP 429 responses — ${Math.round((throttled429 / requests) * 100)}% of requests were throttled`,
        recommendation: `Scale out (increase instance count / plan tier) or check for host.json throttling and dynamic concurrency limits. Consumption plan apps in particular can throttle under burst load.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-throttles-${app.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${app.id}" \\\n  --condition "total Http429 > 0" \\\n  --window-size 5m --evaluation-frequency 5m`,
      });
    }

    // ── Missing tags ──────────────────────────────────────────────────────
    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz functionapp update --name "${app.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: apps.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeAzureFunctions };
