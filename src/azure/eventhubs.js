'use strict';

const { EventHubManagementClient } = require('@azure/arm-eventhub');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { eventHubsMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// Namespace-level scan — mirrors src/aws/msk.js's cluster-level scope.
// Throughput units (and their cost) are provisioned per namespace, not per
// event hub, so namespace is the right unit for idle/underutilised findings.
async function analyzeEventHubs({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const ehClient = new EventHubManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Event Hubs: listing namespaces... ');
  const allNamespaces = await listAll(ehClient.namespaces.list());
  let namespaces = allNamespaces.filter(ns => (ns.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    namespaces = namespaces.filter(ns => ns.name.toLowerCase().includes(needle));
  }
  namespaces = namespaces.filter(ns => !azureManagedPrefixes.some(p => ns.name.toLowerCase().startsWith(p)));
  console.log(`${namespaces.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (namespaces.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Event Hubs: fetching throughput metrics for ${namespaces.length} namespace(s)... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, namespaces,
    ['IncomingMessages', 'OutgoingMessages', 'IncomingBytes', 'OutgoingBytes', 'ThrottledRequests', 'UserErrors', 'ServerErrors', 'QuotaExceededErrors'],
    startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  namespaces.forEach(ns => {
    const metrics = metricsMap.get(ns.id) || {};
    const incomingMsgs = metrics.IncomingMessages?.sum ?? 0;
    const outgoingMsgs = metrics.OutgoingMessages?.sum ?? 0;
    const incomingBytes = metrics.IncomingBytes?.sum ?? 0;
    const outgoingBytes = metrics.OutgoingBytes?.sum ?? 0;
    const throttled = metrics.ThrottledRequests?.sum ?? 0;
    const userErrors = metrics.UserErrors?.sum ?? 0;
    const serverErrors = metrics.ServerErrors?.sum ?? 0;
    const quotaExceeded = metrics.QuotaExceededErrors?.sum ?? 0;

    const secondsInWindow = days * 86400;
    const avgInKBps = (incomingBytes / secondsInWindow) / 1024;
    const avgOutKBps = (outgoingBytes / secondsInWindow) / 1024;

    const tags = ns.tags || {};
    const environment = detectEnvironment(tags, ns.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(ns.id);
    const tier = ns.sku?.name || 'Standard';
    const throughputUnits = ns.sku?.capacity ?? 1;
    const monthlyEvents = ((incomingMsgs + outgoingMsgs) / days) * 30;
    const monthlyCost = eventHubsMonthlyCost(tier, throughputUnits, monthlyEvents);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Event Hubs',
      resourceName: ns.name,
      resourceId: ns.id,
      region: ns.location,
      environment,
      team,
      tags,
      metrics: {
        incomingMessages: Math.round(incomingMsgs),
        outgoingMessages: Math.round(outgoingMsgs),
        avgIncomingKBps: parseFloat(avgInKBps.toFixed(2)),
        avgOutgoingKBps: parseFloat(avgOutKBps.toFixed(2)),
        tier,
        throughputUnits,
      },
    };

    if (incomingMsgs === 0 && outgoingMsgs === 0) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'EH_IDLE',
        details: `No messages in or out in the last ${days} days — est. $${monthlyCost.toFixed(2)}/month for ${throughputUnits}× ${tier} throughput unit(s)`,
        recommendation: `Confirm all producers and consumers have disconnected. If this namespace belongs to a decommissioned workload, delete it to stop the fixed throughput-unit charge.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az eventhubs namespace delete --name "${ns.name}" --resource-group "${rg}"`,
        suggestedAlarm: null,
      });
    } else if (tier !== 'Basic' && avgInKBps < thresholds.azure.eventhubs.underutilizedKBps && avgOutKBps < thresholds.azure.eventhubs.underutilizedKBps) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'EH_UNDERUTILIZED',
        details: `Low throughput: ~${avgInKBps.toFixed(1)} KB/s in / ~${avgOutKBps.toFixed(1)} KB/s out across ${throughputUnits} throughput unit(s) (${days}-day average)`,
        recommendation: `Reduce the number of provisioned throughput units, or enable auto-inflate to scale down automatically during low-traffic periods. Current: ${throughputUnits}× ${tier} (~$${monthlyCost.toFixed(2)}/month).`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: null,
        fixCommand: `az eventhubs namespace update --name "${ns.name}" --resource-group "${rg}" --capacity ${Math.max(1, throughputUnits - 1)}`,
        suggestedAlarm: null,
      });
    }

    if (throttled > 0 || quotaExceeded > 0) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'EH_THROTTLED',
        details: `${Math.round(throttled + quotaExceeded).toLocaleString()} throttled/quota-exceeded requests in the last ${days} days — producers or consumers are being rate-limited`,
        recommendation: `Increase throughput units (or enable auto-inflate) to raise the namespace's ingress/egress quota, or reduce client-side send/receive rates.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-ehthrottle-${ns.name.substring(0, 40)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${ns.id}" \\\n  --condition "total ThrottledRequests > 0" \\\n  --window-size 15m --evaluation-frequency 15m`,
      });
    } else if (serverErrors + userErrors >= 10) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'HIGH_ERROR_RATE',
        details: `${Math.round(serverErrors)} server error(s) and ${Math.round(userErrors)} user error(s) in the last ${days} days`,
        recommendation: `Review client SDK error handling for user errors (bad requests, auth failures) and check Azure status for server errors.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }

    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz eventhubs namespace update --name "${ns.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: namespaces.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeEventHubs };
