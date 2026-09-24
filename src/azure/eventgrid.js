'use strict';

const { EventGridManagementClient } = require('@azure/arm-eventgrid');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { eventGridMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// Custom topics only — mirrors src/aws/eventbridge.js's scope of custom rules
// (system topics created implicitly by other Azure services are out of scope).
async function analyzeEventGrid({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const egClient = new EventGridManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Event Grid: listing topics... ');
  const allTopics = await listAll(egClient.topics.listBySubscription());
  let topics = allTopics;
  if (filter) {
    const needle = filter.toLowerCase();
    topics = topics.filter(t => t.name.toLowerCase().includes(needle));
  }
  topics = topics.filter(t => !azureManagedPrefixes.some(p => t.name.toLowerCase().startsWith(p)));
  topics = topics.filter(t => matchesLocation(t.location, location));
  console.log(`${topics.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (topics.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Event Grid: fetching delivery metrics for ${topics.length} topics... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, topics,
    ['PublishSuccessCount', 'PublishFailCount', 'MatchedEventCount', 'DeliverySuccessCount', 'DeliveryAttemptFailCount', 'DeadLetteredCount'],
    startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  topics.forEach(topic => {
    const metrics = metricsMap.get(topic.id) || {};
    const published = metrics.PublishSuccessCount?.sum ?? 0;
    const publishFailures = metrics.PublishFailCount?.sum ?? 0;
    const matched = metrics.MatchedEventCount?.sum ?? 0;
    const deliverySuccess = metrics.DeliverySuccessCount?.sum ?? 0;
    const deliveryFailures = metrics.DeliveryAttemptFailCount?.sum ?? 0;
    const deadLettered = metrics.DeadLetteredCount?.sum ?? 0;
    const tags = topic.tags || {};
    const environment = detectEnvironment(tags, topic.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(topic.id);
    const monthlyOps = ((published + matched + deliverySuccess + deliveryFailures) / days) * 30;
    const monthlyCost = eventGridMonthlyCost(monthlyOps);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Event Grid',
      resourceName: topic.name,
      resourceId: topic.id,
      region: topic.location,
      environment,
      team,
      tags,
      metrics: {
        published: Math.round(published),
        matched: Math.round(matched),
        deliverySuccess: Math.round(deliverySuccess),
        deliveryFailures: Math.round(deliveryFailures),
        deadLettered: Math.round(deadLettered),
      },
    };

    if (published + publishFailures < thresholds.azure.eventgrid.idlePublished) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'IDLE',
        details: `No events published to this topic in the last ${days} days`,
        recommendation: `Verify whether any publisher still targets this topic. If decommissioned, delete it and any subscriptions attached to it.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az eventgrid topic delete --name "${topic.name}" --resource-group "${rg}"`,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-idle-${topic.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${topic.id}" \\\n  --condition "total PublishSuccessCount < 1" \\\n  --window-size 1d --evaluation-frequency 1d`,
      });
    }

    if (deadLettered > 0) {
      findings.push({
        ...base,
        priority: deadLettered > 100 ? 'HIGH' : 'MEDIUM',
        type: 'DLQ_MESSAGES',
        details: `${Math.round(deadLettered).toLocaleString()} events dead-lettered — deliveries have exhausted retry attempts`,
        recommendation: `Check the event subscription's dead-letter destination (storage container) to inspect failed events, fix the receiving endpoint, and replay if needed.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-dlq-${topic.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${topic.id}" \\\n  --condition "total DeadLetteredCount > 0" \\\n  --window-size 15m --evaluation-frequency 15m`,
      });
    } else if (deliverySuccess + deliveryFailures >= 10 && deliveryFailures / (deliverySuccess + deliveryFailures) > 0.05) {
      const failRate = deliveryFailures / (deliverySuccess + deliveryFailures);
      findings.push({
        ...base,
        priority: failRate > 0.20 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `${Math.round(failRate * 100)}% of delivery attempts failed — ${Math.round(deliveryFailures)} failures out of ${Math.round(deliverySuccess + deliveryFailures)} attempts`,
        recommendation: `Check the event subscription's endpoint health. Repeated failures eventually dead-letter or drop events depending on the subscription's retry policy.`,
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz eventgrid topic update --name "${topic.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: topics.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeEventGrid };
