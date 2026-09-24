'use strict';

const { ServiceBusManagementClient } = require('@azure/arm-servicebus');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { serviceBusMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeServiceBus({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const sbClient = new ServiceBusManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Service Bus: listing namespaces... ');
  const allNamespaces = await listAll(sbClient.namespaces.list());
  let namespaces = allNamespaces;
  if (filter) {
    const needle = filter.toLowerCase();
    namespaces = namespaces.filter(n => n.name.toLowerCase().includes(needle));
  }
  namespaces = namespaces.filter(n => !azureManagedPrefixes.some(p => n.name.toLowerCase().startsWith(p)));
  namespaces = namespaces.filter(n => matchesLocation(n.location, location));
  console.log(`${namespaces.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (namespaces.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];
  let totalMonthlyCost = 0;
  let resourcesScanned = 0;

  for (const ns of namespaces) {
    const rg = resourceGroupFromId(ns.id);
    const tier = ns.sku?.tier || 'Basic';
    totalMonthlyCost += serviceBusMonthlyCost(tier);

    const nsTags = ns.tags || {};
    const nsEnvironment = detectEnvironment(nsTags, ns.name);
    const nsTeam = detectTeam(nsTags);

    process.stdout.write(`  Service Bus: fetching queues/topics for "${ns.name}"... `);
    const [queues, topics] = await Promise.all([
      listAll(sbClient.queues.listByNamespace(rg, ns.name)).catch(() => []),
      listAll(sbClient.topics.listByNamespace(rg, ns.name)).catch(() => []),
    ]);
    console.log(`${queues.length} queues, ${topics.length} topics`);

    resourcesScanned += 1 + queues.length + topics.length;

    const queueMetricsMap = await batchGetResourceMetrics(
      monitorClient,
      queues.map(q => ({ id: `${ns.id}/queues/${q.name}` })),
      ['IncomingMessages', 'OutgoingMessages'], startTime, endTime
    );

    queues.forEach(q => {
      const activeMessages = q.countDetails?.activeMessageCount ?? 0;
      const dlqMessages = q.countDetails?.deadLetterMessageCount ?? 0;
      const scheduledMessages = q.countDetails?.scheduledMessageCount ?? 0;
      const incoming = queueMetricsMap.get(`${ns.id}/queues/${q.name}`)?.IncomingMessages?.sum ?? 0;
      const outgoing = queueMetricsMap.get(`${ns.id}/queues/${q.name}`)?.OutgoingMessages?.sum ?? 0;

      const base = {
        provider: 'azure',
        service: 'Service Bus',
        resourceName: `${ns.name}/${q.name}`,
        resourceId: q.id || `${ns.id}/queues/${q.name}`,
        region: ns.location,
        environment: nsEnvironment,
        team: nsTeam,
        tags: nsTags,
        metrics: {
          activeMessages, deadLetterMessages: dlqMessages, scheduledMessages,
          incomingMessages: Math.round(incoming), outgoingMessages: Math.round(outgoing),
        },
      };

      if (dlqMessages > 0) {
        findings.push({
          ...base,
          priority: dlqMessages > 100 ? 'HIGH' : 'MEDIUM',
          type: 'DLQ_MESSAGES',
          details: `Dead-letter sub-queue has ${dlqMessages.toLocaleString()} unprocessed messages`,
          recommendation: `Messages in a dead-letter queue indicate failed processing. Investigate the consumer for errors, fix the root cause, then resubmit dead-lettered messages.`,
          estimatedCurrentCost: null,
          estimatedMonthlySavings: null,
          suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-dlq-${q.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${ns.id}" \\\n  --condition "max DeadletteredMessages > 0" \\\n  --window-size 5m --evaluation-frequency 5m`,
        });
      }

      if (activeMessages === 0 && incoming === 0) {
        findings.push({
          ...base,
          priority: 'LOW',
          type: 'IDLE',
          details: `No incoming messages in the last ${days} days and no messages currently queued`,
          recommendation: `Verify whether this queue is still needed. Delete if no longer used.`,
          estimatedCurrentCost: null,
          estimatedMonthlySavings: null,
          fixCommand: `az servicebus queue delete --name "${q.name}" --namespace-name "${ns.name}" --resource-group "${rg}"`,
          suggestedAlarm: null,
        });
      } else if ((activeMessages + scheduledMessages) >= thresholds.azure.servicebus.staleActiveMessages && outgoing === 0) {
        // Azure Service Bus has no oldest-message-age metric like SQS's ApproximateAgeOfOldestMessage,
        // so this uses activeMessageCount sitting alongside zero dequeue activity as the stall signal.
        findings.push({
          ...base,
          priority: 'MEDIUM',
          type: 'STALE_MESSAGES',
          details: `${(activeMessages + scheduledMessages).toLocaleString()} message(s) queued but zero dequeued in the last ${days} days — consumer may be stalled or disconnected`,
          recommendation: `Check the consumer application for errors, crashes, or a stopped/scaled-to-zero deployment. Messages approaching the queue's max delivery count will dead-letter without ever being read.`,
          estimatedCurrentCost: null,
          estimatedMonthlySavings: null,
          suggestedAlarm: null,
        });
      }
    });

    for (const topic of topics) {
      const subs = await listAll(sbClient.subscriptions.listByTopic(rg, ns.name, topic.name)).catch(() => []);
      const activeMessages = topic.countDetails?.activeMessageCount ?? 0;

      if (subs.length === 0 && activeMessages === 0) {
        findings.push({
          provider: 'azure',
          service: 'Service Bus',
          resourceName: `${ns.name}/${topic.name}`,
          resourceId: topic.id || `${ns.id}/topics/${topic.name}`,
          region: ns.location,
          environment: nsEnvironment,
          team: nsTeam,
          tags: nsTags,
          priority: 'MEDIUM',
          type: 'IDLE',
          details: `Topic has no subscriptions and no queued messages — likely orphaned`,
          recommendation: `This topic has no subscribers. Confirm it is not referenced by any IaC stack, then delete it.`,
          metrics: { subscriptions: subs.length, activeMessages },
          estimatedCurrentCost: null,
          estimatedMonthlySavings: null,
          fixCommand: `az servicebus topic delete --name "${topic.name}" --namespace-name "${ns.name}" --resource-group "${rg}"`,
          suggestedAlarm: null,
        });
      }
    }

    const missing = missingTagGroups(nsTags);
    if (missing.length > 0) {
      findings.push({
        provider: 'azure',
        service: 'Service Bus',
        resourceName: ns.name,
        resourceId: ns.id,
        region: ns.location,
        environment: nsEnvironment,
        team: nsTeam,
        tags: nsTags,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz servicebus namespace update --name "${ns.name}" --resource-group "${rg}" --set tags.Environment=${nsEnvironment} tags.Team=your-team`,
        metrics: { tier },
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  }

  return { findings, resourcesScanned, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeServiceBus };
