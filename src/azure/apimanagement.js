'use strict';

const { ApiManagementClient } = require('@azure/arm-apimanagement');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { apiManagementMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeApiManagement({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const apimClient = new ApiManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  API Management: listing services... ');
  const allServices = await listAll(apimClient.apiManagementService.list());
  let services = allServices;
  if (filter) {
    const needle = filter.toLowerCase();
    services = services.filter(s => s.name.toLowerCase().includes(needle));
  }
  services = services.filter(s => !azureManagedPrefixes.some(p => s.name.toLowerCase().startsWith(p)));
  services = services.filter(s => matchesLocation(s.location, location));
  console.log(`${services.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (services.length === 0) return { findings: [], resourcesScanned: 0 };

  // Modern GatewayResponseCodeCategory-dimensioned Requests metric replaced the
  // deprecated TotalRequests/SuccessfulRequests/FailedRequests trio.
  process.stdout.write(`  API Management: fetching gateway metrics for ${services.length} services... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, services, ['Requests', 'Capacity', 'Duration', 'BackendDuration'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  services.forEach(svc => {
    const metrics = metricsMap.get(svc.id) || {};
    const requests = metrics.Requests?.sum ?? 0;
    const capacityPct = metrics.Capacity?.avg ?? null;
    const durationMs = metrics.Duration?.avg ?? null;
    const tags = svc.tags || {};
    const environment = detectEnvironment(tags, svc.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(svc.id);
    const tier = svc.sku?.name || 'Developer';
    const capacityUnits = svc.sku?.capacity ?? 1;
    const monthlyRequests = (requests / days) * 30;
    const monthlyCost = apiManagementMonthlyCost(tier, monthlyRequests) * (tier === 'Consumption' ? 1 : capacityUnits);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'API Management',
      resourceName: svc.name,
      resourceId: svc.id,
      region: svc.location,
      environment,
      team,
      tags,
      metrics: {
        requests: Math.round(requests),
        tier,
        capacityUnits,
        ...(capacityPct !== null ? { avgCapacityPct: Math.round(capacityPct * 10) / 10 } : {}),
        ...(durationMs !== null ? { avgDurationMs: Math.round(durationMs) } : {}),
      },
    };

    if (requests < thresholds.azure.apimanagement.idleRequests) {
      findings.push({
        ...base,
        priority: tier === 'Consumption' ? 'LOW' : 'HIGH',
        type: 'API_IDLE',
        details: `No requests through this gateway in the last ${days} days (${tier} tier${tier !== 'Consumption' ? `, est. $${monthlyCost.toFixed(2)}/month` : ''})`,
        recommendation: tier === 'Consumption'
          ? `Consumption tier has no fixed cost, but verify this gateway is still needed and remove it if decommissioned.`
          : `A dedicated ${tier} tier instance bills a fixed monthly fee regardless of traffic. If no APIs are actively served through it, delete it or downgrade to the Consumption tier.`,
        estimatedCurrentCost: tier === 'Consumption' ? null : parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: tier === 'Consumption' ? null : parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az apim delete --name "${svc.name}" --resource-group "${rg}" --yes`,
        suggestedAlarm: null,
      });
    } else if (capacityPct !== null && tier !== 'Consumption' && capacityUnits > 1 && capacityPct < 10) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'OVER_PROVISIONED',
        details: `Averaging ${capacityPct.toFixed(1)}% gateway capacity utilisation across ${capacityUnits} scale unit(s) — est. $${monthlyCost.toFixed(2)}/month`,
        recommendation: `Scale down the number of units on this ${tier} instance, or move to a lower tier if this level of traffic persists.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: null,
        fixCommand: `az apim update --name "${svc.name}" --resource-group "${rg}" --sku-capacity ${Math.max(1, capacityUnits - 1)}`,
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz apim update --name "${svc.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: services.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeApiManagement };
