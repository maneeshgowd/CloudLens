'use strict';

const { NetworkManagementClient } = require('@azure/arm-network');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { natGatewayMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeNatGateway({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const networkClient = new NetworkManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  NAT Gateway: listing gateways... ');
  const allGateways = await listAll(networkClient.natGateways.listAll());
  let gateways = allGateways;
  if (filter) {
    const needle = filter.toLowerCase();
    gateways = gateways.filter(g => g.name.toLowerCase().includes(needle));
  }
  gateways = gateways.filter(g => !azureManagedPrefixes.some(p => g.name.toLowerCase().startsWith(p)));
  gateways = gateways.filter(g => matchesLocation(g.location, location));
  console.log(`${gateways.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (gateways.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  NAT Gateway: fetching traffic metrics for ${gateways.length} gateways... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, gateways, ['ByteCount', 'PacketDropCount', 'DatapathAvailability'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  gateways.forEach(gw => {
    const metrics = metricsMap.get(gw.id) || {};
    const bytes = metrics.ByteCount?.sum ?? 0;
    const packetDrops = metrics.PacketDropCount?.sum ?? 0;
    const availability = metrics.DatapathAvailability?.avg ?? null;
    const totalGB = bytes / (1024 ** 3);
    const tags = gw.tags || {};
    const environment = detectEnvironment(tags, gw.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(gw.id);
    const monthlyCost = natGatewayMonthlyCost(totalGB, days);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'NAT Gateway',
      resourceName: gw.name,
      resourceId: gw.id,
      region: gw.location,
      environment,
      team,
      tags,
      metrics: {
        totalGB: parseFloat(totalGB.toFixed(3)),
        packetDrops: Math.round(packetDrops),
        ...(availability !== null ? { availabilityPct: Math.round(availability * 100) / 100 } : {}),
      },
    };

    if (totalGB < thresholds.azure.natgateway.idleGB) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'NAT_IDLE',
        details: `Only ${totalGB.toFixed(3)} GB processed in the last ${days} days — a NAT Gateway bills a fixed hourly charge regardless of traffic (est. $${monthlyCost.toFixed(2)}/month)`,
        recommendation: `Verify which subnets still route through this NAT Gateway. If none do, delete it and detach it from its subnets to stop the hourly charge.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az network nat gateway delete --name "${gw.name}" --resource-group "${rg}"`,
        suggestedAlarm: null,
      });
    } else if (totalGB / days < thresholds.azure.natgateway.lowUtilisationGBPerDay) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'NAT_LOW_UTILISATION',
        details: `Averaging ${(totalGB / days).toFixed(2)} GB/day — low outbound traffic for a dedicated NAT Gateway (est. $${monthlyCost.toFixed(2)}/month)`,
        recommendation: `Confirm this level of traffic justifies a dedicated NAT Gateway versus consolidating with another subnet's gateway or using a lower-cost outbound method for low-volume workloads.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }

    if (availability !== null && availability < 99) {
      findings.push({
        ...base,
        priority: availability < 95 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `Datapath availability averaged ${availability.toFixed(2)}% over the last ${days} days${packetDrops > 0 ? ` — ${Math.round(packetDrops)} dropped packets` : ''}`,
        recommendation: `Investigate SNAT port exhaustion (common cause of degraded NAT Gateway availability under high connection-count workloads) or check for regional network incidents.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-natavail-${gw.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${gw.id}" \\\n  --condition "avg DatapathAvailability < 99" \\\n  --window-size 15m --evaluation-frequency 15m`,
      });
    }

    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz network nat gateway update --name "${gw.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: gateways.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeNatGateway };
