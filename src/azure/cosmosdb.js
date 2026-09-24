'use strict';

const { CosmosDBManagementClient } = require('@azure/arm-cosmosdb');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { cosmosMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeCosmosDB({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const cosmosClient = new CosmosDBManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Cosmos DB: listing accounts... ');
  const allAccounts = await listAll(cosmosClient.databaseAccounts.list());
  let accounts = allAccounts;
  if (filter) {
    const needle = filter.toLowerCase();
    accounts = accounts.filter(a => a.name.toLowerCase().includes(needle));
  }
  accounts = accounts.filter(a => !azureManagedPrefixes.some(p => a.name.toLowerCase().startsWith(p)));
  accounts = accounts.filter(a => matchesLocation(a.location, location));
  console.log(`${accounts.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (accounts.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Cosmos DB: fetching usage metrics for ${accounts.length} accounts... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, accounts, ['TotalRequests', 'NormalizedRUConsumption', 'ProvisionedThroughput'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  accounts.forEach(account => {
    const metrics = metricsMap.get(account.id) || {};
    const totalRequests = metrics.TotalRequests?.sum ?? 0;
    const ruUtilPct = metrics.NormalizedRUConsumption?.avg ?? null;
    const provisionedRU = metrics.ProvisionedThroughput?.avg ?? 0;
    const tags = account.tags || {};
    const environment = detectEnvironment(tags, account.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(account.id);
    const monthlyCost = cosmosMonthlyCost(provisionedRU);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Cosmos DB',
      resourceName: account.name,
      resourceId: account.id,
      region: account.location,
      environment,
      team,
      tags,
      metrics: {
        totalRequests: Math.round(totalRequests),
        ...(ruUtilPct !== null ? { ruUtilisationPct: Math.round(ruUtilPct) } : {}),
        provisionedRU: Math.round(provisionedRU),
      },
    };

    if (totalRequests === 0) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'IDLE',
        details: `Zero requests in the last ${days} days — est. $${monthlyCost.toFixed(2)}/month of provisioned throughput unused`,
        recommendation: `Verify this account is still needed. If decommissioned, delete it. If still needed but idle, consider switching to serverless capacity mode.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az cosmosdb delete --name "${account.name}" --resource-group "${rg}" --yes`,
        suggestedAlarm: null,
      });
    } else if (ruUtilPct !== null && ruUtilPct < thresholds.azure.cosmos.overProvisionedRatio * 100) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'OVER_PROVISIONED',
        details: `Using only ${Math.round(ruUtilPct)}% of provisioned RU/s — paying $${monthlyCost.toFixed(2)}/month for mostly idle throughput`,
        recommendation: `Reduce provisioned throughput to match actual usage, or switch to autoscale/serverless capacity mode.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat((monthlyCost * (1 - ruUtilPct / 100)).toFixed(2)),
        fixCommand: `az cosmosdb update --name "${account.name}" --resource-group "${rg}" --capabilities EnableServerless\n# Or lower provisioned throughput on the affected database/container.`,
        suggestedAlarm: null,
      });
    } else if (ruUtilPct !== null && ruUtilPct < thresholds.azure.cosmos.underutilisedRatio * 100) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'OVER_PROVISIONED',
        details: `Using ${Math.round(ruUtilPct)}% of provisioned RU/s — $${monthlyCost.toFixed(2)}/month provisioned`,
        recommendation: `Consider autoscale throughput with a lower ceiling to reduce cost while retaining headroom.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz cosmosdb update --name "${account.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: accounts.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeCosmosDB };
