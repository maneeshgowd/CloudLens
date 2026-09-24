'use strict';

const { SqlManagementClient } = require('@azure/arm-sql');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { sqlDatabaseMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

// DTU-based service tiers report utilisation via dtu_consumption_percent; vCore-based
// tiers (General Purpose / Business Critical / Hyperscale) have no DTU metric and use
// cpu_percent as the closest utilisation proxy instead.
const DTU_TIERS = new Set(['Basic', 'Standard', 'Premium']);

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeSqlDatabase({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const sqlClient = new SqlManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  SQL Database: listing servers... ');
  const allServers = await listAll(sqlClient.servers.list());
  const servers = allServers.filter(s => matchesLocation(s.location, location));
  console.log(`${servers.length} found`);

  process.stdout.write(`  SQL Database: listing databases across ${servers.length} servers... `);
  const perServerDatabases = await Promise.all(
    servers.map(server => {
      const rg = resourceGroupFromId(server.id);
      return listAll(sqlClient.databases.listByServer(rg, server.name)).catch(() => []);
    })
  );
  let databases = perServerDatabases.flat().filter(db => db.name !== 'master');
  if (filter) {
    const needle = filter.toLowerCase();
    databases = databases.filter(db => db.name.toLowerCase().includes(needle));
  }
  databases = databases.filter(db => !azureManagedPrefixes.some(p => db.name.toLowerCase().startsWith(p)));
  console.log(`${databases.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (databases.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  SQL Database: fetching usage metrics for ${databases.length} databases... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, databases, ['cpu_percent', 'dtu_consumption_percent', 'connection_successful'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  databases.forEach(db => {
    const metrics = metricsMap.get(db.id) || {};
    const connections = metrics.connection_successful?.sum ?? 0;
    const isDtuTier = DTU_TIERS.has(db.sku?.tier);
    const utilPct = isDtuTier ? metrics.dtu_consumption_percent?.avg ?? null : metrics.cpu_percent?.avg ?? null;
    const tags = db.tags || {};
    const environment = detectEnvironment(tags, db.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(db.id);
    const serverName = db.id.match(/servers\/([^/]+)\/databases/i)?.[1] || '?';
    const monthlyCost = sqlDatabaseMonthlyCost(db);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'SQL Database',
      resourceName: `${serverName}/${db.name}`,
      resourceId: db.id,
      region: db.location,
      environment,
      team,
      tags,
      metrics: {
        connections: Math.round(connections),
        ...(utilPct !== null ? { [isDtuTier ? 'dtuUtilisationPct' : 'cpuUtilisationPct']: Math.round(utilPct) } : {}),
        tier: db.sku?.tier || 'unknown',
        serviceObjective: db.currentServiceObjectiveName || db.sku?.name || 'unknown',
      },
    };

    if (connections === 0) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'IDLE',
        details: `Zero successful connections in the last ${days} days — est. $${monthlyCost.toFixed(2)}/month for an unused database`,
        recommendation: `Verify this database is still needed. If decommissioned, delete it. If still needed but idle, scale down to a lower service objective.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az sql db delete --name "${db.name}" --server "${serverName}" --resource-group "${rg}" --yes`,
        suggestedAlarm: null,
      });
    } else if (utilPct !== null && utilPct < thresholds.azure.sql.overProvisionedRatio * 100) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'OVER_PROVISIONED',
        details: `Using only ${Math.round(utilPct)}% of provisioned ${isDtuTier ? 'DTU' : 'vCore CPU'} capacity — paying $${monthlyCost.toFixed(2)}/month for mostly idle compute`,
        recommendation: `Scale down to a lower service objective (e.g. via az sql db update --service-objective) to match actual usage.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat((monthlyCost * (1 - utilPct / 100)).toFixed(2)),
        fixCommand: `az sql db update --name "${db.name}" --server "${serverName}" --resource-group "${rg}" --service-objective <smaller-tier>`,
        suggestedAlarm: null,
      });
    } else if (utilPct !== null && utilPct < thresholds.azure.sql.underutilisedRatio * 100) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'OVER_PROVISIONED',
        details: `Using ${Math.round(utilPct)}% of provisioned ${isDtuTier ? 'DTU' : 'vCore CPU'} capacity — $${monthlyCost.toFixed(2)}/month provisioned`,
        recommendation: `Consider a smaller service objective, or move to a serverless/elastic pool tier to reduce cost while retaining headroom.`,
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz sql db update --name "${db.name}" --server "${serverName}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: databases.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeSqlDatabase };
