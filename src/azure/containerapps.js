'use strict';

const { ContainerAppsAPIClient } = require('@azure/arm-appcontainers');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { containerAppsMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// Container Apps support scale-to-zero as an intentional feature (unlike ECS
// services, which always have a fixed desired count), so 0 running replicas
// is only a finding when the app's own minReplicas config expects at least 1.
async function analyzeContainerApps({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const caClient = new ContainerAppsAPIClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Container Apps: listing apps... ');
  const allApps = await listAll(caClient.containerApps.listBySubscription());
  let apps = allApps.filter(a => (a.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    apps = apps.filter(a => a.name.toLowerCase().includes(needle));
  }
  apps = apps.filter(a => !azureManagedPrefixes.some(p => a.name.toLowerCase().startsWith(p)));
  console.log(`${apps.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (apps.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Container Apps: fetching utilisation metrics for ${apps.length} app(s)... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, apps, ['Requests', 'RestartCount', 'Replicas', 'CpuPercentage', 'MemoryPercentage'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  apps.forEach(app => {
    const metrics = metricsMap.get(app.id) || {};
    const avgReplicas = metrics.Replicas?.avg ?? null;
    const maxReplicas = metrics.Replicas?.max ?? null;
    const avgCpu = metrics.CpuPercentage?.avg ?? null;
    const avgMem = metrics.MemoryPercentage?.avg ?? null;
    const restarts = metrics.RestartCount?.sum ?? 0;
    const requests = metrics.Requests?.sum ?? 0;

    const scale = app.template?.scale || {};
    const minReplicas = scale.minReplicas ?? 0;
    const containers = app.template?.containers || [];
    const vCpu = containers.reduce((s, c) => s + (parseFloat(c.resources?.cpu) || 0.25), 0);
    const memoryGB = containers.reduce((s, c) => {
      const mem = c.resources?.memory || '0.5Gi';
      return s + (parseFloat(mem.replace('Gi', '')) || 0.5);
    }, 0);

    const tags = app.tags || {};
    const environment = detectEnvironment(tags, app.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(app.id);
    const steadyReplicas = Math.max(minReplicas, avgReplicas ?? 0);
    const monthlyCost = containerAppsMonthlyCost(vCpu, memoryGB) * Math.max(steadyReplicas, minReplicas > 0 ? minReplicas : 1);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Container Apps',
      resourceName: app.name,
      resourceId: app.id,
      region: app.location,
      environment,
      team,
      tags,
      metrics: {
        ...(avgReplicas !== null ? { avgReplicas: parseFloat(avgReplicas.toFixed(2)) } : {}),
        ...(maxReplicas !== null ? { maxReplicas: Math.round(maxReplicas) } : {}),
        minReplicas,
        vCpu,
        memoryGB,
        ...(avgCpu !== null ? { avgCpuPct: Math.round(avgCpu) } : {}),
        ...(avgMem !== null ? { avgMemPct: Math.round(avgMem) } : {}),
        restarts: Math.round(restarts),
        requests: Math.round(requests),
      },
    };

    if (minReplicas > 0 && maxReplicas === 0) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'CA_NO_RUNNING_REPLICAS',
        details: `Configured minReplicas=${minReplicas} but 0 replicas ran in the last ${days} days — paying $${monthlyCost.toFixed(2)}/month for nothing`,
        recommendation: `Investigate why replicas are not starting (check the app's revision status and container logs via 'az containerapp logs show'). If the app is no longer needed, delete it.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az containerapp revision list --name "${app.name}" --resource-group "${rg}" -o table`,
        suggestedAlarm: null,
      });
    } else if (avgCpu !== null && avgMem !== null && (avgReplicas ?? 0) > 0
      && avgCpu < thresholds.azure.containerapps.lowCpuPct && avgMem < thresholds.azure.containerapps.lowMemPct) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'UNDERUTILISED',
        details: `Avg CPU ${Math.round(avgCpu)}%, Avg Memory ${Math.round(avgMem)}% over ${days} days — allocated ${vCpu} vCPU / ${memoryGB} GiB per replica (est. $${monthlyCost.toFixed(2)}/month)`,
        recommendation: `Reduce per-container CPU/memory allocation, or lower minReplicas if steady-state traffic doesn't need it. Container Apps bills per-replica resource allocation regardless of actual usage.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: null,
        fixCommand: `az containerapp update --name "${app.name}" --resource-group "${rg}" --cpu ${(vCpu / 2).toFixed(2)} --memory ${(memoryGB / 2).toFixed(1)}Gi`,
        suggestedAlarm: null,
      });
    }

    if (restarts > 5) {
      findings.push({
        ...base,
        priority: restarts > 20 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `${Math.round(restarts)} container restart(s) in the last ${days} days — indicates crashing or failing health probes`,
        recommendation: `Check container logs and health probe configuration ('az containerapp logs show'). Frequent restarts often point to memory limits being hit (OOMKilled) or an unhandled startup exception.`,
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz containerapp update --name "${app.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: apps.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeContainerApps };
