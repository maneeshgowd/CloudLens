'use strict';

const { CdnManagementClient } = require('@azure/arm-cdn');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { cdnMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// Classic CDN profiles/endpoints only (Front Door's separate afdEndpoints
// resource type is out of scope for v1, mirroring how src/aws/cloudfront.js
// only covers CloudFront distributions, not Global Accelerator).
async function analyzeCdn({ credential, subscriptionId, startTime, endTime, days, filter }) {
  const cdnClient = new CdnManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  CDN: listing profiles... ');
  const profiles = await listAll(cdnClient.profiles.list());

  const endpoints = [];
  for (const profile of profiles) {
    const rg = resourceGroupFromId(profile.id);
    const profileEndpoints = await listAll(cdnClient.endpoints.listByProfile(rg, profile.name));
    profileEndpoints.forEach(ep => endpoints.push({ ...ep, _profileTags: profile.tags || {}, _profileName: profile.name }));
  }

  let filtered = endpoints;
  if (filter) {
    const needle = filter.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(needle) || (e.hostName || '').toLowerCase().includes(needle));
  }
  filtered = filtered.filter(e => !azureManagedPrefixes.some(p => e.name.toLowerCase().startsWith(p)));
  console.log(`${filtered.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (filtered.length === 0) return { findings: [], resourcesScanned: 0, estimatedMonthlyCost: 0 };

  process.stdout.write(`  CDN: fetching traffic metrics for ${filtered.length} endpoints... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, filtered, ['RequestCount', 'ResponseSize', 'Percentage4XX', 'Percentage5XX'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  filtered.forEach(ep => {
    const metrics = metricsMap.get(ep.id) || {};
    const requests = metrics.RequestCount?.sum ?? 0;
    const bytesOut = metrics.ResponseSize?.sum ?? 0;
    const gbOut = bytesOut / (1024 ** 3);
    const pct4xx = metrics.Percentage4XX?.avg ?? null;
    const pct5xx = metrics.Percentage5XX?.avg ?? null;
    const tags = { ...ep._profileTags, ...(ep.tags || {}) };
    const environment = detectEnvironment(tags, ep.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(ep.id);
    const monthlyGB = (gbOut / days) * 30;
    const monthlyCost = cdnMonthlyCost(monthlyGB);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'CDN',
      resourceName: ep.hostName || ep.name,
      resourceId: ep.id,
      region: ep.location || 'global',
      environment,
      team,
      tags,
      metrics: {
        totalRequests: Math.round(requests),
        avgDailyRequests: Math.round(requests / days),
        totalDataGB: parseFloat(gbOut.toFixed(3)),
        avgDailyGB: parseFloat((gbOut / days).toFixed(3)),
        ...(pct4xx !== null ? { avgPct4xx: Math.round(pct4xx * 100) / 100 } : {}),
        ...(pct5xx !== null ? { avgPct5xx: Math.round(pct5xx * 100) / 100 } : {}),
      },
    };

    if (requests < thresholds.azure.cdn.idleRequests) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'CDN_IDLE',
        details: `0 requests in the last ${days} days — endpoint is provisioned but receiving no traffic`,
        recommendation: `Stop or delete this CDN endpoint if it is no longer in use. No requests means no data-transfer cost, but idle endpoints add operational clutter and still count toward profile limits.`,
        estimatedCurrentCost: 0,
        estimatedMonthlySavings: null,
        fixCommand: `az cdn endpoint delete --name "${ep.name}" --profile-name "${ep._profileName || ''}" --resource-group "${rg}"`,
        suggestedAlarm: null,
      });
    } else if (monthlyCost > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'CDN_ACTIVE',
        details: `${Math.round(requests).toLocaleString()} requests + ${gbOut.toFixed(2)} GB in ${days} days — est. $${monthlyCost.toFixed(2)}/month`,
        recommendation: `Review cache hit ratio and compression settings on this endpoint. A low hit rate means most requests reach the origin, increasing origin compute costs.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(4)),
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }

    if (pct5xx !== null && pct5xx > 5) {
      findings.push({
        ...base,
        priority: pct5xx > 20 ? 'HIGH' : 'MEDIUM',
        type: 'HIGH_ERROR_RATE',
        details: `Averaging ${pct5xx.toFixed(1)}% 5xx responses over the last ${days} days`,
        recommendation: `Check origin health — CDN 5xx rates usually reflect origin server errors or timeouts rather than CDN-side issues.`,
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
        recommendation: `Tag the CDN profile to enable cost allocation and ownership routing:\naz cdn profile update --name "${ep._profileName || ''}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: filtered.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeCdn };
