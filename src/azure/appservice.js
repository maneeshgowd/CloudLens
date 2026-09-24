'use strict';

const { WebSiteManagementClient } = require('@azure/arm-appservice');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { azureManagedPrefixes } = require('../config');
const { appServicePlanMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeAppService({ credential, subscriptionId, startTime, endTime, days, filter, location }) {
  const webClient = new WebSiteManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  App Service: listing plans... ');
  const allPlans = await listAll(webClient.appServicePlans.list());
  let plans = allPlans;
  if (filter) {
    const needle = filter.toLowerCase();
    plans = plans.filter(p => p.name.toLowerCase().includes(needle));
  }
  plans = plans.filter(p => !azureManagedPrefixes.some(pre => p.name.toLowerCase().startsWith(pre)));
  plans = plans.filter(p => matchesLocation(p.location, location));
  console.log(`${plans.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (plans.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write('  App Service: listing web apps... ');
  const allApps = await listAll(webClient.webApps.list());
  const allAppsFiltered = allApps.filter(a => matchesLocation(a.location, location));
  const webApps = allAppsFiltered.filter(a => !(a.kind || '').toLowerCase().includes('functionapp'));
  console.log(`${webApps.length} found`);

  // Count ALL apps (web apps + function apps) per plan so a plan hosting only a
  // function app isn't mistaken for having "no deployed apps" — function apps are
  // analyzed separately (src/azure/functions.js) but they still occupy the plan.
  const appsByPlan = new Map();
  const webAppsByPlan = new Map();
  for (const app of allAppsFiltered) {
    if (!app.serverFarmId) continue;
    const list = appsByPlan.get(app.serverFarmId) || [];
    list.push(app);
    appsByPlan.set(app.serverFarmId, list);

    if (!(app.kind || '').toLowerCase().includes('functionapp')) {
      const webList = webAppsByPlan.get(app.serverFarmId) || [];
      webList.push(app);
      webAppsByPlan.set(app.serverFarmId, webList);
    }
  }

  process.stdout.write(`  App Service: fetching request metrics for ${webApps.length} apps... `);
  const metricsMap = await batchGetResourceMetrics(monitorClient, webApps, ['Requests'], startTime, endTime);
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  plans.forEach(plan => {
    const tier = plan.sku?.tier || 'Basic';
    const monthlyCost = appServicePlanMonthlyCost(tier);
    const tags = plan.tags || {};
    const environment = detectEnvironment(tags, plan.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(plan.id);
    const appsInPlan = appsByPlan.get(plan.id) || [];
    const webAppsInPlan = webAppsByPlan.get(plan.id) || [];
    // Azure's own plan.numberOfSites can be stale/lagging (observed returning 0 for
    // plans with live apps) — trust whichever count is higher between it and what we
    // actually found by listing apps and matching serverFarmId to this plan.
    const numberOfSites = Math.max(plan.numberOfSites || 0, appsInPlan.length);
    const isFree = tier === 'Free' || tier === 'Shared';

    if (!isFree) totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'App Service',
      resourceName: plan.name,
      resourceId: plan.id,
      region: plan.location,
      environment,
      team,
      tags,
      metrics: { tier, numberOfSites },
    };

    // ── Billed plan with no deployed apps ────────────────────────────────
    if (numberOfSites === 0 && !isFree) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'IDLE',
        details: `App Service Plan (${tier}) has no deployed apps but is still billed at ~$${monthlyCost.toFixed(2)}/month`,
        recommendation: `Delete this unused plan, or scale it down if you plan to deploy apps to it soon.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az appservice plan delete --name "${plan.name}" --resource-group "${rg}" --yes`,
        suggestedAlarm: null,
      });
    }

    // ── Idle web apps within this plan ───────────────────────────────────
    // A stopped/disabled app with zero requests is genuinely not in use — IDLE,
    // with a delete recommendation. A running app with zero requests is still
    // deployed and reachable, so it's LOW_ACTIVITY: no delete suggestion, and any
    // cost-saving angle is a plan-tier degrade (shared across apps), not deletion.
    webAppsInPlan.forEach(app => {
      const requests = metricsMap.get(app.id)?.Requests?.sum ?? 0;
      if (requests !== 0) return;

      const isStopped = app.enabled === false || (app.state && app.state !== 'Running');
      const appTags = app.tags || {};
      findings.push({
        provider: 'azure',
        service: 'App Service',
        resourceName: app.name,
        resourceId: app.id,
        region: app.location,
        environment: detectEnvironment(appTags, app.name),
        team: detectTeam(appTags),
        tags: appTags,
        priority: isStopped ? 'MEDIUM' : 'LOW',
        type: isStopped ? 'IDLE' : 'LOW_ACTIVITY',
        details: isStopped
          ? `App is stopped/disabled with no requests in the last ${days} days (plan: ${plan.name}, ${tier})`
          : `No requests in the last ${days} days, but the app is still running (plan: ${plan.name}, ${tier})`,
        recommendation: isStopped
          ? `Verify whether this app is still needed. If decommissioned, delete it and consider scaling down or deleting the plan if it was the only app on it.`
          : `This app is running but received no requests. Confirm it's still needed — if every app on plan "${plan.name}" (${tier}) is similarly low-traffic, consider degrading the plan to a lower tier rather than deleting an app that's still deployed and enabled.`,
        metrics: { requests: 0, plan: plan.name, tier, appState: isStopped ? (app.state || 'Stopped') : 'Running' },
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: isStopped
          ? `az webapp delete --name "${app.name}" --resource-group "${resourceGroupFromId(app.id)}"`
          : null,
        suggestedAlarm: null,
      });
    });

    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz appservice plan update --name "${plan.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return {
    findings,
    resourcesScanned: plans.length + webApps.length,
    estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)),
  };
}

module.exports = { analyzeAppService };
