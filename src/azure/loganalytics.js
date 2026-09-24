'use strict';

const { OperationalInsightsManagementClient } = require('@azure/arm-operationalinsights');
const { thresholds, azureManagedPrefixes } = require('../config');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeLogAnalytics({ credential, subscriptionId, location, filter }) {
  const client = new OperationalInsightsManagementClient(credential, subscriptionId);

  process.stdout.write('  Log Analytics: listing workspaces... ');
  const allWorkspaces = await listAll(client.workspaces.list());
  let workspaces = allWorkspaces.filter(w => (w.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    workspaces = workspaces.filter(w => w.name.toLowerCase().includes(needle));
  }
  workspaces = workspaces.filter(w => !azureManagedPrefixes.some(p => w.name.toLowerCase().startsWith(p)));
  console.log(`${workspaces.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (workspaces.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];

  workspaces.forEach(ws => {
    const tags = ws.tags || {};
    const environment = detectEnvironment(tags, ws.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(ws.id);
    const retentionDays = ws.retentionInDays;
    const dailyQuotaGb = ws.workspaceCapping?.dailyQuotaGb ?? -1;

    const base = {
      provider: 'azure',
      service: 'Log Analytics',
      resourceName: ws.name,
      resourceId: ws.id,
      region: ws.location,
      environment,
      team,
      tags,
      metrics: { retentionDays, dailyQuotaGb },
    };

    // ── Excessive retention ────────────────────────────────────────────────
    if (retentionDays && retentionDays > thresholds.azure.loganalytics.retentionCeilingDays) {
      findings.push({
        ...base,
        priority: retentionDays > thresholds.azure.loganalytics.retentionCeilingDays * 2 ? 'MEDIUM' : 'LOW',
        type: 'NO_RETENTION',
        details: `Retention is set to ${retentionDays} days — beyond the recommended ${thresholds.azure.loganalytics.retentionCeilingDays}-day ceiling, driving up ingestion+retention cost`,
        recommendation: `Lower retention unless required for compliance. Consider an Archive tier or export to cheaper storage for data that must be kept longer.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az monitor log-analytics workspace update --workspace-name "${ws.name}" --resource-group "${rg}" --retention-time ${thresholds.azure.loganalytics.retentionCeilingDays}`,
        suggestedAlarm: null,
      });
    }

    // ── Unlimited daily ingestion cap ───────────────────────────────────────
    if (dailyQuotaGb === -1) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'NO_RETENTION',
        details: `No daily ingestion quota is set — a noisy log source could cause runaway ingestion cost`,
        recommendation: `Set a daily quota to cap worst-case spend from misconfigured or noisy log sources.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az monitor log-analytics workspace update --workspace-name "${ws.name}" --resource-group "${rg}" --quota <daily-gb-limit>`,
        suggestedAlarm: null,
      });
    }

    // ── Missing tags ──────────────────────────────────────────────────────
    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz monitor log-analytics workspace update --workspace-name "${ws.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: workspaces.length };
}

module.exports = { analyzeLogAnalytics };
