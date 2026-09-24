'use strict';

const { KeyVaultManagementClient } = require('@azure/arm-keyvault');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { keyVaultMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// Key Vault's management-plane API exposes vault-level config (soft delete,
// purge protection, network ACLs) but not secret/key contents — reading those
// requires separate data-plane RBAC we don't request. Findings here are based
// on vault-level Monitor metrics + configuration, not literal secret access
// (unlike src/aws/secretsmanager.js, which reads per-secret LastAccessedDate).
async function analyzeKeyVault({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const kvClient = new KeyVaultManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Key Vault: listing vaults... ');
  const allVaults = await listAll(kvClient.vaults.listBySubscription());
  let vaults = allVaults.filter(v => (v.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    vaults = vaults.filter(v => v.name.toLowerCase().includes(needle));
  }
  vaults = vaults.filter(v => !azureManagedPrefixes.some(p => v.name.toLowerCase().startsWith(p)));
  console.log(`${vaults.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (vaults.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Key Vault: fetching usage metrics for ${vaults.length} vaults... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, vaults, ['ServiceApiHit', 'ServiceApiResult', 'Availability'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  vaults.forEach(vault => {
    const metrics = metricsMap.get(vault.id) || {};
    const apiHits = metrics.ServiceApiHit?.sum ?? 0;
    const availability = metrics.Availability?.avg ?? null;
    const tags = vault.tags || {};
    const environment = detectEnvironment(tags, vault.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(vault.id);
    const monthlyOps = (apiHits / days) * 30;
    const monthlyCost = keyVaultMonthlyCost(monthlyOps);
    totalMonthlyCost += monthlyCost;

    const props = vault.properties || {};
    const softDeleteEnabled = props.enableSoftDelete !== false; // defaults to true on modern API versions
    const purgeProtectionEnabled = props.enablePurgeProtection === true;
    const defaultAction = props.networkAcls?.defaultAction || 'Allow';
    const publicNetworkAccess = (props.publicNetworkAccess || 'Enabled').toLowerCase();

    const base = {
      provider: 'azure',
      service: 'Key Vault',
      resourceName: vault.name,
      resourceId: vault.id,
      region: vault.location,
      environment,
      team,
      tags,
      metrics: {
        apiHits: Math.round(apiHits),
        ...(availability !== null ? { availabilityPct: Math.round(availability * 100) / 100 } : {}),
        softDeleteEnabled,
        purgeProtectionEnabled,
        networkDefaultAction: defaultAction,
      },
    };

    // ── Idle vault ──────────────────────────────────────────────────────────
    if (apiHits < thresholds.azure.keyvault.idleApiHits) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'IDLE',
        details: `No API operations (secret/key/certificate access) in the last ${days} days`,
        recommendation: `Verify whether this vault is still referenced by any application or pipeline. If decommissioned, delete it — but note vaults are soft-deleted by default and continue to count toward quota until purged.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az keyvault delete --name "${vault.name}" --resource-group "${rg}"\naz keyvault purge --name "${vault.name}" --location "${vault.location}"  # if purge protection is off`,
        suggestedAlarm: null,
      });
    }

    // ── No soft delete ─────────────────────────────────────────────────────
    if (!softDeleteEnabled) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'KV_NO_SOFT_DELETE',
        details: `Soft delete is disabled — an accidental or malicious deletion of this vault (and every secret/key/certificate in it) is unrecoverable`,
        recommendation: `Enable soft delete. Azure now enforces this on new vaults, but older vaults can still have it off. This is required before purge protection can be enabled.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az keyvault update --name "${vault.name}" --resource-group "${rg}" --enable-soft-delete true`,
        suggestedAlarm: null,
      });
    }

    // ── No purge protection ────────────────────────────────────────────────
    if (softDeleteEnabled && !purgeProtectionEnabled) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'KV_NO_PURGE_PROTECTION',
        details: `Purge protection is disabled — anyone with delete permissions can permanently purge this vault during the soft-delete retention window, bypassing recovery`,
        recommendation: `Enable purge protection so a deleted vault can only be permanently removed after its retention period expires, giving you a recovery window against malicious or accidental purges.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az keyvault update --name "${vault.name}" --resource-group "${rg}" --enable-purge-protection true`,
        suggestedAlarm: null,
      });
    }

    // ── Open network access ────────────────────────────────────────────────
    if (defaultAction.toLowerCase() === 'allow' && publicNetworkAccess !== 'disabled') {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'KV_PUBLIC_ACCESS',
        details: `Network ACLs default action is "Allow" — this vault is reachable from any public IP unless a firewall rule narrows it`,
        recommendation: `Restrict access with a virtual network service endpoint or private endpoint, and set the network ACL default action to "Deny" with explicit allow-listed ranges.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az keyvault update --name "${vault.name}" --resource-group "${rg}" --default-action Deny`,
        suggestedAlarm: null,
      });
    }

    // ── Missing tags ────────────────────────────────────────────────────────
    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz keyvault update --name "${vault.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: vaults.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeKeyVault };
