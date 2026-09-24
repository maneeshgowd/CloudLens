'use strict';

const { StorageManagementClient } = require('@azure/arm-storage');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { azureManagedPrefixes } = require('../config');
const { blobStorageMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

async function analyzeBlobStorage({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const storageClient = new StorageManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Blob Storage: listing storage accounts... ');
  const allAccounts = await listAll(storageClient.storageAccounts.list());
  let accounts = allAccounts.filter(a => (a.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    accounts = accounts.filter(a => a.name.toLowerCase().includes(needle));
  }
  accounts = accounts.filter(a => !azureManagedPrefixes.some(p => a.name.toLowerCase().startsWith(p)));
  console.log(`${accounts.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (accounts.length === 0) return { findings: [], resourcesScanned: 0 };

  // Blob capacity/count metrics live on the account's blob service sub-resource,
  // not the storage account itself — mirrors s3.js reading bucket-level CloudWatch
  // metrics rather than enumerating objects.
  const blobServiceResources = accounts.map(a => ({ id: `${a.id}/blobServices/default` }));

  process.stdout.write(`  Blob Storage: fetching capacity metrics for ${accounts.length} accounts... `);
  const metricsMap = await batchGetResourceMetrics(
    monitorClient, blobServiceResources, ['BlobCapacity', 'BlobCount'], startTime, endTime
  );
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  accounts.forEach(account => {
    const blobResId = `${account.id}/blobServices/default`;
    const metrics = metricsMap.get(blobResId) || {};
    const capacity = metrics.BlobCapacity?.avg ?? 0;
    const blobCount = metrics.BlobCount?.avg ?? 0;
    const gb = capacity / (1024 ** 3);
    const tags = account.tags || {};
    const environment = detectEnvironment(tags, account.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(account.id);
    const monthlyCost = blobStorageMonthlyCost(gb);
    totalMonthlyCost += monthlyCost;

    const base = {
      provider: 'azure',
      service: 'Blob Storage',
      resourceName: account.name,
      resourceId: account.id,
      region: account.location,
      environment,
      team,
      tags,
      metrics: { capacityGB: parseFloat(gb.toFixed(2)), blobCount: Math.round(blobCount), sku: account.sku?.name },
    };

    if (blobCount === 0 && capacity === 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'IDLE',
        details: `Storage account has no blobs and 0 bytes stored`,
        recommendation: `Delete empty storage accounts to keep your subscription tidy. Empty accounts incur minimal storage cost but add operational overhead and RBAC surface area.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az storage account delete --name "${account.name}" --resource-group "${rg}" --yes`,
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
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz storage account update --name "${account.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: accounts.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeBlobStorage };
