'use strict';

const { ComputeManagementClient } = require('@azure/arm-compute');
const { MonitorClient } = require('@azure/arm-monitor');
const { batchGetResourceMetrics } = require('./monitor');
const { thresholds, azureManagedPrefixes } = require('../config');
const { vmMonthlyCost } = require('./localcosts');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

function powerState(vm) {
  const statuses = vm.instanceView?.statuses || [];
  const status = statuses.find(s => (s.code || '').startsWith('PowerState/'));
  return status ? status.code.replace('PowerState/', '') : 'unknown';
}

async function analyzeVirtualMachines({ credential, subscriptionId, location, startTime, endTime, days, filter }) {
  const computeClient = new ComputeManagementClient(credential, subscriptionId);
  const monitorClient = new MonitorClient(credential, subscriptionId);

  process.stdout.write('  Virtual Machines: listing VMs... ');
  const allVMs = await listAll(computeClient.virtualMachines.listAll());
  let vms = allVMs.filter(vm => (vm.location || '').toLowerCase() === location.toLowerCase());
  if (filter) {
    const needle = filter.toLowerCase();
    vms = vms.filter(vm => vm.name.toLowerCase().includes(needle));
  }
  vms = vms.filter(vm => !azureManagedPrefixes.some(p => vm.name.toLowerCase().startsWith(p)));
  console.log(`${vms.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (vms.length === 0) return { findings: [], resourcesScanned: 0 };

  process.stdout.write(`  Virtual Machines: fetching instance views for ${vms.length} VMs... `);
  const instanceViews = await Promise.all(vms.map(vm => {
    const rg = resourceGroupFromId(vm.id);
    return computeClient.virtualMachines.get(rg, vm.name, { expand: 'instanceView' }).catch(() => vm);
  }));
  console.log('done');

  const running = instanceViews.filter(vm => powerState(vm) === 'running');

  process.stdout.write(`  Virtual Machines: fetching CPU metrics for ${running.length} running VMs... `);
  const metricsMap = await batchGetResourceMetrics(monitorClient, running, ['Percentage CPU'], startTime, endTime);
  console.log('done');

  const findings = [];
  let totalMonthlyCost = 0;

  instanceViews.forEach(vm => {
    const state = powerState(vm);
    const size = vm.hardwareProfile?.vmSize || 'unknown';
    const tags = vm.tags || {};
    const environment = detectEnvironment(tags, vm.name);
    const team = detectTeam(tags);
    const monthlyCost = vmMonthlyCost(size);
    const rg = resourceGroupFromId(vm.id);

    const base = {
      provider: 'azure',
      service: 'Virtual Machines',
      resourceName: vm.name,
      resourceId: vm.id,
      region: vm.location,
      environment,
      team,
      tags,
      metrics: { vmSize: size, powerState: state },
    };

    if (state === 'stopped') {
      // "Stopped" (not deallocated) still reserves compute capacity and bills for it —
      // only "deallocated" actually stops compute charges.
      totalMonthlyCost += monthlyCost;
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'STOPPED_NOT_DEALLOCATED',
        details: `VM is stopped but not deallocated — still incurring compute charges (est. $${monthlyCost.toFixed(2)}/month)`,
        recommendation: `Deallocate the VM to stop compute billing, or delete it if no longer needed. A merely "stopped" VM still reserves its compute capacity.`,
        estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
        estimatedMonthlySavings: parseFloat(monthlyCost.toFixed(2)),
        fixCommand: `az vm deallocate --name "${vm.name}" --resource-group "${rg}"\n# Or, if no longer needed:\naz vm delete --name "${vm.name}" --resource-group "${rg}" --yes`,
        suggestedAlarm: null,
      });
    } else if (state === 'deallocated') {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'IDLE',
        details: `VM is deallocated — no compute charges, but attached managed disks and reserved public IPs (if any) continue to bill`,
        recommendation: `If this VM is no longer needed, delete it along with its managed disks and any reserved public IPs to stop residual storage/networking charges.`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: `az vm delete --name "${vm.name}" --resource-group "${rg}" --yes\n# Add --force-deletion true to also remove attached disks and NICs`,
        suggestedAlarm: null,
      });
    } else if (state === 'running') {
      totalMonthlyCost += monthlyCost;
      const cpu = metricsMap.get(vm.id)?.['Percentage CPU']?.avg ?? null;
      base.metrics.avgCpuPct = cpu !== null ? Math.round(cpu * 10) / 10 : null;

      if (cpu !== null && cpu < thresholds.azure.vm.lowCpuPct) {
        findings.push({
          ...base,
          priority: cpu < thresholds.azure.vm.veryLowCpuPct ? 'HIGH' : 'MEDIUM',
          type: 'OVER_ALLOCATED',
          details: `Average CPU utilisation is only ${cpu.toFixed(1)}% over the last ${days} days — sized as ${size} ($${monthlyCost.toFixed(2)}/month)`,
          recommendation: `Resize to a smaller VM size, or stop/deallocate if this VM is no longer actively used.`,
          estimatedCurrentCost: parseFloat(monthlyCost.toFixed(2)),
          estimatedMonthlySavings: null,
          fixCommand: `az vm resize --name "${vm.name}" --resource-group "${rg}" --size <smaller-size>\n# Run 'az vm list-vm-resize-options --location ${vm.location}' to see available sizes`,
          suggestedAlarm: `az monitor metrics alert create \\\n  --name "cloudlens-lowcpu-${vm.name.substring(0, 50)}" \\\n  --resource-group "${rg}" \\\n  --scopes "${vm.id}" \\\n  --condition "avg Percentage CPU < ${thresholds.azure.vm.lowCpuPct}" \\\n  --window-size 1d --evaluation-frequency 1d`,
        });
      }
    }

    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz vm update --name "${vm.name}" --resource-group "${rg}" --set tags.Environment=${environment} tags.Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: vms.length, estimatedMonthlyCost: parseFloat(totalMonthlyCost.toFixed(4)) };
}

module.exports = { analyzeVirtualMachines };
