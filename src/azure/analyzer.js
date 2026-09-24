'use strict';

// ─── Azure Analyzer ───────────────────────────────────────────────────────────
//
// Entry point for all Azure service analysers.
// Called from cloudlens.js when --provider azure or --provider all is used.
//
// Credentials are passed via CLI flags:
//   --azure-subscription  Azure Subscription ID
//   --azure-tenant        Azure Tenant ID
//   --azure-client-id     Service principal client ID
//   --azure-client-secret Service principal client secret
//
// Each service analyser must return:
//   {
//     findings:            Finding[],   // see shape below
//     resourcesScanned:    number,
//     estimatedMonthlyCost?: number,    // optional
//   }
//
// ─── Finding shape (must match AWS findings exactly) ─────────────────────────
//   {
//     provider:     'azure',
//     service:      string,           // e.g. 'Azure Functions', 'Virtual Machines'
//     resourceName: string,
//     resourceId:   string,           // full Azure resource ID or name
//     region:       string,           // Azure location, e.g. 'eastus'
//     priority:     'HIGH' | 'MEDIUM' | 'LOW',
//     type:         string,           // e.g. 'IDLE', 'OVER_ALLOCATED', 'DEPRECATED_RUNTIME'
//     details:      string,
//     recommendation: string,
//     metrics:      object,
//     estimatedCurrentCost:    number | null,
//     estimatedMonthlySavings: number | null,
//     suggestedAlarm:          string | null,  // az monitor metrics alert create ...
//     environment:  string | null,    // prod | dev | tst — read from Azure tags
//     team:         string | null,    // e.g. 'Owner: John Smith'
//     tags:         object,
//   }
//
// ─── Services to implement ────────────────────────────────────────────────────
//   Azure Functions  — idle functions, deprecated runtimes (node 14, python 3.8)
//   Virtual Machines — stopped/deallocated VMs still incurring storage costs
//   App Service      — idle app service plans with no traffic
//   Blob Storage     — large containers with no access in N days
//   Cosmos DB        — provisioned throughput (RU/s) with low utilisation
//   Service Bus      — idle queues/topics
//   Log Analytics    — workspaces with no retention policy or excessive retention
//   Azure Monitor    — missing alerts on critical resources
//
// ─── Suggested Azure SDK packages ────────────────────────────────────────────
//   @azure/arm-resources        — list subscriptions, resource groups
//   @azure/arm-compute          — VMs, disks
//   @azure/arm-web              — App Service, Azure Functions
//   @azure/arm-storage          — Blob Storage
//   @azure/arm-cosmosdb         — Cosmos DB
//   @azure/arm-servicebus       — Service Bus
//   @azure/arm-monitor          — Azure Monitor metrics + alerts
//   @azure/arm-operationalinsights — Log Analytics
//   @azure/identity             — DefaultAzureCredential / ClientSecretCredential

// const { analyzeAzureFunctions }  = require('./functions');
// const { analyzeVirtualMachines } = require('./virtualmachines');
// const { analyzeAppService }      = require('./appservice');
// const { analyzeBlobStorage }     = require('./blobstorage');
// const { analyzeCosmosDB }        = require('./cosmosdb');
// const { analyzeServiceBus }      = require('./servicebus');
// const { analyzeLogAnalytics }    = require('./loganalytics');

async function analyzeAzure({ subscriptionId, tenantId, clientId, clientSecret, location, days, filter, exclude = [] }) {
  if (!subscriptionId) {
    throw new Error('--azure-subscription is required for Azure analysis');
  }

  const findings = [];
  let resourcesScanned = 0;

  // ── Uncomment each block as you implement the analyser ───────────────────

  // try {
  //   const result = await analyzeAzureFunctions({ subscriptionId, tenantId, clientId, clientSecret, location, days, filter });
  //   findings.push(...result.findings);
  //   resourcesScanned += result.resourcesScanned;
  // } catch (err) {
  //   console.warn(`  [WARN] Azure Functions analysis failed: ${err.message}`);
  // }

  // try {
  //   const result = await analyzeVirtualMachines({ subscriptionId, tenantId, clientId, clientSecret, location, days, filter });
  //   findings.push(...result.findings);
  //   resourcesScanned += result.resourcesScanned;
  // } catch (err) {
  //   console.warn(`  [WARN] Virtual Machines analysis failed: ${err.message}`);
  // }

  // try {
  //   const result = await analyzeBlobStorage({ subscriptionId, tenantId, clientId, clientSecret, location, days, filter });
  //   findings.push(...result.findings);
  //   resourcesScanned += result.resourcesScanned;
  // } catch (err) {
  //   console.warn(`  [WARN] Blob Storage analysis failed: ${err.message}`);
  // }

  console.log('  Azure: analysis complete');

  return {
    findings,
    summary: { resourcesScanned, costContext: null },
  };
}

module.exports = { analyzeAzure };
