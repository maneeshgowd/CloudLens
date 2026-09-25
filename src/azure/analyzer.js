'use strict';

// ─── Azure Analyzer ───────────────────────────────────────────────────────────
//
// Entry point for all Azure service analysers.
// Called from cloudlens.js when --provider azure is used.
//
// Credentials are passed via CLI flags:
//   --azure-subscription  Azure Subscription ID
//   --azure-tenant        Azure Tenant ID
//   --azure-client-id     Service principal client ID
//   --azure-client-secret Service principal client secret
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

const { analyzeAzureFunctions }  = require('./functions');
const { analyzeVirtualMachines } = require('./virtualmachines');
const { analyzeAppService }      = require('./appservice');
const { analyzeBlobStorage }     = require('./blobstorage');
const { analyzeCosmosDB }        = require('./cosmosdb');
const { analyzeServiceBus }      = require('./servicebus');
const { analyzeLogAnalytics }    = require('./loganalytics');
const { analyzeKeyVault }        = require('./keyvault');
const { analyzeNatGateway }      = require('./natgateway');
const { analyzeEventGrid }       = require('./eventgrid');
const { analyzeApiManagement }   = require('./apimanagement');
const { analyzeCdn }             = require('./cdn');
const { analyzeEventHubs }       = require('./eventhubs');
const { analyzeContainerApps }   = require('./containerapps');
const { analyzeSqlDatabase }     = require('./sqldatabase');
const { analyzeCertificates }    = require('./certificates');
const { analyzeAppRegistrations } = require('./appregistrations');
const { computeCostContext }     = require('./localcosts');
const { buildAzureCredential }   = require('./credentials');

// Maps user-supplied aliases → canonical service name (lowercase)
const SERVICE_ALIASES = {
  functions:          'azure functions',
  'azure-functions':  'azure functions',
  vm:                 'virtual machines',
  vms:                'virtual machines',
  'virtual-machines': 'virtual machines',
  appservice:         'app service',
  'app-service':      'app service',
  blob:               'blob storage',
  'blob-storage':     'blob storage',
  storage:            'blob storage',
  cosmos:             'cosmos db',
  cosmosdb:           'cosmos db',
  'cosmos-db':        'cosmos db',
  servicebus:         'service bus',
  'service-bus':      'service bus',
  loganalytics:       'log analytics',
  'log-analytics':    'log analytics',
  keyvault:           'key vault',
  'key-vault':        'key vault',
  kv:                 'key vault',
  natgateway:         'nat gateway',
  'nat-gateway':      'nat gateway',
  nat:                'nat gateway',
  eventgrid:          'event grid',
  'event-grid':       'event grid',
  apim:               'api management',
  apimanagement:      'api management',
  'api-management':   'api management',
  cdn:                'cdn',
  eventhubs:          'event hubs',
  'event-hubs':       'event hubs',
  eventhub:           'event hubs',
  containerapps:      'container apps',
  'container-apps':   'container apps',
  aca:                'container apps',
  sql:                'sql database',
  sqldb:              'sql database',
  sqldatabase:        'sql database',
  'sql-database':     'sql database',
  azuresql:           'sql database',
  'azure-sql':        'sql database',
  mssql:              'sql database',
  certificates:       'ssl certificates',
  certs:              'ssl certificates',
  'ssl-certificates': 'ssl certificates',
  ssl:                'ssl certificates',
  appregistrations:   'app registrations',
  'app-registrations':'app registrations',
  approg:             'app registrations',
  apps:               'app registrations',
  entra:              'app registrations',
};

async function analyzeAzure({ subscriptionId, tenantId, clientId, clientSecret, location, days, filter, exclude = [], include = [] }) {
  if (!subscriptionId) {
    throw new Error('--azure-subscription is required for Azure analysis');
  }

  const endTime   = new Date();
  const startTime = new Date(endTime.getTime() - days * 24 * 60 * 60 * 1000);
  const credential = buildAzureCredential({ tenantId, clientId, clientSecret });

  const ctx = { credential, subscriptionId, location, startTime, endTime, days, filter };

  const excluded = new Set(exclude.map(e => SERVICE_ALIASES[e] ?? e));
  const included = new Set(include.map(e => SERVICE_ALIASES[e] ?? e));

  const analysers = [
    { name: 'Azure Functions',  fn: analyzeAzureFunctions  },
    { name: 'Virtual Machines', fn: analyzeVirtualMachines },
    { name: 'App Service',      fn: analyzeAppService      },
    { name: 'Blob Storage',     fn: analyzeBlobStorage     },
    { name: 'Cosmos DB',        fn: analyzeCosmosDB        },
    { name: 'Service Bus',      fn: analyzeServiceBus      },
    { name: 'Log Analytics',    fn: analyzeLogAnalytics    },
    { name: 'Key Vault',        fn: analyzeKeyVault        },
    { name: 'NAT Gateway',      fn: analyzeNatGateway      },
    { name: 'Event Grid',       fn: analyzeEventGrid       },
    { name: 'API Management',   fn: analyzeApiManagement   },
    { name: 'CDN',              fn: analyzeCdn             },
    { name: 'Event Hubs',       fn: analyzeEventHubs       },
    { name: 'Container Apps',   fn: analyzeContainerApps   },
    { name: 'SQL Database',     fn: analyzeSqlDatabase     },
    { name: 'SSL Certificates', fn: analyzeCertificates    },
    { name: 'App Registrations', fn: analyzeAppRegistrations },
  ].filter(({ name }) => (included.size === 0 || included.has(name.toLowerCase())) && !excluded.has(name.toLowerCase()));

  const findings = [];
  let resourcesScanned = 0;
  const spendByService = {};

  for (const { name, fn } of analysers) {
    try {
      const result = await fn(ctx);
      findings.push(...result.findings);
      resourcesScanned += result.resourcesScanned;
      if (result.estimatedMonthlyCost != null && result.estimatedMonthlyCost > 0) {
        spendByService[name] = result.estimatedMonthlyCost;
      }
    } catch (err) {
      console.warn(`  [WARN] ${name} analysis failed: ${err.message}`);
    }
  }

  console.log('  Azure: analysis complete');

  correlatePipelineFindings(findings);

  const costContext = computeCostContext(findings, spendByService);

  return {
    findings,
    summary: { resourcesScanned, costContext },
  };
}

function longestCommonPrefixLength(a, b) {
  const len = Math.min(a.length, b.length);
  let i = 0;
  while (i < len && a[i] === b[i]) i++;
  return i;
}

// Cross-references idle Event Grid topics with idle downstream Azure Functions
// by name-prefix matching, upgrading both to PIPELINE_SILENT — mirrors
// src/aws/analyzer.js's EventBridge/Lambda correlatePipelineFindings.
function correlatePipelineFindings(findings) {
  const functionsIdle = findings.filter(f => f.service === 'Azure Functions' && f.type === 'IDLE');
  const egIdle         = findings.filter(f => f.service === 'Event Grid'      && f.type === 'IDLE');

  const MIN_PREFIX = 20;
  const usedFunctions = new Set();

  for (const egFinding of egIdle) {
    const topicLower = egFinding.resourceName.toLowerCase();
    let bestFn  = null;
    let bestLen = MIN_PREFIX - 1;

    for (const fnFinding of functionsIdle) {
      if (usedFunctions.has(fnFinding.resourceName)) continue;
      const fnLower = fnFinding.resourceName.toLowerCase();
      const prefLen = longestCommonPrefixLength(topicLower, fnLower);
      if (prefLen > bestLen) {
        bestLen = prefLen;
        bestFn  = fnFinding;
      }
    }

    if (bestFn) {
      usedFunctions.add(bestFn.resourceName);
      // Upgrade both to PIPELINE_SILENT and cross-reference
      egFinding.type           = 'PIPELINE_SILENT';
      egFinding.details        = `Automated pipeline completely silent — this Event Grid topic is provisioned, but zero events are reaching target function "${bestFn.resourceName}". No alarm has fired. A broken workflow that conventional monitoring did not catch.`;
      egFinding.correlatedWith = bestFn.resourceName;

      bestFn.details          += ` — its upstream Event Grid topic "${egFinding.resourceName}" is also silent. This is a broken automated pipeline, not just an idle function.`;
      bestFn.correlatedWith    = egFinding.resourceName;
    }
  }
}

module.exports = { analyzeAzure };
