'use strict';

// Azure public retail pricing (East US, pay-as-you-go), as of Sep 2026.
// Estimating from these constants avoids requiring Cost Management RBAC —
// mirrors the approach in src/aws/localcosts.js.
const PRICING = {
  functions: {
    perGBSecond: 0.000016,
    perMillionExecutions: 0.20,
  },
  vm: {
    // Hourly, common sizes. Anything not listed falls back to `fallbackHourly`.
    sizes: {
      Standard_B1s: 0.0104,
      Standard_B1ms: 0.0207,
      Standard_B2s: 0.0416,
      Standard_B2ms: 0.0832,
      Standard_B4ms: 0.166,
      Standard_D2s_v3: 0.096,
      Standard_D4s_v3: 0.192,
      Standard_D2s_v5: 0.096,
      Standard_D4s_v5: 0.192,
      Standard_F2s_v2: 0.085,
      Standard_F4s_v2: 0.169,
      Standard_E2s_v3: 0.126,
      Standard_A1_v2: 0.043,
      Standard_A2_v2: 0.086,
    },
    fallbackHourly: 0.10,
  },
  appServicePlan: {
    // Hourly, by SKU tier.
    tiers: {
      Free: 0,
      Shared: 0.015,
      Basic: 0.018,
      Standard: 0.10,
      PremiumV2: 0.146,
      PremiumV3: 0.198,
      Isolated: 0.30,
      IsolatedV2: 0.30,
    },
    fallbackHourly: 0.05,
  },
  blob: {
    hotPerGBMonth: 0.0184,
  },
  cosmos: {
    perRUHour: 0.00008, // $0.008 per 100 RU/s-hour
  },
  serviceBus: {
    standardNamespaceMonthly: 9.81,
    premiumNamespaceMonthly: 668.00,
  },
  keyVault: {
    perTenThousandOps: 0.03, // Standard tier: $0.03 per 10,000 operations
  },
  natGateway: {
    perHour: 0.045,
    perGB: 0.045,
  },
  eventGrid: {
    perMillionOps: 0.60,
  },
  apiManagement: {
    // Hourly, by tier (Consumption is per-call and handled separately).
    tiers: {
      Consumption: 0,
      Developer: 0.073,
      Basic: 0.211,
      Standard: 0.926,
      Premium: 3.701,
    },
    consumptionPerMillionCalls: 3.50,
    fallbackHourly: 0.211,
  },
  cdn: {
    perGB: 0.081,
  },
  eventHubs: {
    // Hourly, per throughput unit / processing unit (Standard tier).
    perThroughputUnitHour: 0.03,
    basicPerMillionEvents: 0.028,
  },
  containerApps: {
    perVCpuHour: 0.000024 * 3600, // active usage charge, vCPU-second billing normalised to hourly
    perGBHour: 0.000003 * 3600,   // memory GiB-second billing normalised to hourly
  },
  sqlDatabase: {
    // DTU-based (Basic/Standard/Premium) single databases — flat monthly rate by SKU name.
    dtuMonthly: {
      Basic: 4.90,
      S0: 15, S1: 30, S2: 75, S3: 150, S4: 300, S6: 600, S7: 1200, S9: 2400, S12: 4800,
      P1: 465, P2: 930, P4: 1860, P6: 3720, P11: 7000, P15: 9509,
    },
    // vCore-based purchasing model — hourly rate per vCore, by service tier.
    vCoreHourly: {
      GeneralPurpose: 0.196,
      BusinessCritical: 0.507,
      Hyperscale: 0.244,
    },
    fallbackMonthly: 15,
  },
};

function vmMonthlyCost(vmSize) {
  const hourly = PRICING.vm.sizes[vmSize] ?? PRICING.vm.fallbackHourly;
  return hourly * 24 * 30;
}

function appServicePlanMonthlyCost(tier) {
  const hourly = PRICING.appServicePlan.tiers[tier] ?? PRICING.appServicePlan.fallbackHourly;
  return hourly * 24 * 30;
}

function functionsMonthlyCost(monthlyExecutions, avgDurationMs = 200, memoryGB = 0.5) {
  const gbSeconds = memoryGB * (avgDurationMs / 1000) * monthlyExecutions;
  return gbSeconds * PRICING.functions.perGBSecond
       + (monthlyExecutions / 1e6) * PRICING.functions.perMillionExecutions;
}

function blobStorageMonthlyCost(gb) {
  return gb * PRICING.blob.hotPerGBMonth;
}

function cosmosMonthlyCost(provisionedRU) {
  return provisionedRU * PRICING.cosmos.perRUHour * 24 * 30;
}

function serviceBusMonthlyCost(tier) {
  if (tier === 'Premium') return PRICING.serviceBus.premiumNamespaceMonthly;
  if (tier === 'Standard') return PRICING.serviceBus.standardNamespaceMonthly;
  return 0; // Basic tier is usage-based with a negligible fixed cost
}

function keyVaultMonthlyCost(monthlyOperations) {
  return (monthlyOperations / 10000) * PRICING.keyVault.perTenThousandOps;
}

function natGatewayMonthlyCost(totalGB, days) {
  const monthlyHourly = PRICING.natGateway.perHour * 720;
  const monthlyGB = (totalGB / Math.max(1, days)) * 30 * PRICING.natGateway.perGB;
  return monthlyHourly + monthlyGB;
}

function eventGridMonthlyCost(monthlyOperations) {
  return (monthlyOperations / 1e6) * PRICING.eventGrid.perMillionOps;
}

function apiManagementMonthlyCost(tier, monthlyCalls = 0) {
  if (tier === 'Consumption') {
    return (monthlyCalls / 1e6) * PRICING.apiManagement.consumptionPerMillionCalls;
  }
  const hourly = PRICING.apiManagement.tiers[tier] ?? PRICING.apiManagement.fallbackHourly;
  return hourly * 24 * 30;
}

function cdnMonthlyCost(gb) {
  return gb * PRICING.cdn.perGB;
}

function eventHubsMonthlyCost(tier, throughputUnits = 1, monthlyEvents = 0) {
  if (tier === 'Basic') return (monthlyEvents / 1e6) * PRICING.eventHubs.basicPerMillionEvents;
  return throughputUnits * PRICING.eventHubs.perThroughputUnitHour * 24 * 30;
}

function containerAppsMonthlyCost(vCpu, memoryGB) {
  return (vCpu * PRICING.containerApps.perVCpuHour + memoryGB * PRICING.containerApps.perGBHour) * 24 * 30;
}

// database: the Database resource from @azure/arm-sql (needs sku.name, sku.tier, sku.capacity, elasticPoolId).
// Elastic-pool members are billed as part of the pool, not per-database, so they cost 0 here to avoid double counting.
function sqlDatabaseMonthlyCost(database) {
  if (database.elasticPoolId) return 0;

  const sku = database.sku || {};
  if (sku.name && PRICING.sqlDatabase.dtuMonthly[sku.name] != null) {
    return PRICING.sqlDatabase.dtuMonthly[sku.name];
  }

  const vCoreRate = PRICING.sqlDatabase.vCoreHourly[sku.tier];
  if (vCoreRate && sku.capacity) {
    return vCoreRate * sku.capacity * 24 * 30;
  }

  return PRICING.sqlDatabase.fallbackMonthly;
}

// Same shape/logic as src/aws/localcosts.js's computeCostContext, kept as a
// separate instance since Azure spend is summed independently of AWS.
function computeCostContext(findings, spendByService = {}) {
  let totalSavings = 0;
  for (const f of findings) {
    if (f.estimatedMonthlySavings > 0) totalSavings += f.estimatedMonthlySavings;
  }

  const totalSpend = Object.values(spendByService).reduce((a, b) => a + b, 0);

  return {
    totalEstimatedCost: totalSpend,
    totalPotentialSavings: totalSavings,
    topServices: Object.entries(spendByService)
      .map(([service, amount]) => ({ service, amount: parseFloat(amount.toFixed(2)) }))
      .sort((a, b) => b.amount - a.amount),
    source: 'Estimated from Azure Monitor metrics · Azure public pricing (East US)',
  };
}

module.exports = {
  PRICING,
  vmMonthlyCost,
  appServicePlanMonthlyCost,
  functionsMonthlyCost,
  blobStorageMonthlyCost,
  cosmosMonthlyCost,
  serviceBusMonthlyCost,
  keyVaultMonthlyCost,
  natGatewayMonthlyCost,
  eventGridMonthlyCost,
  apiManagementMonthlyCost,
  cdnMonthlyCost,
  eventHubsMonthlyCost,
  containerAppsMonthlyCost,
  sqlDatabaseMonthlyCost,
  computeCostContext,
};
