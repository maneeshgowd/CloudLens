'use strict';

const { CostExplorerClient, GetCostAndUsageCommand } = require('@aws-sdk/client-cost-explorer');

/**
 * Fetches last 30-day spend grouped by AWS service.
 * Cost Explorer is a global service — always uses us-east-1.
 * Returns null gracefully if the user lacks ce:GetCostAndUsage permission.
 */
async function getCostContext() {
  const client = new CostExplorerClient({ region: 'us-east-1' });

  const end   = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  const fmt   = d => d.toISOString().slice(0, 10); // YYYY-MM-DD

  try {
    const res = await client.send(new GetCostAndUsageCommand({
      TimePeriod:  { Start: fmt(start), End: fmt(end) },
      Granularity: 'MONTHLY',
      Metrics:     ['UnblendedCost'],
      GroupBy:     [{ Type: 'DIMENSION', Key: 'SERVICE' }],
    }));

    const byService = [];
    let total = 0;

    for (const period of (res.ResultsByTime || [])) {
      for (const group of (period.Groups || [])) {
        const service = group.Keys[0];
        const amount  = parseFloat(group.Metrics.UnblendedCost.Amount || '0');
        if (amount < 0.01) continue; // skip negligible

        const existing = byService.find(s => s.service === service);
        if (existing) {
          existing.amount += amount;
        } else {
          byService.push({ service, amount });
        }
        total += amount;
      }
    }

    byService.sort((a, b) => b.amount - a.amount);

    return {
      totalSpend: parseFloat(total.toFixed(2)),
      currency: 'USD',
      topServices: byService.slice(0, 8),
    };
  } catch (err) {
    // Cost Explorer might not be enabled or user lacks permission — non-fatal
    console.warn(`  [WARN] Cost Explorer unavailable: ${err.message}`);
    return null;
  }
}

module.exports = { getCostContext };
