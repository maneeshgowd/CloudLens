'use strict';

const { SecretsManagerClient, ListSecretsCommand } = require('@aws-sdk/client-secrets-manager');

const COST_PER_SECRET_MONTH = 0.40; // $0.40/secret/month regardless of usage
const STALE_THRESHOLD_DAYS  = 30;   // not accessed in 30+ days = stale

async function analyzeSecretsManager({ region, startTime, endTime, days, filter }) {
  const smClient = new SecretsManagerClient({ region });

  process.stdout.write('  Secrets Manager: listing secrets... ');

  const secrets = [];
  let nextToken;
  do {
    const res = await smClient.send(
      new ListSecretsCommand({ NextToken: nextToken, MaxResults: 100 })
    );
    secrets.push(...(res.SecretList || []));
    nextToken = res.NextToken;
  } while (nextToken);

  const needle = filter ? filter.toLowerCase() : null;
  const filtered = needle
    ? secrets.filter(s => s.Name?.toLowerCase().includes(needle))
    : secrets;

  console.log(`${filtered.length} found`);
  if (filtered.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];
  const now = new Date();

  for (const secret of filtered) {
    const lastAccessed   = secret.LastAccessedDate ? new Date(secret.LastAccessedDate) : null;
    const lastChanged    = secret.LastChangedDate  ? new Date(secret.LastChangedDate)  : null;
    const daysSinceAccess = lastAccessed
      ? Math.floor((now - lastAccessed) / 86400000)
      : null;
    const daysSinceChange = lastChanged
      ? Math.floor((now - lastChanged) / 86400000)
      : null;

    const base = {
      provider:     'aws',
      service:      'Secrets Manager',
      resourceName: secret.Name,
      resourceId:   secret.ARN,
      region,
      metrics: {
        lastAccessedDaysAgo: daysSinceAccess ?? 'never',
        lastChangedDaysAgo:  daysSinceChange ?? 'unknown',
        monthlyCostUsd:      COST_PER_SECRET_MONTH,
      },
    };

    if (daysSinceAccess === null) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'SECRET_NEVER_ACCESSED',
        details: `Secret "${secret.Name}" has never been accessed — $${COST_PER_SECRET_MONTH.toFixed(2)}/month wasted.`,
        recommendation: `Delete if this secret was created in error or belongs to a decommissioned service. Every secret costs $0.40/month regardless of usage.`,
        estimatedCurrentCost:    COST_PER_SECRET_MONTH,
        estimatedMonthlySavings: COST_PER_SECRET_MONTH,
      });
    } else if (daysSinceAccess > STALE_THRESHOLD_DAYS) {
      findings.push({
        ...base,
        priority: daysSinceAccess > 90 ? 'HIGH' : 'MEDIUM',
        type: 'SECRET_STALE',
        details: `Last accessed ${daysSinceAccess} days ago — $${COST_PER_SECRET_MONTH.toFixed(2)}/month.`,
        recommendation: `Verify this secret is still in active use. If the associated service or integration no longer exists, delete it to save $0.40/month.`,
        estimatedCurrentCost:    COST_PER_SECRET_MONTH,
        estimatedMonthlySavings: COST_PER_SECRET_MONTH,
      });
    }
  }

  return {
    findings,
    resourcesScanned: filtered.length,
    estimatedMonthlyCost: parseFloat((filtered.length * COST_PER_SECRET_MONTH).toFixed(4)),
  };
}

module.exports = { analyzeSecretsManager };
