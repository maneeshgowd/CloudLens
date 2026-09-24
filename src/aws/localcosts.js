'use strict';

/**
 * AWS public pricing constants (us-east-1, on-demand).
 * Used to estimate costs from CloudWatch metrics — no Cost Explorer API needed.
 */
const PRICING = {
  lambda:      { perGBSecond: 0.0000166667,  perMillionRequests: 0.20 },
  dynamodb:    { perRCUHour: 0.00013,         perWCUHour: 0.00065,
                 readPerMillion: 0.25,         writePerMillion: 1.25 },   // PAY_PER_REQUEST
  cwLogs:      { storagePerGBMonth: 0.03,     ingestPerGB: 0.50 },
  s3:          { storagePerGBMonth: 0.023 },
  cloudfront:  { dataTransferPerGB: 0.0085,   requestsPer10k: 0.01 },
  natGateway:  { perHour: 0.045,              perGB: 0.045 },
  fargate:     { vcpuPerHour: 0.04048,        gbPerHour: 0.004445 },
  secretsMgr:  { perSecretMonth: 0.40 },
  apiGateway:  { restPerMillion: 3.50,        httpPerMillion: 1.00 },
  pc:          { perGBSecond: 0.000004646 },  // provisioned concurrency allocation
};

/**
 * Estimate current monthly Lambda compute cost.
 * monthlyInvocations × GB-seconds × price
 */
function lambdaComputeCost(configuredMemMB, avgDurationMs, monthlyInvocations) {
  const gbSeconds = (configuredMemMB / 1024) * (avgDurationMs / 1000) * monthlyInvocations;
  return gbSeconds * PRICING.lambda.perGBSecond
       + (monthlyInvocations / 1e6) * PRICING.lambda.perMillionRequests;
}

/**
 * Aggregate total spend + potential savings.
 * spendByService: { 'Lambda': 45.20, 'DynamoDB': 120.00, ... } — returned by each analyser.
 * findings: used only to sum up potential savings.
 */
function computeCostContext(findings, spendByService = {}) {
  let totalSavings = 0;
  for (const f of findings) {
    if (f.estimatedMonthlySavings > 0) totalSavings += f.estimatedMonthlySavings;
  }

  const totalSpend = Object.values(spendByService).reduce((a, b) => a + b, 0);

  return {
    totalEstimatedCost:    totalSpend,
    totalPotentialSavings: totalSavings,
    topServices: Object.entries(spendByService)
      .map(([service, amount]) => ({ service, amount: parseFloat(amount.toFixed(2)) }))
      .sort((a, b) => b.amount - a.amount),
    source: 'Estimated from CloudWatch metrics · AWS public pricing (us-east-1)',
  };
}

module.exports = { PRICING, lambdaComputeCost, computeCostContext };
