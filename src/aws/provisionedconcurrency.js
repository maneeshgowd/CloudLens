'use strict';

const {
  LambdaClient,
  ListFunctionsCommand,
  ListProvisionedConcurrencyConfigsCommand,
} = require('@aws-sdk/client-lambda');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

// Provisioned Concurrency pricing (us-east-1)
const PC_ALLOC_PER_GB_SECOND = 0.000004646; // charged even when idle
const SECONDS_PER_MONTH = 30 * 24 * 3600;

async function listAllFunctions(client) {
  const fns = [];
  let marker;
  do {
    const res = await client.send(new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }));
    fns.push(...(res.Functions || []));
    marker = res.NextMarker;
  } while (marker);
  return fns;
}

async function listProvisionedConfigs(client, functionName) {
  const configs = [];
  let marker;
  do {
    const res = await client.send(
      new ListProvisionedConcurrencyConfigsCommand({ FunctionName: functionName, Marker: marker })
    );
    configs.push(...(res.ProvisionedConcurrencyConfigs || []));
    marker = res.NextMarker;
  } while (marker);
  return configs;
}

async function analyzeProvisionedConcurrency({ region, startTime, endTime, days, filter }) {
  const lambdaClient = new LambdaClient({ region });
  const cwClient     = new CloudWatchClient({ region });

  process.stdout.write('  Provisioned Concurrency: listing functions... ');
  let functions = await listAllFunctions(lambdaClient);
  if (filter) {
    const needle = filter.toLowerCase();
    functions = functions.filter(f => f.FunctionName.toLowerCase().includes(needle));
  }

  // Check each function for PC configs (parallel, capped to avoid throttles)
  const BATCH = 20;
  const withPC = [];
  for (let i = 0; i < functions.length; i += BATCH) {
    const batch = functions.slice(i, i + BATCH);
    const results = await Promise.all(
      batch.map(fn =>
        listProvisionedConfigs(lambdaClient, fn.FunctionName)
          .then(configs => ({ fn, configs }))
          .catch(() => ({ fn, configs: [] }))
      )
    );
    for (const r of results) {
      if (r.configs.length > 0) withPC.push(r);
    }
  }
  console.log(`${withPC.length} functions with provisioned concurrency`);

  if (withPC.length === 0) return { findings: [], resourcesScanned: 0 };

  // Fetch actual ConcurrentExecutions (Max) per function
  const querySpecs = withPC.map(({ fn }, i) => ({
    id: metricId('pc', i, 'cx'),
    namespace: 'AWS/Lambda',
    metricName: 'ConcurrentExecutions',
    dimensions: [{ Name: 'FunctionName', Value: fn.FunctionName }],
    stat: 'Maximum',
  }));

  process.stdout.write(`  Provisioned Concurrency: fetching concurrency metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];
  let totalPCCost = 0;

  withPC.forEach(({ fn, configs }, i) => {
    const provisioned = configs.reduce(
      (sum, c) => sum + (c.RequestedProvisionedConcurrentExecutions || c.AllocatedProvisionedConcurrentExecutions || 0),
      0
    );
    const actualPeak = cwMetrics[metricId('pc', i, 'cx')]?.max ?? 0;
    const memGB      = (fn.MemorySize || 128) / 1024;

    // Monthly allocation cost (charged every second, whether invoked or not)
    const currentCost = provisioned * memGB * SECONDS_PER_MONTH * PC_ALLOC_PER_GB_SECOND;
    totalPCCost += currentCost;

    // Recommended: 1.5× actual peak (50% headroom), minimum 1
    const recommended = Math.max(1, Math.ceil(actualPeak * 1.5));

    const base = {
      provider:     'aws',
      service:      'Provisioned Concurrency',
      resourceName: fn.FunctionName,
      resourceId:   fn.FunctionArn,
      region,
      metrics: {
        provisionedUnits:     provisioned,
        actualPeakConcurrency: Math.round(actualPeak),
        configuredMemMB:      fn.MemorySize || 128,
        recommendedUnits:     recommended,
        monthlyCostUsd:       parseFloat(currentCost.toFixed(2)),
      },
    };

    if (actualPeak === 0) {
      // No traffic at all — 100% waste
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'PC_IDLE',
        details: `${provisioned} units provisioned — zero concurrent executions in last ${days} days. Burning $${currentCost.toFixed(2)}/month with no traffic.`,
        recommendation: `Remove provisioned concurrency entirely. Re-enable only if traffic resumes. Cold starts will add ~100–500 ms latency but there is no point paying for warm capacity that is never used.`,
        estimatedCurrentCost:    parseFloat(currentCost.toFixed(4)),
        estimatedMonthlySavings: parseFloat(currentCost.toFixed(4)),
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-pc-idle-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name ProvisionedConcurrencyUtilization \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Average --period 86400 \\
  --threshold 10 --comparison-operator LessThanThreshold \\
  --evaluation-periods 3`,
      });
    } else if (provisioned > recommended) {
      const optimisedCost = recommended * memGB * SECONDS_PER_MONTH * PC_ALLOC_PER_GB_SECOND;
      const savings = Math.max(0, currentCost - optimisedCost);
      findings.push({
        ...base,
        priority: savings > 100 ? 'HIGH' : 'MEDIUM',
        type: 'PC_OVER_PROVISIONED',
        details: `${provisioned} units provisioned — actual peak was ${Math.round(actualPeak)} over last ${days} days. Allocation cost: $${currentCost.toFixed(2)}/month.`,
        recommendation: `Reduce provisioned concurrency from ${provisioned} → ${recommended} (1.5× actual peak for headroom). Saves ~$${savings.toFixed(2)}/month.`,
        estimatedCurrentCost:    parseFloat(currentCost.toFixed(4)),
        estimatedMonthlySavings: parseFloat(savings.toFixed(4)),
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-pc-over-${fn.FunctionName.substring(0, 50)}" \\
  --namespace AWS/Lambda --metric-name ProvisionedConcurrencyUtilization \\
  --dimensions Name=FunctionName,Value="${fn.FunctionName}" \\
  --statistic Average --period 86400 \\
  --threshold 10 --comparison-operator LessThanThreshold \\
  --evaluation-periods 3`,
      });
    }
  });

  return { findings, resourcesScanned: withPC.length, estimatedMonthlyCost: parseFloat(totalPCCost.toFixed(4)) };
}

module.exports = { analyzeProvisionedConcurrency };
