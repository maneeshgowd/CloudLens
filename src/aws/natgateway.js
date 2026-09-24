'use strict';

const { EC2Client, DescribeNatGatewaysCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

// NAT Gateway pricing (us-east-1)
const NAT_GW_PER_HOUR = 0.045;  // fixed, regardless of traffic
const NAT_GW_PER_GB   = 0.045;  // per GB of data processed
const HOURS_PER_MONTH = 30 * 24;

async function analyzeNATGateways({ region, startTime, endTime, days, filter }) {
  const ec2Client = new EC2Client({ region });
  const cwClient  = new CloudWatchClient({ region });

  process.stdout.write('  NAT Gateway: listing... ');

  const gateways = [];
  let nextToken;
  do {
    const res = await ec2Client.send(new DescribeNatGatewaysCommand({
      Filter: [{ Name: 'state', Values: ['available'] }],
      NextToken: nextToken,
    }));
    gateways.push(...(res.NatGateways || []));
    nextToken = res.NextToken;
  } while (nextToken);

  // Apply name-tag filter
  const needle = filter ? filter.toLowerCase() : null;
  const filtered = needle
    ? gateways.filter(gw => {
        const nameTag = (gw.Tags || []).find(t => t.Key === 'Name');
        return nameTag?.Value?.toLowerCase().includes(needle)
            || gw.NatGatewayId.toLowerCase().includes(needle);
      })
    : gateways;

  console.log(`${filtered.length} found`);
  if (filtered.length === 0) return { findings: [], resourcesScanned: 0 };

  const querySpecs = [];
  filtered.forEach((gw, i) => {
    const dims = [{ Name: 'NatGatewayId', Value: gw.NatGatewayId }];
    querySpecs.push(
      { id: metricId('nat', i, 'out'), namespace: 'AWS/NATGateway', metricName: 'BytesOutToDestination', dimensions: dims, stat: 'Sum' },
      { id: metricId('nat', i, 'in'),  namespace: 'AWS/NATGateway', metricName: 'BytesOutToSource',      dimensions: dims, stat: 'Sum' },
    );
  });

  process.stdout.write(`  NAT Gateway: fetching traffic metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];
  const fixedMonthly = NAT_GW_PER_HOUR * HOURS_PER_MONTH; // $32.40/month fixed

  filtered.forEach((gw, i) => {
    const nameTag    = (gw.Tags || []).find(t => t.Key === 'Name');
    const name       = nameTag?.Value || gw.NatGatewayId;
    const bytesOut   = cwMetrics[metricId('nat', i, 'out')]?.sum ?? 0;
    const bytesIn    = cwMetrics[metricId('nat', i, 'in')]?.sum  ?? 0;
    const totalBytes = bytesOut + bytesIn;
    const totalGB    = totalBytes / (1024 ** 3);
    const transferCost   = totalGB * NAT_GW_PER_GB;
    const totalMonthlyCost = fixedMonthly + transferCost;

    const base = {
      provider:     'aws',
      service:      'NAT Gateway',
      resourceName: name,
      resourceId:   gw.NatGatewayId,
      region,
      metrics: {
        totalDataTransferGB:  parseFloat(totalGB.toFixed(3)),
        avgDailyGB:           parseFloat((totalGB / days).toFixed(3)),
        fixedMonthlyCostUsd:  parseFloat(fixedMonthly.toFixed(2)),
        totalMonthlyCostUsd:  parseFloat(totalMonthlyCost.toFixed(2)),
      },
    };

    if (totalGB < 0.1) {
      // Near-zero traffic — almost entirely fixed-cost waste
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'NAT_IDLE',
        details: `Only ${totalGB.toFixed(3)} GB processed in ${days} days — paying $${fixedMonthly.toFixed(2)}/month fixed cost for near-zero traffic.`,
        recommendation: `Check what workload is using this NAT Gateway. Replace AWS-service traffic (S3, DynamoDB, ECR, Secrets Manager) with free VPC Endpoints. If no workload remains, delete the gateway.`,
        estimatedCurrentCost:    parseFloat(totalMonthlyCost.toFixed(4)),
        estimatedMonthlySavings: parseFloat(fixedMonthly.toFixed(4)),
      });
    } else if (totalGB / days < 1) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'NAT_LOW_UTILISATION',
        details: `Avg ${(totalGB / days).toFixed(2)} GB/day — low throughput for a $${fixedMonthly.toFixed(2)}/month fixed-cost gateway.`,
        recommendation: `Add VPC Endpoints for S3, DynamoDB, ECR, and Secrets Manager to eliminate the majority of data transfer through NAT. Check if multiple NAT Gateways can be consolidated into one.`,
        estimatedCurrentCost:    parseFloat(totalMonthlyCost.toFixed(4)),
        estimatedMonthlySavings: null,
      });
    }
  });

  return { findings, resourcesScanned: filtered.length };
}

module.exports = { analyzeNATGateways };
