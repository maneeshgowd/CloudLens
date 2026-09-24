'use strict';

const { CloudFrontClient, ListDistributionsCommand } = require('@aws-sdk/client-cloudfront');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

// CloudFront pricing (us-east-1 origin, class-1 edge)
const CF_DATA_TRANSFER_PER_GB = 0.0085;  // first 10 TB/month
const CF_REQUESTS_PER_10K     = 0.01;    // HTTPS requests

// CloudFront metrics MUST be fetched from us-east-1 regardless of distribution region
const CF_METRICS_REGION = 'us-east-1';

async function analyzeCloudFront({ region, startTime, endTime, days, filter }) {
  const cfClient = new CloudFrontClient({ region: CF_METRICS_REGION });
  const cwClient = new CloudWatchClient({ region: CF_METRICS_REGION });

  process.stdout.write('  CloudFront: listing distributions... ');

  const distributions = [];
  let marker;
  do {
    const res = await cfClient.send(new ListDistributionsCommand({ Marker: marker }));
    const list = res.DistributionList;
    distributions.push(...(list?.Items || []));
    marker = list?.IsTruncated ? list.NextMarker : undefined;
  } while (marker);

  const needle = filter ? filter.toLowerCase() : null;
  const filtered = needle
    ? distributions.filter(d =>
        d.DomainName?.toLowerCase().includes(needle) ||
        (d.Aliases?.Items || []).some(a => a.toLowerCase().includes(needle)) ||
        d.Id?.toLowerCase().includes(needle)
      )
    : distributions;

  console.log(`${filtered.length} found`);
  if (filtered.length === 0) return { findings: [], resourcesScanned: 0, estimatedMonthlyCost: 0 };

  // CloudFront metrics use dimension Region = 'Global'
  const querySpecs = [];
  filtered.forEach((d, i) => {
    const dims = [
      { Name: 'DistributionId', Value: d.Id },
      { Name: 'Region',         Value: 'Global' },
    ];
    querySpecs.push(
      { id: metricId('cf', i, 'req'), namespace: 'AWS/CloudFront', metricName: 'Requests',        dimensions: dims, stat: 'Sum' },
      { id: metricId('cf', i, 'byt'), namespace: 'AWS/CloudFront', metricName: 'BytesDownloaded', dimensions: dims, stat: 'Sum' },
    );
  });

  process.stdout.write(`  CloudFront: fetching request + transfer metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];
  let totalCFCost = 0;

  filtered.forEach((d, i) => {
    const requests    = cwMetrics[metricId('cf', i, 'req')]?.sum ?? 0;
    const bytesDown   = cwMetrics[metricId('cf', i, 'byt')]?.sum ?? 0;
    const gbDown      = bytesDown / (1024 ** 3);

    const monthlyRequests = (requests / days) * 30;
    const monthlyGB       = (gbDown / days) * 30;
    const requestCost     = (monthlyRequests / 10000) * CF_REQUESTS_PER_10K;
    const transferCost    = monthlyGB * CF_DATA_TRANSFER_PER_GB;
    const monthlyCost     = requestCost + transferCost;
    totalCFCost += monthlyCost;

    const aliases = (d.Aliases?.Items || []).join(', ') || d.DomainName;

    const base = {
      provider:     'aws',
      service:      'CloudFront',
      resourceName: aliases,
      resourceId:   d.Id,
      region:       'global',
      metrics: {
        totalRequests:    Math.round(requests),
        avgDailyRequests: Math.round(requests / days),
        totalDataGB:      parseFloat(gbDown.toFixed(3)),
        avgDailyGB:       parseFloat((gbDown / days).toFixed(3)),
        estimatedMonthlyCostUsd: parseFloat(monthlyCost.toFixed(2)),
      },
    };

    if (requests === 0) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'CF_IDLE',
        details: `0 requests in last ${days} days — distribution is deployed but receiving no traffic`,
        recommendation: `Disable or delete this distribution if it is no longer in use. No requests = no cost, but idle distributions add operational clutter.`,
        estimatedCurrentCost:    0,
        estimatedMonthlySavings: null,
      });
    } else if (monthlyCost > 0) {
      // Active distribution — show as LOW informational finding so cost is visible in report
      findings.push({
        ...base,
        priority: 'LOW',
        type: 'CF_ACTIVE',
        details: `${Math.round(requests).toLocaleString()} requests + ${gbDown.toFixed(2)} GB in ${days} days — est. $${monthlyCost.toFixed(2)}/month`,
        recommendation: `Review cache hit ratio in CloudFront logs. A low hit rate means most requests reach the origin, increasing API Gateway + Lambda costs. Enable caching where possible to reduce spend.`,
        estimatedCurrentCost:    parseFloat(monthlyCost.toFixed(4)),
        estimatedMonthlySavings: null,
      });
    }
  });

  return { findings, resourcesScanned: filtered.length, estimatedMonthlyCost: parseFloat(totalCFCost.toFixed(4)) };
}

module.exports = { analyzeCloudFront };
