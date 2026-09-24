'use strict';

const { APIGatewayClient, GetRestApisCommand, GetStagesCommand: GetRestStagesCommand } = require('@aws-sdk/client-api-gateway');
const { ApiGatewayV2Client, GetApisCommand, GetStagesCommand: GetHttpStagesCommand  } = require('@aws-sdk/client-apigatewayv2');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

// API Gateway pricing (us-east-1)
const REST_PER_MILLION  = 3.50;  // REST API v1
const HTTP_PER_MILLION  = 1.00;  // HTTP API v2

async function analyzeAPIGateway({ region, startTime, endTime, days, filter }) {
  const v1Client = new APIGatewayClient({ region });
  const v2Client = new ApiGatewayV2Client({ region });
  const cwClient = new CloudWatchClient({ region });

  // ── REST APIs (v1) ─────────────────────────────────────────────────────
  process.stdout.write('  API Gateway: listing REST APIs (v1)... ');
  const restApis = [];
  let position;
  do {
    const res = await v1Client.send(new GetRestApisCommand({ position, limit: 500 }));
    restApis.push(...(res.items || []));
    position = res.position;
  } while (position);
  console.log(`${restApis.length} found`);

  // ── HTTP APIs (v2) ─────────────────────────────────────────────────────
  process.stdout.write('  API Gateway: listing HTTP APIs (v2)... ');
  const httpApis = [];
  let nextToken;
  do {
    const res = await v2Client.send(new GetApisCommand({ NextToken: nextToken }));
    httpApis.push(...(res.Items || []));
    nextToken = res.NextToken;
  } while (nextToken);
  console.log(`${httpApis.length} found`);

  const needle = filter ? filter.toLowerCase() : null;
  const filteredRest = needle ? restApis.filter(a => a.name?.toLowerCase().includes(needle)) : restApis;
  const filteredHttp = needle ? httpApis.filter(a => a.Name?.toLowerCase().includes(needle)) : httpApis;

  // Collect stages for REST APIs
  const restStages = [];
  for (const api of filteredRest) {
    try {
      const res = await v1Client.send(new GetRestStagesCommand({ restApiId: api.id }));
      for (const stage of (res.item || [])) {
        restStages.push({ api, stage });
      }
    } catch { /* skip */ }
  }

  // Collect stages for HTTP APIs
  const httpStages = [];
  for (const api of filteredHttp) {
    try {
      const res = await v2Client.send(new GetHttpStagesCommand({ ApiId: api.ApiId }));
      for (const stage of (res.Items || [])) {
        httpStages.push({ api, stage });
      }
    } catch { /* skip */ }
  }

  const totalStages = restStages.length + httpStages.length;
  if (totalStages === 0) return { findings: [], resourcesScanned: 0 };

  // CloudWatch request counts
  const querySpecs = [];

  restStages.forEach(({ api, stage }, i) => {
    querySpecs.push({
      id: metricId('agv1', i, 'cnt'),
      namespace: 'AWS/ApiGateway',
      metricName: 'Count',
      dimensions: [
        { Name: 'ApiName', Value: api.name   },
        { Name: 'Stage',   Value: stage.stageName },
      ],
      stat: 'Sum',
    });
  });

  httpStages.forEach(({ api, stage }, i) => {
    querySpecs.push({
      id: metricId('agv2', i, 'cnt'),
      namespace: 'AWS/ApiGateway',
      metricName: 'Count',
      dimensions: [
        { Name: 'ApiId', Value: api.ApiId        },
        { Name: 'Stage', Value: stage.StageName  },
      ],
      stat: 'Sum',
    });
  });

  process.stdout.write(`  API Gateway: fetching request metrics for ${totalStages} stages... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];
  let totalApiCost = 0;

  restStages.forEach(({ api, stage }, i) => {
    const requests        = cwMetrics[metricId('agv1', i, 'cnt')]?.sum ?? 0;
    const monthlyRequests = (requests / days) * 30;
    const monthlyCost     = (monthlyRequests / 1e6) * REST_PER_MILLION;
    totalApiCost += monthlyCost;

    const base = {
      provider:     'aws',
      service:      'API Gateway',
      resourceName: `${api.name} [${stage.stageName}]`,
      resourceId:   `${api.id}/${stage.stageName}`,
      region,
      metrics: {
        totalRequests:    Math.round(requests),
        avgDailyRequests: Math.round(requests / days),
        apiType:          'REST v1',
        estimatedMonthlyCostUsd: parseFloat(monthlyCost.toFixed(4)),
      },
    };

    if (requests === 0) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'API_IDLE',
        details: `0 requests in last ${days} days on stage "${stage.stageName}"`,
        recommendation: `Delete this stage or API if it is no longer in use. Idle REST APIs have no direct request cost but incur caching costs if a cache is enabled, and add operational clutter.`,
        estimatedCurrentCost:    null,
        estimatedMonthlySavings: null,
      });
    }
  });

  httpStages.forEach(({ api, stage }, i) => {
    const requests        = cwMetrics[metricId('agv2', i, 'cnt')]?.sum ?? 0;
    const monthlyRequests = (requests / days) * 30;
    const monthlyCost     = (monthlyRequests / 1e6) * HTTP_PER_MILLION;
    totalApiCost += monthlyCost;

    const base = {
      provider:     'aws',
      service:      'API Gateway',
      resourceName: `${api.Name} [${stage.StageName}]`,
      resourceId:   `${api.ApiId}/${stage.StageName}`,
      region,
      metrics: {
        totalRequests:    Math.round(requests),
        avgDailyRequests: Math.round(requests / days),
        apiType:          'HTTP v2',
        estimatedMonthlyCostUsd: parseFloat(monthlyCost.toFixed(4)),
      },
    };

    if (requests === 0) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'API_IDLE',
        details: `0 requests in last ${days} days on stage "${stage.StageName}"`,
        recommendation: `Delete this stage or API if it is no longer in use. HTTP API v2 charges $1.00/million requests — idle stages have no cost but should be cleaned up to reduce confusion.`,
        estimatedCurrentCost:    null,
        estimatedMonthlySavings: null,
      });
    }
  });

  return { findings, resourcesScanned: totalStages, estimatedMonthlyCost: parseFloat(totalApiCost.toFixed(4)) };
}

module.exports = { analyzeAPIGateway };
