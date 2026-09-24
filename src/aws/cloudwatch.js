'use strict';

const { CloudWatchClient, GetMetricDataCommand } = require('@aws-sdk/client-cloudwatch');

/**
 * Fetches batched CloudWatch metrics for multiple resources in a single API call.
 * GetMetricData accepts up to 500 queries per call; we batch to stay well under.
 *
 * @param {CloudWatchClient} client
 * @param {Array} querySpecs - array of { id, namespace, metricName, dimensions, stat }
 * @param {Date} startTime
 * @param {Date} endTime
 * @param {number} periodSeconds - CloudWatch aggregation period in seconds
 * @returns {Object} map of id -> { values: number[], sum: number, avg: number, max: number }
 */
async function batchGetMetrics(client, querySpecs, startTime, endTime, periodSeconds = 86400) {
  const results = {};
  const BATCH_SIZE = 450; // stay under 500 query limit

  for (let i = 0; i < querySpecs.length; i += BATCH_SIZE) {
    const batch = querySpecs.slice(i, i + BATCH_SIZE);

    const queries = batch.map(spec => ({
      Id: spec.id,
      MetricStat: {
        Metric: {
          Namespace: spec.namespace,
          MetricName: spec.metricName,
          Dimensions: spec.dimensions,
        },
        Period: periodSeconds,
        Stat: spec.stat,
      },
      ReturnData: true,
    }));

    let nextToken;
    const batchResults = {};

    do {
      const params = {
        MetricDataQueries: queries,
        StartTime: startTime,
        EndTime: endTime,
      };
      if (nextToken) params.NextToken = nextToken;

      const response = await client.send(new GetMetricDataCommand(params));

      for (const r of (response.MetricDataResults || [])) {
        if (!batchResults[r.Id]) batchResults[r.Id] = [];
        batchResults[r.Id].push(...(r.Values || []));
      }

      nextToken = response.NextToken;
    } while (nextToken);

    for (const [id, values] of Object.entries(batchResults)) {
      const sum = values.reduce((a, b) => a + b, 0);
      const avg = values.length > 0 ? sum / values.length : 0;
      const max = values.length > 0 ? Math.max(...values) : 0;
      results[id] = { values, sum, avg, max };
    }

    // Ensure every requested ID is in the result (even with no data)
    for (const spec of batch) {
      if (!results[spec.id]) {
        results[spec.id] = { values: [], sum: 0, avg: 0, max: 0 };
      }
    }
  }

  return results;
}

/**
 * Builds a safe CloudWatch metric query ID from an index.
 * IDs must match [a-z][a-zA-Z0-9_]* and be ≤ 255 chars.
 */
function metricId(prefix, index, suffix) {
  return `${prefix}${index}${suffix}`;
}

module.exports = { batchGetMetrics, metricId };
