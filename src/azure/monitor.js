'use strict';

// Azure Monitor metrics helper — mirrors src/aws/cloudwatch.js's batchGetMetrics.
// Azure Monitor's classic metrics.list() (Microsoft.Insights data-plane, via
// @azure/arm-monitor) is per-resource — there's no CloudWatch-style GetMetricData
// batching across resources — so we fan out with a concurrency cap instead.

// Fetches one or more metrics for a single resource over [startTime, endTime].
// Always returns an entry for every requested metric name (zeroed if the API
// call fails or returns no data points), so callers can safely do
// `metrics.SomeMetric.sum` without extra null-checks.
async function getResourceMetrics(monitorClient, resourceUri, metricNames, startTime, endTime, opts = {}) {
  const { interval = 'P1D', aggregations = ['Total', 'Average', 'Maximum'] } = opts;

  const result = {};
  for (const name of metricNames) result[name] = { sum: 0, avg: 0, max: 0 };

  try {
    const res = await monitorClient.metrics.list(resourceUri, {
      metricnames: metricNames.join(','),
      timespan: `${startTime.toISOString()}/${endTime.toISOString()}`,
      interval,
      aggregation: aggregations.join(','),
    });

    for (const metric of res.value || []) {
      const name = metric.name?.value;
      if (!name || !(name in result)) continue;

      let sum = 0;
      let avgTotal = 0;
      let avgCount = 0;
      let max = 0;

      for (const series of metric.timeseries || []) {
        for (const point of series.data || []) {
          if (typeof point.total === 'number') sum += point.total;
          if (typeof point.average === 'number') { avgTotal += point.average; avgCount += 1; }
          if (typeof point.maximum === 'number' && point.maximum > max) max = point.maximum;
        }
      }

      result[name] = { sum, avg: avgCount > 0 ? avgTotal / avgCount : 0, max };
    }
  } catch {
    // Resource may not support the requested metrics, or the Monitoring Reader
    // role is missing — leave the zeroed defaults rather than failing the caller.
  }

  return result;
}

// Fetches metrics for many resources with a concurrency cap (default 20, same
// as batchFetchTags in src/aws/lambda.js). Returns Map<resourceId, metricsByName>.
async function batchGetResourceMetrics(monitorClient, resources, metricNames, startTime, endTime, opts = {}, concurrency = 20) {
  const results = new Map();

  for (let i = 0; i < resources.length; i += concurrency) {
    const batch = resources.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(r =>
        getResourceMetrics(monitorClient, r.id, metricNames, startTime, endTime, opts)
          .then(metrics => ({ id: r.id, metrics }))
      )
    );
    for (const { id, metrics } of batchResults) results.set(id, metrics);
  }

  return results;
}

module.exports = { getResourceMetrics, batchGetResourceMetrics };
