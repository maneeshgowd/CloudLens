'use strict';

const {
  ECSClient,
  ListClustersCommand,
  ListServicesCommand,
  DescribeServicesCommand,
  DescribeTaskDefinitionCommand,
} = require('@aws-sdk/client-ecs');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

// Fargate pricing (us-east-1, Linux/x86)
const FARGATE_VCPU_PER_HOUR = 0.04048;
const FARGATE_GB_PER_HOUR   = 0.004445;
const HOURS_PER_MONTH       = 30 * 24;

async function analyzeECS({ region, startTime, endTime, days, filter }) {
  const ecsClient = new ECSClient({ region });
  const cwClient  = new CloudWatchClient({ region });

  process.stdout.write('  ECS: listing clusters... ');
  const clustersRes = await ecsClient.send(new ListClustersCommand({}));
  const clusterArns = clustersRes.clusterArns || [];
  console.log(`${clusterArns.length} found`);

  if (clusterArns.length === 0) return { findings: [], resourcesScanned: 0 };

  // List services in every cluster
  const allServices = [];
  for (const clusterArn of clusterArns) {
    let nextToken;
    do {
      const res = await ecsClient.send(
        new ListServicesCommand({ cluster: clusterArn, nextToken, maxResults: 100 })
      );
      for (const serviceArn of (res.serviceArns || [])) {
        allServices.push({ clusterArn, serviceArn });
      }
      nextToken = res.nextToken;
    } while (nextToken);
  }

  // Apply filter
  const needle = filter ? filter.toLowerCase() : null;
  const filtered = needle
    ? allServices.filter(s => s.serviceArn.toLowerCase().includes(needle))
    : allServices;

  if (filtered.length === 0) {
    console.log('  ECS: 0 services found');
    return { findings: [], resourcesScanned: 0 };
  }

  // Describe services (API limit: 10 per call, grouped by cluster)
  const byCluster = {};
  for (const { clusterArn, serviceArn } of filtered) {
    (byCluster[clusterArn] = byCluster[clusterArn] || []).push(serviceArn);
  }

  const describedServices = [];
  for (const [clusterArn, serviceArns] of Object.entries(byCluster)) {
    for (let i = 0; i < serviceArns.length; i += 10) {
      const res = await ecsClient.send(
        new DescribeServicesCommand({ cluster: clusterArn, services: serviceArns.slice(i, i + 10) })
      );
      for (const svc of (res.services || [])) {
        describedServices.push({ clusterArn, service: svc });
      }
    }
  }
  console.log(`  ECS: ${describedServices.length} services found`);

  // Fetch task definitions to get CPU/memory allocations (cached)
  const taskDefCache = {};
  async function getTaskDef(arn) {
    if (taskDefCache[arn]) return taskDefCache[arn];
    try {
      const res = await ecsClient.send(new DescribeTaskDefinitionCommand({ taskDefinition: arn }));
      taskDefCache[arn] = res.taskDefinition;
      return res.taskDefinition;
    } catch { return null; }
  }

  // CloudWatch CPU + memory per service
  const querySpecs = [];
  describedServices.forEach(({ clusterArn, service }, i) => {
    const clusterName = clusterArn.split('/').pop();
    const dims = [
      { Name: 'ClusterName', Value: clusterName },
      { Name: 'ServiceName', Value: service.serviceName },
    ];
    querySpecs.push(
      { id: metricId('ecs', i, 'cpu'), namespace: 'AWS/ECS', metricName: 'CPUUtilization',    dimensions: dims, stat: 'Average' },
      { id: metricId('ecs', i, 'mem'), namespace: 'AWS/ECS', metricName: 'MemoryUtilization', dimensions: dims, stat: 'Average' },
    );
  });

  process.stdout.write(`  ECS: fetching utilisation metrics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];

  for (let i = 0; i < describedServices.length; i++) {
    const { clusterArn, service } = describedServices[i];
    const clusterName  = clusterArn.split('/').pop();
    const avgCpu       = cwMetrics[metricId('ecs', i, 'cpu')]?.avg ?? null;
    const avgMem       = cwMetrics[metricId('ecs', i, 'mem')]?.avg ?? null;
    const runningCount = service.runningCount || 0;
    const desiredCount = service.desiredCount || 0;

    const taskDef     = service.taskDefinition ? await getTaskDef(service.taskDefinition) : null;
    const taskVcpu    = taskDef ? (parseInt(taskDef.cpu    || '0') / 1024) : null; // milliCPU → vCPU
    const taskMemGB   = taskDef ? (parseInt(taskDef.memory || '0') / 1024) : null; // MiB → GB

    const costPerTask = (taskVcpu !== null && taskMemGB !== null)
      ? (taskVcpu * FARGATE_VCPU_PER_HOUR + taskMemGB * FARGATE_GB_PER_HOUR) * HOURS_PER_MONTH
      : null;
    const totalCost = costPerTask !== null ? costPerTask * Math.max(desiredCount, 1) : null;

    const base = {
      provider:     'aws',
      service:      'ECS',
      resourceName: `${clusterName} / ${service.serviceName}`,
      resourceId:   service.serviceArn,
      region,
      metrics: {
        runningTasks:  runningCount,
        desiredTasks:  desiredCount,
        ...(avgCpu  !== null ? { avgCpuPct:  Math.round(avgCpu)  } : {}),
        ...(avgMem  !== null ? { avgMemPct:  Math.round(avgMem)  } : {}),
        ...(taskVcpu  !== null ? { taskVcpu  } : {}),
        ...(taskMemGB !== null ? { taskMemGB } : {}),
        ...(totalCost !== null ? { estimatedMonthlyCostUsd: parseFloat(totalCost.toFixed(2)) } : {}),
      },
    };

    if (desiredCount > 0 && runningCount === 0) {
      findings.push({
        ...base,
        priority: 'HIGH',
        type: 'ECS_NO_RUNNING_TASKS',
        details: `Desired ${desiredCount} task(s) but 0 running${totalCost ? ` — paying $${totalCost.toFixed(2)}/month for nothing` : ''}`,
        recommendation: `Investigate why tasks are not starting (check ECS service events and CloudWatch Logs). If the service is no longer needed, delete it.`,
        estimatedCurrentCost:    totalCost ? parseFloat(totalCost.toFixed(4)) : null,
        estimatedMonthlySavings: totalCost ? parseFloat(totalCost.toFixed(4)) : null,
      });
    } else if (avgCpu !== null && avgMem !== null && avgCpu < 10 && avgMem < 20) {
      findings.push({
        ...base,
        priority: 'MEDIUM',
        type: 'ECS_UNDERUTILISED',
        details: `Avg CPU ${Math.round(avgCpu)}%, Avg Memory ${Math.round(avgMem)}% over ${days} days — allocated ${taskVcpu ?? '?'} vCPU / ${taskMemGB ?? '?'} GB${totalCost ? ` ($${totalCost.toFixed(2)}/month)` : ''}`,
        recommendation: `Reduce task CPU/memory allocation or right-size to a smaller Fargate profile. For dev/test services, consider stopping outside business hours using scheduled scaling.`,
        estimatedCurrentCost:    totalCost ? parseFloat(totalCost.toFixed(4)) : null,
        estimatedMonthlySavings: null,
      });
    }
  }

  return { findings, resourcesScanned: describedServices.length };
}

module.exports = { analyzeECS };
