'use strict';

// AWS MSK (Managed Streaming for Apache Kafka) analyser.
// CloudWatch metrics and alarm thresholds sourced from:
//   https://docs.aws.amazon.com/msk/latest/developerguide/metrics-details.html
//   https://docs.aws.amazon.com/msk/latest/developerguide/bestpractices-cw-alarms.html

const { KafkaClient, ListClustersV2Command } = require('@aws-sdk/client-kafka');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics } = require('./cloudwatch');
const { thresholds, managedPrefixes } = require('../config');

// Approximate on-demand hourly cost per broker (us-east-1).
// Source: https://aws.amazon.com/msk/pricing/
const MSK_BROKER_HOURLY_COST = {
  'kafka.t3.small':    0.048,
  'kafka.m5.large':    0.096,
  'kafka.m5.xlarge':   0.192,
  'kafka.m5.2xlarge':  0.384,
  'kafka.m5.4xlarge':  0.768,
  'kafka.m7g.large':   0.094,
  'kafka.m7g.xlarge':  0.188,
  'kafka.m7g.2xlarge': 0.376,
};
const DEFAULT_BROKER_HOURLY = 0.096; // kafka.m5.large fallback

async function listAllClusters(client) {
  const clusters = [];
  let nextToken;
  do {
    const res = await client.send(new ListClustersV2Command({ NextToken: nextToken, MaxResults: 100 }));
    clusters.push(...(res.ClusterInfoList || []));
    nextToken = res.NextToken;
  } while (nextToken);
  return clusters;
}

async function analyzeMSK({ region, startTime, endTime, days, filter }) {
  const kafkaClient = new KafkaClient({ region });
  const cwClient    = new CloudWatchClient({ region });

  process.stdout.write('  MSK: listing clusters... ');
  let clusters = await listAllClusters(kafkaClient);

  if (filter) {
    const needle = filter.toLowerCase();
    clusters = clusters.filter(c => c.ClusterName.toLowerCase().includes(needle));
  }
  clusters = clusters.filter(c =>
    !managedPrefixes.some(p => c.ClusterName.toLowerCase().startsWith(p))
  );
  console.log(`${clusters.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (clusters.length === 0) return { findings: [], resourcesScanned: 0 };

  // Only analyze ACTIVE provisioned clusters.
  // Serverless clusters use different CloudWatch metrics and billing models.
  const active = clusters.filter(c => c.State === 'ACTIVE' && c.ClusterType === 'PROVISIONED');

  if (active.length === 0) return { findings: [], resourcesScanned: clusters.length };

  // ── Build CloudWatch query specs ───────────────────────────────────────────
  //
  // MSK CloudWatch namespace: AWS/Kafka
  // Cluster-level dimensions: [{ Name: 'Cluster Name', Value: clusterName }]
  // Broker-level dimensions:  [{ Name: 'Cluster Name', ... }, { Name: 'Broker ID', Value: '1' }]
  //
  // Metrics queried:
  //   CLUSTER-LEVEL (DEFAULT monitoring tier):
  //     OfflinePartitionsCount   — should always be 0; alarm at >= 1
  //   BROKER-LEVEL (DEFAULT monitoring tier):
  //     BytesInPerSec            — producer throughput
  //     BytesOutPerSec           — consumer throughput
  //     UnderReplicatedPartitions — should be 0 under normal conditions
  //     UnderMinIsrPartitionCount — partitions below min in-sync replicas; alarm at >= 1
  //     KafkaDataLogsDiskUsed    — disk utilisation %; alarm at >= 80%

  const querySpecs = [];
  const meta = active.map((cluster, ci) => {
    const brokerCount  = cluster.Provisioned?.NumberOfBrokerNodes ?? 3;
    const instanceType = cluster.Provisioned?.BrokerNodeGroupInfo?.InstanceType ?? 'kafka.m5.large';
    const hourly       = MSK_BROKER_HOURLY_COST[instanceType] ?? DEFAULT_BROKER_HOURLY;
    const monthlyCost  = hourly * brokerCount * 24 * 30;

    const clusterDims = [{ Name: 'Cluster Name', Value: cluster.ClusterName }];

    // ── Cluster-level queries ──────────────────────────────────────────────
    const offlineId = `mkoff${ci}`;
    querySpecs.push({
      id: offlineId, namespace: 'AWS/Kafka', metricName: 'OfflinePartitionsCount',
      dimensions: clusterDims, stat: 'Maximum',
    });

    // ── Per-broker queries ─────────────────────────────────────────────────
    const inIds  = [];
    const outIds = [];
    const urpIds = [];
    const isrIds = [];
    const dskIds = [];

    for (let b = 1; b <= brokerCount; b++) {
      const dims = [
        { Name: 'Cluster Name', Value: cluster.ClusterName },
        { Name: 'Broker ID',    Value: String(b) },
      ];
      const inId  = `mkin${ci}b${b}`;
      const outId = `mkout${ci}b${b}`;
      const urpId = `mkurp${ci}b${b}`;
      const isrId = `mkisr${ci}b${b}`;
      const dskId = `mkdsk${ci}b${b}`;

      inIds.push(inId);
      outIds.push(outId);
      urpIds.push(urpId);
      isrIds.push(isrId);
      dskIds.push(dskId);

      querySpecs.push(
        { id: inId,  namespace: 'AWS/Kafka', metricName: 'BytesInPerSec',             dimensions: dims, stat: 'Average' },
        { id: outId, namespace: 'AWS/Kafka', metricName: 'BytesOutPerSec',            dimensions: dims, stat: 'Average' },
        { id: urpId, namespace: 'AWS/Kafka', metricName: 'UnderReplicatedPartitions', dimensions: dims, stat: 'Maximum' },
        { id: isrId, namespace: 'AWS/Kafka', metricName: 'UnderMinIsrPartitionCount', dimensions: dims, stat: 'Maximum' },
        { id: dskId, namespace: 'AWS/Kafka', metricName: 'KafkaDataLogsDiskUsed',     dimensions: dims, stat: 'Maximum' }
      );
    }

    return { cluster, brokerCount, instanceType, monthlyCost, offlineId, inIds, outIds, urpIds, isrIds, dskIds };
  });

  process.stdout.write(`  MSK: fetching metrics for ${active.length} active cluster(s)... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];

  for (const { cluster, brokerCount, instanceType, monthlyCost, offlineId, inIds, outIds, urpIds, isrIds, dskIds } of meta) {
    // Cluster-level
    const maxOffline = cwMetrics[offlineId]?.max ?? 0;

    // Broker-level — aggregate across all brokers
    const totalInSum   = inIds.reduce((s, id)  => s + (cwMetrics[id]?.sum ?? 0), 0);
    const totalOutSum  = outIds.reduce((s, id) => s + (cwMetrics[id]?.sum ?? 0), 0);
    const avgInKBps    = inIds.reduce((s, id)  => s + (cwMetrics[id]?.avg ?? 0), 0) / 1024;
    const avgOutKBps   = outIds.reduce((s, id) => s + (cwMetrics[id]?.avg ?? 0), 0) / 1024;
    const maxUrp       = urpIds.reduce((m, id) => Math.max(m, cwMetrics[id]?.max ?? 0), 0);
    const maxUnderIsr  = isrIds.reduce((m, id) => Math.max(m, cwMetrics[id]?.max ?? 0), 0);
    const maxDiskUsed  = dskIds.reduce((m, id) => Math.max(m, cwMetrics[id]?.max ?? 0), 0);

    // ── MSK_OFFLINE ───────────────────────────────────────────────────────
    // AWS standard: OfflinePartitionsCount should always be 0; alarm at >= 1
    if (maxOffline > thresholds.msk.offlinePartitionsAlarm) {
      findings.push({
        provider:       'aws',
        service:        'MSK',
        resourceName:   cluster.ClusterName,
        resourceId:     cluster.ClusterArn,
        region,
        priority:       'HIGH',
        type:           'MSK_OFFLINE',
        details:        `${maxOffline} partition(s) went offline — consumers are receiving errors and data is unavailable`,
        recommendation: 'Investigate broker health immediately via the MSK console. Check for broker failures, network partitions, or disk exhaustion. OfflinePartitionsCount > 0 is a critical cluster health signal.',
        metrics:        { offlinePartitions: maxOffline, brokerCount, instanceType },
      });
    }

    // ── MSK_DURABILITY_RISK ───────────────────────────────────────────────
    // AWS standard: UnderReplicatedPartitions and UnderMinIsrPartitionCount should be 0
    // UnderMinIsrPartitionCount >= 1 means partitions are below minimum ISR — data at risk of loss
    if (maxUnderIsr > thresholds.msk.underMinIsrAlarm || maxUrp > thresholds.msk.underReplicatedAlarm) {
      const lead = maxUnderIsr > 0
        ? `${maxUnderIsr} partition(s) below minimum in-sync replicas`
        : `${maxUrp} under-replicated partition(s)`;
      findings.push({
        provider:       'aws',
        service:        'MSK',
        resourceName:   cluster.ClusterName,
        resourceId:     cluster.ClusterArn,
        region,
        priority:       'HIGH',
        type:           'MSK_DURABILITY_RISK',
        details:        `${lead} — replication is lagging, data durability is at risk`,
        recommendation: 'Check broker CPU, disk, and network utilisation. Replication lag typically indicates that one or more brokers are overloaded or experiencing connectivity issues. Review the MSK recommended CloudWatch alarms: https://docs.aws.amazon.com/msk/latest/developerguide/bestpractices-cw-alarms.html',
        metrics:        { underMinIsrPartitions: maxUnderIsr, underReplicatedPartitions: maxUrp, brokerCount, instanceType },
      });
    }

    // ── MSK_DISK_CRITICAL ─────────────────────────────────────────────────
    // AWS standard alarm threshold: KafkaDataLogsDiskUsed >= 80%
    if (maxDiskUsed >= thresholds.msk.diskUsedCritical) {
      findings.push({
        provider:       'aws',
        service:        'MSK',
        resourceName:   cluster.ClusterName,
        resourceId:     cluster.ClusterArn,
        region,
        priority:       'HIGH',
        type:           'MSK_DISK_CRITICAL',
        details:        `Broker disk usage reached ${maxDiskUsed.toFixed(0)}% — at 100% the broker stops accepting new messages`,
        recommendation: 'Reduce log retention settings (log.retention.hours / log.retention.bytes), expand broker storage, or enable MSK tiered storage to offload older segments to S3.',
        metrics:        { maxDiskUsedPercent: parseFloat(maxDiskUsed.toFixed(1)), brokerCount, instanceType },
        fixCommand:     `# Reduce retention to free disk space immediately:\naws kafka update-cluster-configuration --cluster-arn "${cluster.ClusterArn}" \\\n  --configuration-info file://reduced-retention-config.json`,
      });
    }

    // ── MSK_IDLE ──────────────────────────────────────────────────────────
    // No producer or consumer traffic detected over the scan window
    if (totalInSum === 0 && totalOutSum === 0) {
      findings.push({
        provider:       'aws',
        service:        'MSK',
        resourceName:   cluster.ClusterName,
        resourceId:     cluster.ClusterArn,
        region,
        priority:       'HIGH',
        type:           'MSK_IDLE',
        details:        `No producer or consumer traffic detected in the last ${days} days`,
        recommendation: `Confirm all producers and consumers have disconnected. If this cluster belongs to a decommissioned workload, delete it. At ~$${monthlyCost.toFixed(0)}/month (${brokerCount}× ${instanceType}), idle MSK clusters are among the costliest orphaned resources in AWS. Consider migrating sporadic workloads to MSK Serverless, which charges only for actual throughput.`,
        metrics:        { bytesInPerSec: 0, bytesOutPerSec: 0, brokerCount, instanceType },
        estimatedMonthlySavings: monthlyCost,
        fixCommand:     `# Inspect cluster before deleting:\naws kafka describe-cluster --cluster-arn "${cluster.ClusterArn}" --region ${region}\n# Delete when confirmed idle:\naws kafka delete-cluster --cluster-arn "${cluster.ClusterArn}"`,
      });
    } else if (avgInKBps < thresholds.msk.underutilizedKBps && avgOutKBps < thresholds.msk.underutilizedKBps) {
      // ── MSK_UNDERUTILIZED ──────────────────────────────────────────────
      findings.push({
        provider:       'aws',
        service:        'MSK',
        resourceName:   cluster.ClusterName,
        resourceId:     cluster.ClusterArn,
        region,
        priority:       'MEDIUM',
        type:           'MSK_UNDERUTILIZED',
        details:        `Low throughput: ~${avgInKBps.toFixed(1)} KB/s in / ~${avgOutKBps.toFixed(1)} KB/s out (${days}-day average)`,
        recommendation: `Consider downsizing the instance type or consolidating workloads onto a shared cluster. Current: ${brokerCount}× ${instanceType} (~$${monthlyCost.toFixed(0)}/month). For variable or low-volume workloads, MSK Serverless eliminates idle capacity costs entirely.`,
        metrics:        {
          avgBytesInKBps:  parseFloat(avgInKBps.toFixed(1)),
          avgBytesOutKBps: parseFloat(avgOutKBps.toFixed(1)),
          brokerCount,
          instanceType,
        },
      });
    }
  }

  const totalMonthlyCost = meta.reduce((s, m) => s + m.monthlyCost, 0);

  return {
    findings,
    resourcesScanned: clusters.length,
    ...(totalMonthlyCost > 0 && { estimatedMonthlyCost: totalMonthlyCost }),
  };
}

module.exports = { analyzeMSK };
