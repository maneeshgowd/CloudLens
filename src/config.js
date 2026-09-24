'use strict';

module.exports = {
  thresholds: {
    lambda: {
      idleInvocations: 10,         // fewer than this over the window = IDLE
      memoryUtilizationLow: 0.50,  // avg memory used < 50% of configured = over-allocated
      memoryUtilizationVeryLow: 0.30,
    },
    dynamodb: {
      idleConsumedUnits: 1,        // total consumed RCU+WCU < this over window = IDLE
      overProvisionedRatio: 0.10,  // consumed < 10% of provisioned = HIGH (severely over-provisioned)
      underutilisedRatio: 0.20,    // consumed < 20% of provisioned = MEDIUM (over-provisioned per AWS standard)
      // Source: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CostOptimization_RightSizedProvisioning.html
    },
    sns: {
      idleMessages: 10,            // fewer published messages over window = IDLE
    },
    s3: {
      emptyBucketObjects: 0,       // 0 objects = IDLE
    },
    eventbridge: {
      idleInvocations: 1,          // 0 invocations over window = IDLE
    },
    msk: {
      // Health thresholds — sourced from AWS recommended CloudWatch alarms:
      // https://docs.aws.amazon.com/msk/latest/developerguide/bestpractices-cw-alarms.html
      offlinePartitionsAlarm: 0,        // OfflinePartitionsCount > 0 = MSK_OFFLINE (HIGH)
      underMinIsrAlarm: 0,              // UnderMinIsrPartitionCount > 0 = MSK_DURABILITY_RISK (HIGH)
      underReplicatedAlarm: 0,          // UnderReplicatedPartitions > 0 = MSK_DURABILITY_RISK (HIGH)
      diskUsedCritical: 80,             // KafkaDataLogsDiskUsed >= 80% = MSK_DISK_CRITICAL (HIGH)
      // Utilisation thresholds
      underutilizedKBps: 100,           // avg combined throughput < 100 KB/s = MSK_UNDERUTILIZED (MEDIUM)
    },
  },

  // Resources with zero invocations AND unmodified for this many days → ABANDONED (always HIGH, no env downgrade)
  abandonedIdleDays: 28,

  // CloudWatch Logs Insights concurrent query limit
  logsInsightsMaxConcurrency: 10,

  // Max Lambda functions to run memory analysis on (Logs Insights is slow)
  lambdaMemoryAnalysisLimit: 50,

  // Max SNS topics to analyse — accounts can have thousands of auto-created topics
  // (e.g. per-tenant or IoT patterns). Topics beyond this limit are counted but skipped.
  snsAnalysisLimit: 500,

  // Resource name prefixes that are AWS-managed and should never be flagged as findings
  managedPrefixes: [
    'aws-controltower-',
    'awscontroltower',
    'ssmexplorer',
    'aws-config-',
    'aws-service-catalog-',
    'aws-codestar-',
    'stacksets-exec-',
  ],
};
