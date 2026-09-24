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
    azure: {
      functions: {
        idleExecutions: 10,          // fewer than this over the window = IDLE
        throttleMinRequests: 10,     // minimum requests before throttle ratio is meaningful
        throttleRatio: 0.05,         // Http429 / Requests above this = THROTTLED
      },
      vm: {
        lowCpuPct: 10,               // avg CPU < 10% while running = OVER_ALLOCATED (MEDIUM)
        veryLowCpuPct: 3,            // avg CPU < 3% while running = OVER_ALLOCATED (HIGH)
      },
      cosmos: {
        overProvisionedRatio: 0.10,  // normalized RU consumption < 10% = HIGH (severely over-provisioned)
        underutilisedRatio: 0.20,    // normalized RU consumption < 20% = MEDIUM (over-provisioned)
      },
      loganalytics: {
        retentionCeilingDays: 90,    // retentionInDays above this = governance finding
      },
      servicebus: {
        staleActiveMessages: 1,      // active/scheduled messages sitting with 0 dequeues over window = STALE_MESSAGES
      },
      keyvault: {
        idleApiHits: 1,              // fewer than this over window = KV_IDLE
      },
      natgateway: {
        idleGB: 0.1,                 // total GB processed below this over window = NAT_IDLE
        lowUtilisationGBPerDay: 1,   // GB/day below this = NAT_LOW_UTILISATION
      },
      eventgrid: {
        idlePublished: 1,            // fewer than this over window = IDLE
      },
      apimanagement: {
        idleRequests: 1,             // fewer than this over window = API_IDLE
      },
      cdn: {
        idleRequests: 1,             // fewer than this over window = CDN_IDLE
      },
      eventhubs: {
        underutilizedKBps: 100,      // avg combined incoming+outgoing throughput < 100 KB/s = EH_UNDERUTILIZED
      },
      containerapps: {
        lowCpuPct: 10,               // avg CPU% below this while running = UNDERUTILISED
        lowMemPct: 20,               // avg memory% below this while running = UNDERUTILISED
      },
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

  // Resource name prefixes that are Azure-managed (auto-created by Azure platform
  // services) and should never be flagged as findings. Distinct from `managedPrefixes`
  // above, which only ever matches AWS resource names.
  azureManagedPrefixes: [
    'networkwatcher_',      // auto-created by Azure Network Watcher, one per region
    'defaultworkspace-',    // auto-created Log Analytics workspace for Defender/Sentinel onboarding
    'cloud-shell-storage-', // auto-created storage account backing Azure Cloud Shell
  ],
};
