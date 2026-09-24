'use strict';

function generateReport({ findings, summary, provider, days }) {
  const isAzure     = provider === 'azure';
  const now         = new Date();
  const highCount   = findings.filter(f => f.priority === 'HIGH').length;
  const mediumCount = findings.filter(f => f.priority === 'MEDIUM').length;
  const lowCount    = findings.filter(f => f.priority === 'LOW').length;
  const scanned     = summary.aws?.resourcesScanned ?? summary.azure?.resourcesScanned ?? 0;
  const costCtx     = summary.aws?.costContext ?? summary.azure?.costContext ?? null;

  const anomalyCount    = findings.filter(f => f.type === 'ANOMALY_DROP').length;
  const deprecatedCount = findings.filter(f => f.type === 'DEPRECATED_RUNTIME').length;
  const missingTagCount = findings.filter(f => f.type === 'MISSING_TAGS').length;
  const pipelineCount   = findings.filter(f => f.type === 'PIPELINE_SILENT').length;
  const abandonedCount  = findings.filter(f => f.type === 'ABANDONED').length;

  const byService = {};
  for (const f of findings) byService[f.service] = (byService[f.service] || 0) + 1;

  const serviceColors = {
    'Lambda':                  '#FF9900', 'Provisioned Concurrency': '#f59e0b',
    'DynamoDB':                '#4A4A9F', 'SNS':                     '#E7157B',
    'S3':                      '#7AA116', 'EventBridge':             '#E7157B',
    'Log Groups':              '#2563eb', 'SQS':                     '#9333ea',
    'ECS':                     '#06b6d4', 'NAT Gateway':             '#64748b',
    'API Gateway':             '#8b5cf6', 'Secrets Manager':         '#ec4899',
    'CloudFront':              '#0ea5e9', 'MSK':                     '#FF6B35',
    'Azure Functions':         '#0078d4', 'Virtual Machines':        '#0078d4',
    'App Service':             '#0078d4', 'Blob Storage':            '#0072c6',
    'Cosmos DB':               '#0072c6', 'Service Bus':             '#0078d4',
    'Log Analytics':           '#0078d4', 'Azure Monitor':           '#0072c6',
    'Key Vault':               '#0072c6', 'Event Grid':              '#0078d4',
    'API Management':          '#0072c6', 'CDN':                     '#0078d4',
    'Event Hubs':              '#0072c6', 'Container Apps':          '#0078d4',
  };
  const serviceIconLabel = {
    'Lambda':'λ', 'Provisioned Concurrency':'PC', 'DynamoDB':'DB', 'SNS':'SNS',
    'S3':'S3', 'EventBridge':'EB', 'Log Groups':'CW', 'SQS':'SQS', 'ECS':'ECS',
    'NAT Gateway':'NAT', 'API Gateway':'API', 'Secrets Manager':'SM', 'CloudFront':'CF',
    'MSK':'MSK', 'Azure Functions':'fn', 'Virtual Machines':'VM', 'App Service':'APP',
    'Blob Storage':'BLOB', 'Cosmos DB':'CDB', 'Service Bus':'SB', 'Log Analytics':'LA', 'Azure Monitor':'MON',
    'Key Vault':'KV', 'Event Grid':'EG', 'API Management':'APIM', 'CDN':'CDN',
    'Event Hubs':'EH', 'Container Apps':'CA',
  };

  // ── Type grouping ──────────────────────────────────────────────────────────
  const TYPE_TO_GROUP = {
    PIPELINE_SILENT:    'PIPELINE_SILENT',
    DEPRECATED_RUNTIME: 'DEPRECATED_RUNTIME',
    ABANDONED:          'ABANDONED',
    ANOMALY_DROP:       'ANOMALY_DROP',
    HIGH_ERROR_RATE:    'HIGH_ERROR_RATE',
    MSK_OFFLINE:        'HIGH_ERROR_RATE',
    MSK_DISK_CRITICAL:  'HIGH_ERROR_RATE',
    IDLE:               'IDLE',
    PC_IDLE:            'IDLE',
    MSK_IDLE:           'IDLE',
    MSK_UNDERUTILIZED:  'IDLE',
    PC_OVER_PROVISIONED:'IDLE',
    OVER_ALLOCATED:     'IDLE',
    OVER_PROVISIONED:   'IDLE',
    STOPPED_NOT_DEALLOCATED: 'IDLE',
    THROTTLED:          'IDLE',
    API_IDLE:           'IDLE',
    CDN_IDLE:           'IDLE',
    EH_IDLE:            'IDLE',
    EH_UNDERUTILIZED:   'IDLE',
    EH_THROTTLED:       'IDLE',
    CA_NO_RUNNING_REPLICAS: 'IDLE',
    UNDERUTILISED:      'IDLE',
    NAT_IDLE:           'IDLE',
    NAT_LOW_UTILISATION:'IDLE',
    DLQ_MESSAGES:       'QUEUE',
    STALE_MESSAGES:     'QUEUE',
    MSK_DURABILITY_RISK:'QUEUE',
    MISSING_TAGS:       'GOVERNANCE',
    NO_RETENTION:       'GOVERNANCE',
    KV_NO_SOFT_DELETE:      'GOVERNANCE',
    KV_NO_PURGE_PROTECTION: 'GOVERNANCE',
    KV_PUBLIC_ACCESS:       'GOVERNANCE',
  };
  function typeGroupOf(t) { return TYPE_TO_GROUP[t] || 'OTHER'; }

  const groupCounts = {};
  for (const f of findings) {
    const g = typeGroupOf(f.type);
    groupCounts[g] = (groupCounts[g] || 0) + 1;
  }

  // Tab definitions — only show tabs that have at least one finding
  const accessTermTab   = isAzure ? 'RBAC role assignments' : 'IAM (access) permissions';
  const patcherTab      = isAzure ? 'Microsoft' : 'AWS';
  const pipelineSourceTab = isAzure ? 'Event Grid topics' : 'Scheduled rules (EventBridge)';
  const pipelineTargetTab = isAzure ? 'Azure Function' : 'Lambda function';
  const TAB_DEFS = [
    { type:'ALL',                icon:'≡',  label:'All Findings',     desc:'',          color:'#60a5fa' },
    { type:'PIPELINE_SILENT',    icon:'⏸',  label:'Silent Pipelines', desc:`${pipelineSourceTab} are active and provisioned, but zero events are reaching the target ${pipelineTargetTab}. The automated pipeline is broken — and no alarm has fired to alert you.`, color:'#f97316' },
    { type:'DEPRECATED_RUNTIME', icon:'⚠',  label:'EOL Runtimes',     desc:`Functions running software versions (Node.js, Python, etc.) that ${patcherTab} no longer patches. Any security vulnerability published after the end-of-life date remains permanently unpatched in production.`, color:'#ef4444' },
    { type:'ABANDONED',          icon:'◌',  label:'Dead Code',        desc:`Resources deployed with zero activity for an extended period — dead weight still holding live ${accessTermTab} and accumulating unpatched vulnerabilities as the runtime ages.`, color:'#f87171' },
    { type:'ANOMALY_DROP',       icon:'↘',  label:'Traffic Anomalies',desc:'Functions showing a sharp drop in invocations vs the prior period — typically a broken upstream caller or a silent deployment failure that no alarm caught.', color:'#ef4444' },
    { type:'HIGH_ERROR_RATE',    icon:'✕',  label:'High Error Rate',  desc:'Resources where a significant percentage of operations are failing (errors, timeouts, dropped packets, restarts, or failed deliveries). Cost is being spent on failed work that produces no value for users or downstream systems.', color:'#ef4444' },
    { type:'IDLE',               icon:'□',  label:'Idle Resources',   desc:'Resources consuming allocated capacity (and cost) with minimal or zero actual usage — over-allocated memory, idle provisioned/throughput units, underutilised clusters or gateways.', color:'#fb923c' },
    { type:'QUEUE',              icon:'▣',  label:'Queue Issues',     desc:'Message queues and topics (SQS/Service Bus/Event Grid, dead-letter destinations) with stuck or unprocessed messages — indicating processing failures or backlog accumulation that may affect downstream consumers.', color:'#fb923c' },
    { type:'GOVERNANCE',         icon:'▤',  label:'Governance',       desc:'Missing resource tags, absent log retention policies, disabled soft-delete/purge protection, open network access, and other hygiene issues that affect cost attribution, security policies, and compliance requirements.', color:'#94a3b8' },
  ];

  const tabsHTML = TAB_DEFS
    .filter(t => t.type === 'ALL' || (groupCounts[t.type] || 0) > 0)
    .map(t => {
      const count = t.type === 'ALL' ? findings.length : (groupCounts[t.type] || 0);
      return `<button class="type-tab${t.type === 'ALL' ? ' active' : ''}"
        data-type="${t.type}"
        data-desc="${escapeHtml(t.desc)}"
        data-label="${escapeHtml(t.label)}"
        data-icon="${escapeHtml(t.icon)}"
        onclick="setTypeFilter('${t.type}',this)">
        <span class="tab-icon">${t.icon}</span>
        <span class="tab-label">${escapeHtml(t.label)}</span>
        <span class="tab-count" style="color:${t.color}">${count}</span>
      </button>`;
    }).join('');

  // Plain-English explanations shown inside the detail panel
  const patcher     = isAzure ? 'Microsoft' : 'AWS';
  const throttleExplain = isAzure
    ? 'This function is being throttled — a large share of requests are returning HTTP 429 as the app hits its plan\'s concurrency or scale-out limits. Affected calls may fail silently without a retry mechanism.'
    : 'This function is being throttled — AWS is rejecting invocations because concurrent execution limits are reached. Affected calls may fail silently without a retry mechanism.';
  const abandonedExplain = isAzure
    ? 'Zero executions over the window and the app is stopped or disabled. This is dead weight — but it still holds live RBAC role assignments, connection strings, and app settings, and will accumulate unpatched vulnerabilities as its runtime ages.'
    : 'Zero invocations for an extended period with no recent code changes. This is dead code — but it still holds live IAM permissions and will accumulate unpatched vulnerabilities as its runtime ages. Every deployed Lambda is an attack surface, active or not.';

  const pipelineExplain = isAzure
    ? 'This Event Grid topic is provisioned and enabled, but zero events are arriving at its target Azure Function. The automated pipeline is completely broken — and no Azure Monitor alert has fired to tell you. This failure is only visible when Event Grid and Functions are analysed together.'
    : 'This EventBridge rule is enabled and scheduled to run, but zero events are arriving at its target Lambda function. The automated pipeline is completely broken — and no CloudWatch alarm has fired to alert you. This failure is only visible when EventBridge and Lambda are analysed together.';

  const TYPE_EXPLAIN = {
    PIPELINE_SILENT:     pipelineExplain,
    DEPRECATED_RUNTIME:  `${patcher} has stopped releasing security patches for this software version. Any CVE (security vulnerability) published after the end-of-life date is permanently unpatched in this function. These appear as open findings in security audits and can block compliance certifications.`,
    ABANDONED:           abandonedExplain,
    ANOMALY_DROP:        "This function's invocations dropped sharply compared to the prior period. This is typically caused by a broken upstream caller that stopped sending requests, or a silent deployment failure that reduced traffic without triggering any monitoring alert.",
    HIGH_ERROR_RATE:     'More than 20% of operations are failing (errors, timeouts, dropped packets, or failed deliveries, depending on the service). Cost is being spent on failed work, and any services or users depending on this resource may be receiving errors.',
    IDLE:                'This resource is consuming allocated capacity (and cost) with minimal or zero actual usage. Rightsizing or removing it recovers cost without impacting active workloads.',
    PC_IDLE:             'Provisioned Concurrency keeps instances warm to eliminate cold starts — but this function has had zero invocations. You are paying for warm instances that are never invoked.',
    PC_OVER_PROVISIONED: 'Provisioned Concurrency is set higher than the function\'s peak utilisation. Reducing the setting saves cost without impacting cold-start performance.',
    DLQ_MESSAGES:        'Messages or events have accumulated in the dead-letter destination — the primary subscriber is failing to process them. These failed items have not been processed or reviewed.',
    STALE_MESSAGES:      'Messages in this queue are older than expected, suggesting the consumer stopped processing or the queue is backed up with unhandled messages.',
    MISSING_TAGS:        'This resource is missing recommended tags (Environment, Team/Owner). Tags are required for cost attribution, security policies, and automated governance across the account/subscription.',
    NO_RETENTION:        'This log group has no retention policy — logs are kept indefinitely, accumulating storage costs and potentially complicating data-retention compliance.',
    THROTTLED:           throttleExplain,
    OVER_ALLOCATED:      'Configured memory is far above actual peak usage. Cloud providers charge for configured memory, not used memory — reducing the setting directly reduces compute cost per invocation.',
    OVER_PROVISIONED:    'Provisioned capacity (throughput, RU/s, IOPS, gateway scale units) is far above actual usage. You are paying for capacity that sits idle — reducing it, or switching to an autoscale/on-demand mode, cuts cost without affecting performance.',
    STOPPED_NOT_DEALLOCATED: 'This VM is stopped but not deallocated — Azure still reserves and bills for its compute capacity. Only a deallocated VM stops compute charges; a merely-stopped one keeps costing money while doing no work.',
    MSK_OFFLINE:         'This Kafka (MSK) cluster has offline partitions — topic partitions are unavailable, meaning producers cannot write and consumers cannot read the affected data.',
    MSK_DURABILITY_RISK: 'The replication factor is below the recommended minimum. A single broker failure could result in data loss on this cluster.',
    MSK_DISK_CRITICAL:   'Disk usage on this MSK cluster is critically high. When disks fill completely, Kafka brokers can fail and data can be lost.',
    MSK_IDLE:            'This Kafka (MSK) cluster has had minimal or zero message traffic. MSK is one of the more expensive AWS services — an idle cluster is significant cost waste.',
    MSK_UNDERUTILIZED:   'This MSK cluster has low throughput relative to its provisioned broker capacity. Consider scaling down to a smaller broker type to reduce cost.',
    API_IDLE:            'This API Management gateway has served zero requests over the window. Dedicated tiers (Developer, Basic, Standard, Premium) bill a fixed fee regardless of traffic — an idle gateway is pure waste. Consumption tier has no fixed cost, but an unused gateway is still clutter and an unnecessary attack surface.',
    CDN_IDLE:            'This CDN endpoint is provisioned and configured but has served zero requests. It carries no direct data-transfer cost while idle, but represents an unused, unmonitored edge of your attack surface.',
    CDN_ACTIVE:          'This CDN endpoint is actively serving traffic. Shown for cost visibility — review cache hit ratio and compression settings to ensure you are not paying for avoidable origin fetches.',
    EH_IDLE:             'This Event Hubs namespace has had zero messages in or out over the window. Throughput units are billed on a fixed hourly basis regardless of traffic — an idle namespace is a fixed, avoidable cost.',
    EH_UNDERUTILIZED:    'This Event Hubs namespace is provisioned with more throughput units than its actual traffic requires. You are paying for ingress/egress capacity that sits mostly idle.',
    EH_THROTTLED:        'Producers or consumers on this Event Hubs namespace are being throttled or hitting quota limits. This causes retries, added latency, or dropped events on the client side.',
    CA_NO_RUNNING_REPLICAS: 'This Container App is configured to always run at least one replica (minReplicas > 0), but zero replicas actually ran during the window. You are paying the fixed per-replica charge for a container that never started successfully.',
    UNDERUTILISED:       'This Container App\'s replicas are running well below their allocated CPU and memory. Container Apps bills per-replica resource allocation regardless of actual usage, so lowering the per-container CPU/memory (or replica count) directly reduces cost.',
    KV_NO_SOFT_DELETE:   'Soft delete is disabled on this Key Vault. Without it, a deleted vault and every secret, key, and certificate inside it is unrecoverable — accidental deletion becomes permanent data loss.',
    KV_NO_PURGE_PROTECTION: 'Purge protection is disabled. Soft delete alone still allows anyone with delete permissions to permanently purge the vault before its retention period ends, bypassing the recovery window soft delete is meant to provide.',
    KV_PUBLIC_ACCESS:    'This vault\'s network ACLs default to allowing access from any public IP. Secrets, keys, and certificates are reachable over the public internet unless narrowed by an explicit allow-list, virtual network rule, or private endpoint.',
    NAT_IDLE:            'This NAT Gateway processed minimal or no traffic over the window. NAT Gateways bill a fixed hourly charge regardless of traffic volume, so an idle gateway is a fixed, avoidable cost.',
    NAT_LOW_UTILISATION: 'This NAT Gateway is seeing low outbound traffic relative to a dedicated gateway\'s fixed cost. Consider consolidating with another subnet\'s gateway if this level of usage persists.',
  };

  // ── Executive summary ──────────────────────────────────────────────────────
  const HTYPES      = new Set(['ANOMALY_DROP','HIGH_ERROR_RATE','PIPELINE_SILENT','DLQ_MESSAGES','STALE_MESSAGES','ABANDONED','THROTTLED','EH_THROTTLED','CA_NO_RUNNING_REPLICAS']);
  const healthCount   = findings.filter(f => HTYPES.has(f.type)).length;
  const securityCount = findings.filter(f => f.type === 'DEPRECATED_RUNTIME' || f.type === 'ABANDONED').length;
  const totalSpend    = costCtx?.totalEstimatedCost ?? 0;
  const totalSavings  = findings.reduce((sum, f) => sum + (f.estimatedMonthlySavings || 0), 0);
  const annualWaste   = totalSavings * 12;

  const RANK = { ABANDONED:0, ANOMALY_DROP:1, MSK_OFFLINE:1, HIGH_ERROR_RATE:2, MSK_DURABILITY_RISK:2, MSK_DISK_CRITICAL:2, MSK_IDLE:2, PIPELINE_SILENT:3, PC_IDLE:4, DLQ_MESSAGES:5, DEPRECATED_RUNTIME:6, PC_OVER_PROVISIONED:7, STALE_MESSAGES:8, OVER_ALLOCATED:9, MSK_UNDERUTILIZED:8 };
  const spotlightItems = findings.slice()
    .sort((a, b) => {
      const pOrder = { HIGH:0, MEDIUM:1, LOW:2 };
      const pDiff = (pOrder[a.priority] ?? 3) - (pOrder[b.priority] ?? 3);
      if (pDiff !== 0) return pDiff;
      const rDiff = (RANK[a.type] ?? 99) - (RANK[b.type] ?? 99);
      if (rDiff !== 0) return rDiff;
      return (b.estimatedMonthlySavings || 0) - (a.estimatedMonthlySavings || 0);
    })
    .slice(0, 3);

  // ── Narrative paragraph ────────────────────────────────────────────────────
  const narrativeParts = [];
  const serviceCount = Object.keys(byService).length;

  if (deprecatedCount > 0) {
    const eolRuntimes = [...new Set(findings.filter(f => f.type === 'DEPRECATED_RUNTIME').map(f => f.metrics?.runtime).filter(Boolean))];
    const runtimeList = eolRuntimes.length > 0 ? ` (${eolRuntimes.slice(0, 3).join(', ')})` : '';
    narrativeParts.push(
      `<strong>${deprecatedCount} function${deprecatedCount > 1 ? 's are' : ' is'} running end-of-life runtimes${runtimeList}</strong> — ` +
      `${patcherTab} has stopped shipping security patches. Any CVE published since the EOL date is permanently unpatched in production.`
    );
  }
  if (pipelineCount > 0) {
    const pl = pipelineCount > 1;
    const pipelineSourceNarr = isAzure ? 'Event Grid topic' : 'EventBridge rule';
    narrativeParts.push(
      `<strong>${pipelineCount} automated pipeline${pl ? 's are' : ' is'} completely silent</strong> — ` +
      `the ${pipelineSourceNarr}${pl ? 's are' : ' is'} enabled and provisioned but zero events are reaching the target function${pl ? 's' : ''}. No alarm has fired.`
    );
  }
  const anomalyFindings = findings.filter(f => f.type === 'ANOMALY_DROP');
  if (anomalyFindings.length > 0) {
    narrativeParts.push(
      `<strong>${anomalyFindings.length} function${anomalyFindings.length > 1 ? 's show' : ' shows'} a sharp traffic drop vs the prior period</strong> — ` +
      `likely a broken upstream dependency or a silent deployment failure.`
    );
  }
  const abandonedFindings = findings.filter(f => f.type === 'ABANDONED')
    .sort((a, b) => (b.metrics?.lastModifiedDaysAgo ?? 0) - (a.metrics?.lastModifiedDaysAgo ?? 0));
  if (abandonedFindings.length > 0) {
    const oldest = abandonedFindings[0];
    const age    = oldest.metrics?.lastModifiedDaysAgo;
    const ageStr = age != null ? (age >= 365 ? `~${(age / 365).toFixed(1)} years` : `${age} days`) : 'an extended period';
    const resourceNoun = isAzure ? 'resource' : 'Lambda function';
    narrativeParts.push(
      `<strong>${abandonedFindings.length} ${resourceNoun}${abandonedFindings.length > 1 ? 's have' : ' has'} been deployed for months with zero activity</strong> — ` +
      `dead weight still holding live ${accessTermTab}. Oldest: <code>${escapeHtml(oldest.resourceName)}</code>, unmodified for ${ageStr}.`
    );
  }
  narrativeParts.push(
    `Scan covered <strong>${scanned} resources</strong> across <strong>${serviceCount} service${serviceCount !== 1 ? 's' : ''}</strong> ` +
    `over the last <strong>${days} days</strong> — ${findings.length} finding${findings.length !== 1 ? 's' : ''} total, ${highCount} high priority.`
  );

  const narrativeHTML = `<div class="narrative-bar">${narrativeParts.join(' ')}</div>`;

  // ── Critical resources (2+ findings on same resource) ─────────────────────
  const resourceMap = new Map();
  for (const f of findings) {
    const key = f.resourceName;
    if (!resourceMap.has(key)) resourceMap.set(key, { service: f.service, findings: [] });
    resourceMap.get(key).findings.push(f);
  }
  const PRIORITY_RANK = { HIGH:0, MEDIUM:1, LOW:2 };
  const criticalResources = [...resourceMap.entries()]
    .map(([name, { service, findings: fns }]) => ({ name, service, findings: fns }))
    .filter(r => r.findings.length >= 2)
    .sort((a, b) => {
      const aHigh = a.findings.filter(f => f.priority === 'HIGH').length;
      const bHigh = b.findings.filter(f => f.priority === 'HIGH').length;
      return bHigh !== aHigh ? bHigh - aHigh : b.findings.length - a.findings.length;
    })
    .slice(0, 5);

  function typeLabel(type) {
    const labels = {
      ABANDONED:'Dead Code', DEPRECATED_RUNTIME:'EOL Runtime', PIPELINE_SILENT:'Silent Pipeline',
      ANOMALY_DROP:'Traffic Anomaly', HIGH_ERROR_RATE:'High Error Rate', IDLE:'Idle',
      OVER_ALLOCATED:'Over-allocated', THROTTLED:'Throttled', DLQ_MESSAGES:'Dead Letter Queue',
      STALE_MESSAGES:'Stale Messages', PC_IDLE:'Idle (Prov. Concurrency)', PC_OVER_PROVISIONED:'Over-provisioned (PC)',
      MSK_IDLE:'Idle Cluster', MSK_UNDERUTILIZED:'Low Utilisation', MSK_OFFLINE:'Offline Partitions',
      MSK_DURABILITY_RISK:'Durability Risk', MSK_DISK_CRITICAL:'Disk Critical',
      MISSING_TAGS:'Missing Tags', NO_RETENTION:'No Log Retention',
      OVER_PROVISIONED:'Over-provisioned', STOPPED_NOT_DEALLOCATED:'Stopped, Not Deallocated',
      API_IDLE:'Idle Gateway', CDN_IDLE:'Idle Endpoint', CDN_ACTIVE:'Active (Cost Visibility)',
      EH_IDLE:'Idle Namespace', EH_UNDERUTILIZED:'Low Throughput', EH_THROTTLED:'Throttled',
      CA_NO_RUNNING_REPLICAS:'No Running Replicas', UNDERUTILISED:'Underutilised',
      KV_NO_SOFT_DELETE:'No Soft Delete', KV_NO_PURGE_PROTECTION:'No Purge Protection',
      KV_PUBLIC_ACCESS:'Public Network Access', NAT_IDLE:'Idle Gateway', NAT_LOW_UTILISATION:'Low Utilisation',
    };
    return labels[type] || type.replace(/_/g, ' ');
  }

  function buildCriticalCard(r) {
    const bg   = serviceColors[r.service]    || '#6b7280';
    const lbl  = serviceIconLabel[r.service] || r.service[0];
    const sortedF = r.findings.slice().sort((a, b) => (PRIORITY_RANK[a.priority] ?? 3) - (PRIORITY_RANK[b.priority] ?? 3));
    const pills = sortedF.map(f =>
      '<span class="cr-pill cr-pill-' + f.priority + '">' + typeLabel(f.type) + '</span>'
    ).join('');
    const crHigh = r.findings.filter(f => f.priority === 'HIGH').length;
    return '<div class="critical-card">'
      + '<div class="cr-left"><div class="cr-count">' + r.findings.length + '</div>'
      + '<div class="cr-count-label">issue' + (r.findings.length > 1 ? 's' : '') + '</div></div>'
      + '<div class="cr-bar" style="background:' + bg + '"></div>'
      + '<div class="cr-body">'
      + '<div class="cr-name"><span class="service-icon-sm" style="background:' + bg + '">' + lbl + '</span>' + escapeHtml(r.name) + '</div>'
      + '<div class="cr-pills">' + pills + '</div>'
      + '<div class="cr-detail">' + escapeHtml(sortedF[0].details) + '</div>'
      + '</div>'
      + (crHigh > 0 ? '<div class="cr-high-badge">' + crHigh + ' HIGH</div>' : '')
      + '</div>';
  }

  const criticalResourcesHTML = criticalResources.length > 0
    ? '<div class="section-title" style="margin-top:0.25rem">Resources with multiple issues</div>'
      + '<div class="critical-list">' + criticalResources.map(buildCriticalCard).join('') + '</div>'
    : '';

  function buildSpotlightCard(f, n) {
    const icons = ['①', '②', '③'];
    const bg  = serviceColors[f.service] || '#6b7280';
    const lbl = serviceIconLabel[f.service] || f.service[0];
    const savPill = f.estimatedMonthlySavings > 0
      ? ' <span class="spotlight-cost">~$' + f.estimatedMonthlySavings.toFixed(2) + '/mo wasted</span>'
      : '';
    return '<div class="spotlight-card spotlight-' + f.priority + '">'
      + '<div class="spotlight-num">' + icons[n] + '</div>'
      + '<div class="spotlight-svc-icon" style="background:' + bg + '">' + lbl + '</div>'
      + '<div class="spotlight-body">'
      + '<div class="spotlight-meta">'
      + '<span class="badge badge-' + f.priority + '">' + f.priority + '</span>'
      + '<span class="spotlight-service">' + escapeHtml(f.service) + '</span>'
      + '<span class="spotlight-type">' + typeLabel(f.type) + '</span>'
      + '<span class="spotlight-resource">' + escapeHtml(f.resourceName) + '</span>'
      + '</div>'
      + '<div class="spotlight-detail">' + escapeHtml(f.details) + savPill + '</div>'
      + '</div>'
      + '</div>';
  }

  const spotlightHTML = spotlightItems.length > 0
    ? '<div class="section-title">Top Issues</div>'
      + '<div class="spotlight-list">' + spotlightItems.map(buildSpotlightCard).join('') + '</div>'
    : '';

  const execSummaryHTML = '<div class="exec-summary">'
    + '<div class="exec-headline">'
    + '<div class="exec-metric health"><div class="exec-metric-value">' + healthCount + '</div>'
    + '<div class="exec-metric-label">Active Health Issues</div>'
    + '<div class="exec-metric-sub">errors · anomalies · silent pipelines</div></div>'
    + '<div class="exec-metric security"><div class="exec-metric-value">' + securityCount + '</div>'
    + '<div class="exec-metric-label">Security Exposure</div>'
    + '<div class="exec-metric-sub">EOL runtimes · unpatched CVEs</div></div>'
    + '<div class="exec-metric waste"><div class="exec-metric-value">' + (annualWaste > 0 ? '$' + annualWaste.toFixed(0) : '—') + '</div>'
    + '<div class="exec-metric-label">Est. Annual Waste</div>'
    + '<div class="exec-metric-sub">' + (annualWaste > 0 ? 'recoverable with no architectural changes' : 'no direct cost savings detected') + '</div></div>'
    + '</div></div>';

  const costContextHTML = costCtx && (totalSpend > 0 || totalSavings > 0) ? `<div class="cost-context-bar">
    <span class="cost-label">Est. monthly spend:</span>
    <span class="cost-total">$${totalSpend.toFixed(2)}<span style="font-size:0.7rem;opacity:0.7">/mo</span></span>
    ${totalSavings > 0 ? `<span class="cost-savings-pill">↓ $${totalSavings.toFixed(2)}/mo recoverable</span>` : ''}
    <span class="cost-services">${(costCtx.topServices || []).slice(0, 6).map(s => `<span class="cost-chip">${s.service}: <strong>$${s.amount.toFixed(2)}</strong></span>`).join('')}</span>
  </div>` : '';

  const serviceBreakdownHTML = Object.entries(byService).sort((a, b) => b[1] - a[1]).map(([svc, cnt]) => {
    const bg  = serviceColors[svc] || '#6b7280';
    const lbl = serviceIconLabel[svc] || svc[0];
    return `<div class="service-tile"><div class="service-icon-lg" style="background:${bg}">${lbl}</div><div class="svc-count">${cnt}</div><div class="svc-name">${svc}</div></div>`;
  }).join('');

  const chartLabels = Object.keys(byService);
  const chartCounts = Object.values(byService);
  const chartColors = chartLabels.map(s => serviceColors[s] || '#6b7280');

  // ── Findings rows ──────────────────────────────────────────────────────────
  const findingsRowsHTML = findings.map((f, idx) => {
    const bg    = serviceColors[f.service] || '#6b7280';
    const lbl   = serviceIconLabel[f.service] || f.service[0];
    const typeG = typeGroupOf(f.type);
    const metricsHTML = Object.entries(f.metrics || {})
      .map(([k, v]) => `<div class="metric-row"><span class="metric-label">${fmtKey(k)}</span><span class="metric-value">${fmtVal(k, v)}</span></div>`)
      .join('');
    const s = f.estimatedMonthlySavings;
    const savingsHTML = s > 0
      ? `<span class="savings-badge">${s < 0.01 ? '< $0.01' : '~$' + s.toFixed(2)}/mo</span>`
      : '<span class="savings-nil">—</span>';
    const envBadge = f.environment
      ? `<span class="env-badge env-${f.environment}">${f.environment}</span>`
      : '';
    const fixSection = f.fixCommand ? `
      <div class="fix-section">
        <h4>Fix Command</h4>
        <pre class="fix-command" id="fix-cmd-${idx}">${escapeHtml(f.fixCommand)}</pre>
        <button class="copy-btn fix-copy-btn" onclick="copyFix(${idx}, event)">Copy</button>
      </div>` : '';
    const alarmSection = f.suggestedAlarm ? `
      <div class="alarm-section">
        <h4>${f.type === 'NO_RETENTION' ? 'Remediation Command' : 'Suggested Alarm'}</h4>
        <pre class="alarm-command" id="alarm-cmd-${idx}">${escapeHtml(f.suggestedAlarm)}</pre>
        <button class="copy-btn" onclick="copyAlarm(${idx}, event)">Copy</button>
      </div>` : '';

    const explainText = TYPE_EXPLAIN[f.type] || '';
    const explainBox  = explainText ? `
      <div class="type-explain-box">
        <div class="explain-title">What does this mean?</div>
        <div class="explain-text">${escapeHtml(explainText)}</div>
      </div>` : '';

    return `
      <tr class="finding-row" id="frow-${idx}" onclick="toggleDetail(${idx})"
          data-priority="${f.priority}"
          data-service="${escapeHtml(f.service)}"
          data-name="${escapeHtml(f.resourceName).toLowerCase()}"
          data-env="${escapeHtml(f.environment || 'unknown')}"
          data-team="${escapeHtml(f.team || '')}"
          data-typegroup="${typeG}">
        <td><span class="badge badge-${f.priority}">${f.priority}</span></td>
        <td><span class="service-icon-sm" style="background:${bg}">${lbl}</span>${escapeHtml(f.service)}</td>
        <td>${envBadge}<span class="resource-name">${escapeHtml(f.resourceName)}</span></td>
        <td><span class="badge badge-type badge-type-${f.type}">${typeLabel(f.type)}</span></td>
        <td class="details-cell">${escapeHtml(f.details)}</td>
        <td class="savings-cell">${savingsHTML}</td>
        <td class="chevron-cell"><span class="chevron" id="chev-${idx}">▸</span></td>
      </tr>
      <tr class="detail-row" id="detail-${idx}">
        <td colspan="7">
          <div class="detail-content">
            <div class="detail-section">
              <h4>Metrics (last ${days} days)</h4>
              ${metricsHTML || '<div class="metric-row"><span class="metric-label">No metrics available</span></div>'}
            </div>
            <div class="detail-section">
              ${explainBox}
              <h4>Recommendation</h4>
              <div class="recommendation">${escapeHtml(f.recommendation || '')}</div>
              <div class="resource-arn">${escapeHtml(f.resourceId || '')}</div>
              ${fixSection}
              ${alarmSection}
            </div>
          </div>
        </td>
      </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudLens — ${provider.toUpperCase()} Health &amp; Cost Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"><\/script>
  <style>
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface-2: #243044;
      --text: #e2e8f0; --muted: #94a3b8; --border: #334155;
      --high: #ef4444; --medium: #f97316; --low: #eab308;
      --aws: #FF9900; --blue: #3b82f6; --green: #22c55e;
      --radius: 10px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }

    /* ── Header ── */
    .header { background: linear-gradient(135deg, #1e3a8a 0%, #1d4ed8 60%, #4f46e5 100%); padding: 1.5rem 2.5rem; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.07); }
    .header h1 { font-size: 1.6rem; font-weight: 800; letter-spacing: -0.5px; }
    .header h1 .lens { color: #93c5fd; }
    .header-tagline { color: #bfdbfe; font-size: 0.8rem; margin-top: 0.2rem; }
    .header-right { text-align: right; color: #bfdbfe; font-size: 0.8rem; line-height: 1.8; }
    .header-right strong { color: white; }

    .container { max-width: 1440px; margin: 0 auto; padding: 1.75rem 2.5rem; }
    .section-title { font-size: 0.68rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 0.75rem; }

    /* ── Cost context bar ── */
    .cost-context-bar { background: rgba(59,130,246,0.07); border: 1px solid rgba(59,130,246,0.18); border-radius: var(--radius); padding: 0.75rem 1.25rem; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; font-size: 0.8rem; }
    .cost-label { color: var(--muted); }
    .cost-total { font-size: 1.1rem; font-weight: 700; color: var(--aws); }
    .cost-services { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .cost-chip { background: var(--surface); border: 1px solid var(--border); border-radius: 99px; padding: 0.2rem 0.6rem; color: var(--muted); font-size: 0.72rem; }
    .cost-chip strong { color: var(--text); }
    .cost-savings-pill { background: rgba(34,197,94,0.13); border: 1px solid rgba(34,197,94,0.28); border-radius: 99px; padding: 0.2rem 0.75rem; color: #4ade80; font-size: 0.75rem; font-weight: 700; }

    /* ── Stats grid ── */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.875rem; margin-bottom: 1.5rem; }
    .stat-card { background: var(--surface); border-radius: var(--radius); padding: 1.1rem 1.4rem; border: 1px solid var(--border); }
    .stat-value { font-size: 2.1rem; font-weight: 800; line-height: 1; }
    .stat-label { color: var(--muted); font-size: 0.72rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.4px; }
    .stat-card.high    .stat-value { color: var(--high); }
    .stat-card.medium  .stat-value { color: var(--medium); }
    .stat-card.low     .stat-value { color: var(--low); }
    .stat-card.total   .stat-value { color: #60a5fa; }
    .stat-card.spend   .stat-value { color: var(--aws); }
    .stat-card.savings .stat-value { color: var(--green); }
    .stat-card.scanned .stat-value { color: var(--muted); }
    .stat-card.anomaly .stat-value { color: #f87171; }
    .stat-card.runtime .stat-value { color: #fb923c; }
    .stat-card.tags    .stat-value { color: #94a3b8; }
    .stat-card.pipeline   .stat-value { color: #fb923c; }
    .stat-card.abandoned  .stat-value { color: #fca5a5; }

    /* ── Dashboard row ── */
    .dashboard-row { display: grid; grid-template-columns: 1fr 280px; gap: 1.5rem; margin-bottom: 1.75rem; align-items: start; }
    .service-breakdown { display: flex; gap: 0.75rem; flex-wrap: wrap; }
    .service-tile { background: var(--surface); border-radius: var(--radius); border: 1px solid var(--border); padding: 0.875rem 1rem; text-align: center; min-width: 90px; }
    .service-icon-lg { width: 34px; height: 34px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.62rem; font-weight: 800; color: white; margin-bottom: 0.4rem; }
    .svc-count { font-size: 1.35rem; font-weight: 700; color: var(--aws); }
    .svc-name  { font-size: 0.68rem; color: var(--muted); margin-top: 0.1rem; }
    .chart-card { background: var(--surface); border-radius: var(--radius); border: 1px solid var(--border); padding: 1.1rem; }
    .chart-card canvas { max-height: 220px; }

    /* ── Type tabs ── */
    .type-tabs-wrap { margin-bottom: 1rem; }
    .type-tabs { display: flex; gap: 0.5rem; overflow-x: auto; padding-bottom: 0.5rem; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
    .type-tabs::-webkit-scrollbar { height: 3px; }
    .type-tabs::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
    .type-tab { display: flex; align-items: center; gap: 0.45rem; padding: 0.45rem 1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 99px; cursor: pointer; white-space: nowrap; color: var(--muted); font-size: 0.8rem; transition: all 0.15s; flex-shrink: 0; }
    .type-tab:hover { color: var(--text); border-color: #4b5563; background: var(--surface-2); }
    .type-tab.active { background: rgba(59,130,246,0.12); border-color: var(--blue); color: #93c5fd; }
    .tab-icon  { font-size: 0.95rem; }
    .tab-label { font-weight: 500; }
    .tab-count { font-weight: 800; font-size: 0.85rem; }

    /* Description bar shown when a non-All tab is active */
    .type-desc-bar { display: none; align-items: flex-start; gap: 0.75rem; background: rgba(59,130,246,0.05); border: 1px solid rgba(59,130,246,0.15); border-radius: 8px; padding: 0.75rem 1.1rem; margin-top: 0.5rem; }
    .type-desc-bar.visible { display: flex; }
    .type-desc-icon { font-size: 1.2rem; flex-shrink: 0; line-height: 1.4; }
    .type-desc-title { font-size: 0.82rem; font-weight: 700; color: var(--text); margin-bottom: 0.2rem; }
    .type-desc-text  { font-size: 0.78rem; color: var(--muted); line-height: 1.6; }

    /* ── Toolbar ── */
    .toolbar { display: flex; gap: 0.65rem; margin-bottom: 0.875rem; align-items: center; flex-wrap: wrap; }
    .search-wrap { flex: 1; min-width: 200px; position: relative; }
    .search-wrap input { width: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0.5rem 0.75rem 0.5rem 2rem; color: var(--text); font-size: 0.85rem; outline: none; transition: border-color 0.15s; }
    .search-wrap input:focus { border-color: var(--blue); }
    .search-wrap input::placeholder { color: var(--muted); }
    .search-icon { position: absolute; left: 0.65rem; top: 50%; transform: translateY(-50%); color: var(--muted); font-size: 0.85rem; pointer-events: none; }
    .filter-bar { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; }
    .filter-label { color: var(--muted); font-size: 0.72rem; }
    .filter-btn { padding: 0.35rem 0.8rem; border-radius: 99px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); font-size: 0.75rem; cursor: pointer; transition: all 0.15s; }
    .filter-btn:hover { color: var(--text); border-color: var(--blue); }
    .filter-btn.active { background: rgba(59,130,246,0.14); border-color: var(--blue); color: #93c5fd; }
    .filter-btn.high.active   { background: rgba(239,68,68,0.14);  border-color: var(--high);   color: #f87171; }
    .filter-btn.medium.active { background: rgba(249,115,22,0.14); border-color: var(--medium); color: #fb923c; }
    .filter-btn.low.active    { background: rgba(234,179,8,0.14);  border-color: var(--low);    color: #facc15; }
    .filter-btn.env-prod.active { background: rgba(239,68,68,0.14);  border-color: var(--high);   color: #f87171; }
    .filter-btn.env-tst.active  { background: rgba(249,115,22,0.14); border-color: var(--medium); color: #fb923c; }
    .filter-btn.env-dev.active  { background: rgba(59,130,246,0.14); border-color: var(--blue);   color: #93c5fd; }
    .results-count { font-size: 0.75rem; color: var(--muted); padding: 0.35rem 0.8rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; white-space: nowrap; }
    .results-count strong { color: var(--text); }
    .csv-btn { padding: 0.4rem 0.9rem; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); font-size: 0.75rem; cursor: pointer; white-space: nowrap; }
    .csv-btn:hover { color: var(--text); border-color: var(--green); }
    .fix-script-btn { padding: 0.4rem 0.9rem; border-radius: 8px; border: 1px solid rgba(34,197,94,0.3); background: rgba(34,197,94,0.07); color: #4ade80; font-size: 0.75rem; cursor: pointer; white-space: nowrap; font-weight: 600; }
    .fix-script-btn:hover { background: rgba(34,197,94,0.14); border-color: rgba(34,197,94,0.5); }

    /* ── Table ── */
    .table-wrapper { background: var(--surface); border-radius: var(--radius); border: 1px solid var(--border); overflow: hidden; }
    table { width: 100%; border-collapse: collapse; }
    thead th { background: var(--surface-2); padding: 0.75rem 1rem; text-align: left; font-weight: 600; color: var(--muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
    tbody tr.finding-row { border-top: 1px solid var(--border); cursor: pointer; transition: background 0.1s; }
    tbody tr.finding-row:hover { background: var(--surface-2); }
    tbody tr.finding-row.filtered { display: none; }
    tbody tr.detail-row { display: none; }
    tbody tr.detail-row.open { display: table-row; }
    tbody tr.detail-row.filtered { display: none !important; }
    td { padding: 0.8rem 1rem; vertical-align: middle; }

    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 99px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap; }
    .badge-HIGH   { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
    .badge-MEDIUM { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.4); }
    .badge-LOW    { background: rgba(234,179,8,0.15);  color: #facc15; border: 1px solid rgba(234,179,8,0.4); }
    .badge-type   { background: rgba(148,163,184,0.1); color: #94a3b8; border: 1px solid rgba(148,163,184,0.2); font-size: 0.6rem; }
    .badge-type-ANOMALY_DROP       { background: rgba(239,68,68,0.12);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    .badge-type-PIPELINE_SILENT    { background: rgba(249,115,22,0.12); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
    .badge-type-DEPRECATED_RUNTIME { background: rgba(239,68,68,0.12);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    .badge-type-MISSING_TAGS       { background: rgba(100,116,139,0.1); color: #94a3b8; border: 1px solid rgba(100,116,139,0.22); }
    .badge-type-ABANDONED          { background: rgba(220,38,38,0.18);  color: #fca5a5; border: 1px solid rgba(220,38,38,0.45); font-weight: 800; }

    /* ── Environment badges ── */
    .env-badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.57rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; margin-right: 0.3rem; vertical-align: middle; }
    .env-prod    { background: rgba(239,68,68,0.18);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    .env-tst     { background: rgba(249,115,22,0.18); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
    .env-dev     { background: rgba(59,130,246,0.18); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }
    .env-unknown { background: rgba(100,116,139,0.18); color: #94a3b8; border: 1px solid rgba(100,116,139,0.28); }

    .service-icon-sm { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 5px; font-size: 0.54rem; font-weight: 800; color: white; margin-right: 0.4rem; vertical-align: middle; }
    .resource-name { font-family: 'SF Mono','Cascadia Code','Fira Code',Consolas,monospace; font-size: 0.78rem; }
    .details-cell  { color: var(--muted); max-width: 360px; font-size: 0.82rem; }
    .chevron-cell  { color: var(--muted); font-size: 0.8rem; width: 28px; }
    .savings-cell  { white-space: nowrap; }
    .savings-badge { background: rgba(34,197,94,0.13); color: #4ade80; border: 1px solid rgba(34,197,94,0.28); border-radius: 99px; padding: 0.2rem 0.5rem; font-size: 0.7rem; font-weight: 700; }
    .savings-nil   { color: #475569; font-size: 0.8rem; }

    /* ── Detail row ── */
    tr.detail-row td { background: #121e30; padding: 1.25rem 1.5rem; border-top: 1px solid var(--border); }
    .detail-content { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
    .detail-section h4 { font-size: 0.63rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.6rem; font-weight: 600; }
    .metric-row { display: flex; justify-content: space-between; padding: 0.32rem 0; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
    .metric-row:last-child { border-bottom: none; }
    .metric-label { color: var(--muted); }
    .metric-value { font-weight: 600; font-family: 'SF Mono',Consolas,monospace; }
    .recommendation { background: rgba(59,130,246,0.07); border: 1px solid rgba(59,130,246,0.22); border-radius: 8px; padding: 0.75rem 1rem; font-size: 0.8rem; color: #93c5fd; line-height: 1.6; white-space: pre-wrap; }
    .resource-arn { margin-top: 0.5rem; font-size: 0.7rem; color: #475569; font-family: monospace; word-break: break-all; }

    /* "What does this mean?" box in detail panel */
    .type-explain-box { background: rgba(99,102,241,0.06); border: 1px solid rgba(99,102,241,0.18); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem; }
    .explain-title { font-size: 0.62rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #a78bfa; margin-bottom: 0.4rem; }
    .explain-text  { font-size: 0.8rem; color: #94a3b8; line-height: 1.6; }

    /* ── Fix / Alarm commands ── */
    .fix-section { margin-top: 1rem; }
    .fix-section h4 { font-size: 0.62rem; color: #4ade80; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem; font-weight: 600; }
    .fix-command { background: #071a0f; border: 1px solid rgba(34,197,94,0.28); border-radius: 8px; padding: 0.75rem 1rem; font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.72rem; color: #86efac; white-space: pre; overflow-x: auto; margin-bottom: 0.5rem; line-height: 1.7; }
    .fix-copy-btn { background: rgba(34,197,94,0.13) !important; border-color: rgba(34,197,94,0.28) !important; color: #4ade80 !important; }
    .fix-copy-btn:hover { background: rgba(34,197,94,0.28) !important; }
    .alarm-section { margin-top: 1rem; }
    .alarm-section h4 { font-size: 0.62rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem; font-weight: 600; }
    .alarm-command { background: #0d1929; border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.72rem; color: #7dd3fc; white-space: pre; overflow-x: auto; margin-bottom: 0.5rem; line-height: 1.7; }
    .copy-btn { padding: 0.3rem 0.8rem; background: rgba(59,130,246,0.13); border: 1px solid rgba(59,130,246,0.28); border-radius: 6px; color: #93c5fd; font-size: 0.72rem; cursor: pointer; transition: background 0.15s; }
    .copy-btn:hover { background: rgba(59,130,246,0.28); }
    .copy-btn.copied { color: #4ade80; border-color: rgba(34,197,94,0.38); background: rgba(34,197,94,0.1); }

    /* ── Executive summary ── */
    .exec-summary { background: linear-gradient(135deg, rgba(30,58,138,0.22), rgba(79,70,229,0.08)); border: 1px solid rgba(99,102,241,0.25); border-radius: var(--radius); padding: 1.5rem 2rem; margin-bottom: 1.5rem; }
    .exec-headline { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
    .exec-metric { text-align: center; padding: 0.4rem; }
    .exec-metric-value { font-size: 2.7rem; font-weight: 800; line-height: 1; }
    .exec-metric-label { font-size: 0.73rem; font-weight: 600; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.4px; }
    .exec-metric-sub { font-size: 0.67rem; color: var(--muted); margin-top: 0.2rem; }
    .exec-metric.health .exec-metric-value   { color: #f87171; }
    .exec-metric.health .exec-metric-label   { color: #f87171; }
    .exec-metric.security .exec-metric-value { color: #fb923c; }
    .exec-metric.security .exec-metric-label { color: #fb923c; }
    .exec-metric.waste .exec-metric-value    { color: #4ade80; }
    .exec-metric.waste .exec-metric-label    { color: #4ade80; }

    /* ── Methodology ── */
    .methodology { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1.5rem; }
    .methodology-title { padding: 0.7rem 1.2rem; font-size: 0.75rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer; list-style: none; display: flex; align-items: center; gap: 0.5rem; }
    .methodology-title::before { content: '▸'; font-size: 0.65rem; transition: transform 0.15s; }
    details.methodology[open] .methodology-title::before { transform: rotate(90deg); }
    .methodology-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; padding: 0 1.2rem 1.2rem; }
    .meth-col ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.38rem; }
    .meth-col ul li { font-size: 0.77rem; color: var(--muted); padding-left: 1rem; position: relative; line-height: 1.5; }
    .meth-col ul li::before { content: '·'; position: absolute; left: 0; color: var(--border); }
    .meth-col ul li em { color: #94a3b8; font-style: normal; font-weight: 600; }
    .meth-heading { font-size: 0.63rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.55rem; }
    .high-text { color: var(--high); } .medium-text { color: var(--medium); } .low-text { color: var(--low); }
    .meth-note { margin-top: 0.75rem; font-size: 0.72rem; color: #475569; line-height: 1.5; border-top: 1px solid var(--border); padding-top: 0.6rem; }

    /* ── Critical Resources ── */
    .critical-list { display: flex; flex-direction: column; gap: 0.65rem; margin-bottom: 1.5rem; }
    .critical-card { background: var(--surface); border: 1px solid rgba(239,68,68,0.22); border-radius: var(--radius); padding: 0.875rem 1.1rem; display: flex; align-items: center; gap: 0.875rem; }
    .cr-left { text-align: center; min-width: 2.4rem; flex-shrink: 0; }
    .cr-count { font-size: 1.9rem; font-weight: 800; color: #f87171; line-height: 1; }
    .cr-count-label { font-size: 0.58rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; }
    .cr-bar { width: 3px; height: 40px; border-radius: 99px; flex-shrink: 0; }
    .cr-body { flex: 1; min-width: 0; }
    .cr-name { font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.8rem; font-weight: 600; color: var(--text); margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.4rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cr-pills { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.3rem; }
    .cr-pill { font-size: 0.58rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; padding: 0.13rem 0.45rem; border-radius: 99px; white-space: nowrap; }
    .cr-pill-HIGH   { background: rgba(239,68,68,0.13);  color: #f87171; border: 1px solid rgba(239,68,68,0.28); }
    .cr-pill-MEDIUM { background: rgba(249,115,22,0.13); color: #fb923c; border: 1px solid rgba(249,115,22,0.28); }
    .cr-pill-LOW    { background: rgba(234,179,8,0.13);  color: #facc15; border: 1px solid rgba(234,179,8,0.28); }
    .cr-detail { font-size: 0.75rem; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cr-high-badge { background: rgba(239,68,68,0.13); border: 1px solid rgba(239,68,68,0.28); color: #f87171; font-size: 0.63rem; font-weight: 800; padding: 0.28rem 0.55rem; border-radius: 99px; white-space: nowrap; flex-shrink: 0; letter-spacing: 0.4px; }

    /* ── Spotlight ── */
    .spotlight-list { display: flex; flex-direction: column; gap: 0.55rem; margin-bottom: 1.5rem; }
    .spotlight-card { background: var(--surface); border-radius: var(--radius); padding: 0.875rem 1.4rem; display: flex; align-items: center; gap: 1.1rem; border: 1px solid var(--border); }
    .spotlight-card.spotlight-HIGH   { border-left: 3px solid var(--high);   background: linear-gradient(to right, rgba(239,68,68,0.06), var(--surface)); }
    .spotlight-card.spotlight-MEDIUM { border-left: 3px solid var(--medium); background: linear-gradient(to right, rgba(249,115,22,0.06), var(--surface)); }
    .spotlight-card.spotlight-LOW    { border-left: 3px solid var(--low);    background: linear-gradient(to right, rgba(234,179,8,0.06), var(--surface)); }
    .spotlight-num { font-size: 1.4rem; color: #818cf8; font-weight: 800; min-width: 1.6rem; line-height: 1; }
    .spotlight-svc-icon { width: 32px; height: 32px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.58rem; font-weight: 800; color: white; flex-shrink: 0; }
    .spotlight-body { flex: 1; min-width: 0; }
    .spotlight-meta { display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.28rem; flex-wrap: wrap; }
    .spotlight-service { font-size: 0.7rem; color: var(--muted); background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; padding: 0.1rem 0.38rem; }
    .spotlight-type { font-size: 0.65rem; color: #64748b; font-family: 'SF Mono',Consolas,monospace; letter-spacing: 0.2px; }
    .spotlight-resource { font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.82rem; color: var(--text); font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 480px; }
    .spotlight-detail { font-size: 0.8rem; color: var(--muted); line-height: 1.5; }
    .spotlight-cost { background: rgba(239,68,68,0.13); color: #f87171; border: 1px solid rgba(239,68,68,0.22); border-radius: 99px; padding: 0.13rem 0.48rem; font-size: 0.7rem; font-weight: 700; margin-left: 0.4rem; white-space: nowrap; }

    /* ── Narrative bar ── */
    .narrative-bar { background: rgba(99,102,241,0.06); border: 1px solid rgba(99,102,241,0.18); border-radius: var(--radius); padding: 1rem 1.4rem; margin-bottom: 1.4rem; font-size: 0.875rem; color: #cbd5e1; line-height: 1.8; }
    .narrative-bar strong { color: #e2e8f0; }
    .narrative-bar code { font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.78rem; color: #93c5fd; background: rgba(59,130,246,0.1); padding: 0.1rem 0.35rem; border-radius: 4px; }

    /* ── Empty state ── */
    .no-results { display: none; flex-direction: column; align-items: center; justify-content: center; padding: 3rem 2rem; gap: 0.75rem; }
    .no-results-icon { font-size: 2rem; opacity: 0.4; }
    .no-results-title { font-size: 1rem; font-weight: 600; color: var(--muted); }
    .no-results-text  { font-size: 0.82rem; color: #475569; text-align: center; max-width: 340px; line-height: 1.5; }
    .no-results-btn { margin-top: 0.25rem; padding: 0.45rem 1.2rem; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.3); border-radius: 8px; color: #93c5fd; font-size: 0.8rem; cursor: pointer; }
    .no-results-btn:hover { background: rgba(59,130,246,0.22); }

    .no-findings { text-align: center; padding: 3rem; color: var(--muted); font-size: 0.9rem; }
    footer { text-align: center; padding: 1.25rem; color: #475569; font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 2rem; }
  </style>
</head>
<body>
<div class="header">
  <div>
    <h1>Cloud<span class="lens">Lens</span></h1>
    <div class="header-tagline">Operational Health &amp; Cost Intelligence — ${provider.toUpperCase()}</div>
  </div>
  <div class="header-right">
    <div>Generated <strong>${now.toUTCString()}</strong></div>
    <div>Analysis window: <strong>last ${days} days</strong></div>
  </div>
</div>

<div class="container">

  ${narrativeHTML}

  ${execSummaryHTML}

  <div class="section-title">At a Glance</div>
  <div class="stats-grid">
    <div class="stat-card scanned"><div class="stat-value">${scanned}</div><div class="stat-label">Resources Scanned</div></div>
    <div class="stat-card total"><div class="stat-value">${findings.length}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card high"><div class="stat-value">${highCount}</div><div class="stat-label">High Priority</div></div>
    ${abandonedCount  > 0 ? `<div class="stat-card abandoned"><div class="stat-value">${abandonedCount}</div><div class="stat-label">Dead Code (28d+)</div></div>` : ''}
    ${pipelineCount   > 0 ? `<div class="stat-card pipeline"><div class="stat-value">${pipelineCount}</div><div class="stat-label">Silent Pipelines</div></div>` : ''}
    ${deprecatedCount > 0 ? `<div class="stat-card runtime"><div class="stat-value">${deprecatedCount}</div><div class="stat-label">EOL Runtimes</div></div>` : ''}
    ${anomalyCount    > 0 ? `<div class="stat-card anomaly"><div class="stat-value">${anomalyCount}</div><div class="stat-label">Traffic Anomalies</div></div>` : ''}
    <div class="stat-card medium"><div class="stat-value">${mediumCount}</div><div class="stat-label">Medium Priority</div></div>
    <div class="stat-card low"><div class="stat-value">${lowCount}</div><div class="stat-label">Low Priority</div></div>
    ${totalSpend   > 0 ? `<div class="stat-card spend"><div class="stat-value">$${totalSpend.toFixed(0)}</div><div class="stat-label">Est. Monthly Spend</div></div>` : ''}
    ${totalSavings > 0 ? `<div class="stat-card savings"><div class="stat-value">$${totalSavings.toFixed(2)}</div><div class="stat-label">Recoverable/mo</div></div>` : ''}
    ${missingTagCount > 0 ? `<div class="stat-card tags"><div class="stat-value">${missingTagCount}</div><div class="stat-label">Untagged Resources</div></div>` : ''}
  </div>

  ${costContextHTML}

  ${Object.keys(byService).length > 0 ? `
  <div class="section-title">Breakdown by Service</div>
  <div class="dashboard-row">
    <div class="service-breakdown">${serviceBreakdownHTML}</div>
    <div class="chart-card"><canvas id="doughnut-chart"></canvas></div>
  </div>` : ''}

  ${spotlightHTML}

  ${criticalResourcesHTML}

  <details class="methodology">
    <summary class="methodology-title">How findings are classified</summary>
    <div class="methodology-grid">
      <div class="meth-col">
        <div class="meth-heading high-text">HIGH</div>
        <ul>
          <li>Zero invocations over the window <em>and</em> no code changes in 28+ days (dead code)</li>
          <li>Traffic drop ≥ 80% vs the prior half-window</li>
          <li>Error rate &gt; 20% of invocations</li>
          <li>Memory utilisation below 30% of configured size</li>
          <li>Runtime at EOL — no security patch coverage</li>
          <li>Provisioned Concurrency with zero utilisation</li>
        </ul>
      </div>
      <div class="meth-col">
        <div class="meth-heading medium-text">MEDIUM</div>
        <ul>
          <li>Fewer than 10 invocations over the analysis window</li>
          <li>Error rate between 5–20%</li>
          <li>Memory utilisation between 30–50% of configured size</li>
          <li>Runtime approaching end-of-life (deprecated, not yet EOL)</li>
          <li>DynamoDB table under 10% of provisioned capacity</li>
        </ul>
      </div>
      <div class="meth-col">
        <div class="meth-heading low-text">LOW</div>
        <ul>
          <li>Missing recommended tags (Environment, Team/Owner)</li>
          <li>S3 bucket with zero objects</li>
          <li>Low-traffic findings on non-production environments</li>
        </ul>
        <div class="meth-note">Priority is downgraded one level for test/staging environments and two levels for dev, to reduce noise on non-production resources.</div>
      </div>
    </div>
  </details>

  <!-- ── Finding browser ── -->
  <div class="section-title" style="margin-top:0.25rem">Browse Findings by Category</div>

  <div class="type-tabs-wrap">
    <div class="type-tabs">${tabsHTML}</div>
    <div class="type-desc-bar" id="type-desc-bar">
      <span class="type-desc-icon" id="type-desc-icon"></span>
      <div>
        <div class="type-desc-title" id="type-desc-title"></div>
        <div class="type-desc-text"  id="type-desc-text"></div>
      </div>
    </div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="search-icon">⌕</span>
      <input type="text" id="search-input" placeholder="Search by resource name…" oninput="applySearch(this.value)">
    </div>
    <div class="filter-bar">
      <span class="filter-label">Priority:</span>
      <button class="filter-btn priority-btn active" data-filter="ALL"    onclick="setPriorityFilter('ALL',this)">All</button>
      <button class="filter-btn priority-btn high"   data-filter="HIGH"   onclick="setPriorityFilter('HIGH',this)">High (${highCount})</button>
      <button class="filter-btn priority-btn medium" data-filter="MEDIUM" onclick="setPriorityFilter('MEDIUM',this)">Med (${mediumCount})</button>
      <button class="filter-btn priority-btn low"    data-filter="LOW"    onclick="setPriorityFilter('LOW',this)">Low (${lowCount})</button>
    </div>
    <div class="filter-bar">
      <span class="filter-label">Env:</span>
      <button class="filter-btn env-btn active"   data-filter="ALL"  onclick="setEnvFilter('ALL',this)">All</button>
      <button class="filter-btn env-btn env-prod" data-filter="prod" onclick="setEnvFilter('prod',this)">Prod</button>
      <button class="filter-btn env-btn env-tst"  data-filter="tst"  onclick="setEnvFilter('tst',this)">Test</button>
      <button class="filter-btn env-btn env-dev"  data-filter="dev"  onclick="setEnvFilter('dev',this)">Dev</button>
    </div>
    <span class="results-count" id="results-count">Showing <strong>${findings.length}</strong> of <strong>${findings.length}</strong> findings</span>
    <button class="csv-btn"        onclick="exportCSV()">⬇ Export CSV</button>
    <button class="fix-script-btn" onclick="downloadFixScript()">⬇ Fix Script</button>
  </div>

  <div class="table-wrapper">
    ${findings.length === 0
      ? '<div class="no-findings">No findings — infrastructure looks healthy for this analysis window.</div>'
      : `<table id="findings-table">
          <thead><tr>
            <th>Priority</th><th>Service</th><th>Resource</th>
            <th>Finding Type</th><th>What's Wrong</th><th>Cost Savings</th><th></th>
          </tr></thead>
          <tbody>${findingsRowsHTML}</tbody>
        </table>
        <div class="no-results" id="no-results">
          <div class="no-results-icon">⊘</div>
          <div class="no-results-title">No findings match these filters</div>
          <div class="no-results-text">Try a different category tab, or clear the search and priority filters.</div>
          <button class="no-results-btn" onclick="resetFilters()">Clear all filters</button>
        </div>`
    }
  </div>

</div>

<footer>CloudLens — read-only, no changes made to any resource &nbsp;·&nbsp; ${now.toUTCString()}</footer>

<script>
  var allFindings = ${JSON.stringify(findings.map((f, i) => ({
    idx:          i,
    priority:     f.priority,
    service:      f.service,
    resourceName: f.resourceName,
    type:         f.type,
    typegroup:    typeGroupOf(f.type),
    details:      f.details,
    region:       f.region,
    savings:      f.estimatedMonthlySavings || 0,
    environment:  f.environment || 'unknown',
    team:         f.team || '',
    fixCommand:   f.fixCommand || '',
  })))};

  var activeFilter     = 'ALL';
  var activeEnvFilter  = 'ALL';
  var activeTypeFilter = 'ALL';
  var activeSearch     = '';

  // ── Doughnut chart ────────────────────────────────────────────────────────
  (function() {
    var canvas = document.getElementById('doughnut-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ${JSON.stringify(chartLabels)},
        datasets: [{ data: ${JSON.stringify(chartCounts)}, backgroundColor: ${JSON.stringify(chartColors)}, borderWidth: 2, borderColor: '#1e293b' }]
      },
      options: {
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font:{ size: 11 }, padding: 8, boxWidth: 12 } } },
        cutout: '65%',
      }
    });
  })();

  // ── Toggle detail row ─────────────────────────────────────────────────────
  function toggleDetail(idx) {
    var row  = document.getElementById('detail-' + idx);
    var chev = document.getElementById('chev-' + idx);
    row.style.display = '';
    var open = row.classList.toggle('open');
    chev.textContent = open ? '▾' : '▸';
  }

  // ── Type tab filter ───────────────────────────────────────────────────────
  function setTypeFilter(type, btn) {
    document.querySelectorAll('.type-tab').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeTypeFilter = type;
    var bar = document.getElementById('type-desc-bar');
    if (type === 'ALL') {
      bar.classList.remove('visible');
    } else {
      document.getElementById('type-desc-icon').textContent  = btn.dataset.icon  || '';
      document.getElementById('type-desc-title').textContent = btn.dataset.label || '';
      document.getElementById('type-desc-text').textContent  = btn.dataset.desc  || '';
      bar.classList.add('visible');
    }
    renderVisibility();
  }

  // ── Priority & env filters ────────────────────────────────────────────────
  function applySearch(val) { activeSearch = val.toLowerCase().trim(); renderVisibility(); }

  function setPriorityFilter(filter, btn) {
    document.querySelectorAll('.priority-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeFilter = filter;
    renderVisibility();
  }

  function setEnvFilter(env, btn) {
    document.querySelectorAll('.env-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeEnvFilter = env;
    renderVisibility();
  }

  function resetFilters() {
    activeFilter = 'ALL'; activeEnvFilter = 'ALL'; activeTypeFilter = 'ALL'; activeSearch = '';
    document.getElementById('search-input').value = '';
    document.querySelectorAll('.type-tab').forEach(function(b) { b.classList.remove('active'); });
    var allTab = document.querySelector('.type-tab[data-type="ALL"]');
    if (allTab) allTab.classList.add('active');
    document.getElementById('type-desc-bar').classList.remove('visible');
    document.querySelectorAll('.priority-btn').forEach(function(b) { b.classList.remove('active'); });
    var allPri = document.querySelector('.priority-btn[data-filter="ALL"]');
    if (allPri) allPri.classList.add('active');
    document.querySelectorAll('.env-btn').forEach(function(b) { b.classList.remove('active'); });
    var allEnv = document.querySelector('.env-btn[data-filter="ALL"]');
    if (allEnv) allEnv.classList.add('active');
    renderVisibility();
  }

  // ── Render row visibility + result count ─────────────────────────────────
  function renderVisibility() {
    var visibleCount = 0;
    allFindings.forEach(function(f) {
      var frow = document.getElementById('frow-'   + f.idx);
      var drow = document.getElementById('detail-' + f.idx);
      var chev = document.getElementById('chev-'   + f.idx);
      var matchPriority = activeFilter     === 'ALL' || activeFilter     === f.priority;
      var matchEnv      = activeEnvFilter  === 'ALL' || activeEnvFilter  === f.environment;
      var matchSearch   = !activeSearch            || f.resourceName.toLowerCase().includes(activeSearch);
      var matchType     = activeTypeFilter === 'ALL' || activeTypeFilter === f.typegroup;
      var visible = matchPriority && matchEnv && matchSearch && matchType;
      if (visible) visibleCount++;
      if (frow) frow.classList.toggle('filtered', !visible);
      if (drow) { drow.classList.toggle('filtered', !visible); drow.classList.remove('open'); }
      if (chev) chev.textContent = '▸';
    });
    var countEl  = document.getElementById('results-count');
    if (countEl) countEl.innerHTML = 'Showing <strong>' + visibleCount + '</strong> of <strong>' + allFindings.length + '</strong> findings';
    var noRes = document.getElementById('no-results');
    var tbl   = document.getElementById('findings-table');
    if (noRes) noRes.style.display = (allFindings.length > 0 && visibleCount === 0) ? 'flex' : 'none';
    if (tbl)   tbl.style.display   = visibleCount === 0 ? 'none' : '';
  }

  // ── Copy fix / alarm commands ─────────────────────────────────────────────
  function copyFix(idx, evt) {
    evt.stopPropagation();
    var el = document.getElementById('fix-cmd-' + idx), btn = evt.target;
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(function() {
      var orig = btn.textContent; btn.textContent = '✓ Copied'; btn.classList.add('copied');
      setTimeout(function() { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(function() { var r = document.createRange(); r.selectNode(el); window.getSelection().removeAllRanges(); window.getSelection().addRange(r); });
  }
  function copyAlarm(idx, evt) {
    evt.stopPropagation();
    var el = document.getElementById('alarm-cmd-' + idx), btn = evt.target;
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(function() {
      var orig = btn.textContent; btn.textContent = '✓ Copied'; btn.classList.add('copied');
      setTimeout(function() { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(function() { var r = document.createRange(); r.selectNode(el); window.getSelection().removeAllRanges(); window.getSelection().addRange(r); });
  }

  // ── Download fix script ───────────────────────────────────────────────────
  function downloadFixScript() {
    var actionable = allFindings.filter(function(f) { return f.fixCommand && f.fixCommand.length > 0; });
    if (actionable.length === 0) { alert('No fix commands available.'); return; }
    var lines = [
      '#!/bin/bash',
      '# CloudLens Remediation Playbook',
      '# Generated: ' + new Date().toUTCString(),
      '#',
      '# REVIEW EACH COMMAND BEFORE RUNNING.',
      '# CloudLens is read-only — these commands WILL make changes to your cloud resources.',
      '# Ordered by severity: HIGH first.',
      '',
    ];
    ['HIGH','MEDIUM','LOW'].forEach(function(p) {
      var group = actionable.filter(function(f) { return f.priority === p; });
      if (group.length === 0) return;
      lines.push('# ══════════════════════════════════════════════');
      lines.push('# ' + p + ' PRIORITY (' + group.length + ' findings)');
      lines.push('# ══════════════════════════════════════════════');
      lines.push('');
      group.forEach(function(f, n) {
        lines.push('# [' + (n+1) + '] ' + f.type.replace(/_/g,' ') + ' — ' + f.service);
        lines.push('# Resource: ' + f.resourceName);
        lines.push('# Issue:    ' + f.details);
        lines.push(f.fixCommand);
        lines.push('');
      });
    });
    var blob = new Blob([lines.join('\\n')], { type:'text/plain' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a'); a.href = url; a.download = 'cloudlens-remediate.sh'; a.click();
    URL.revokeObjectURL(url);
  }

  // ── CSV export ────────────────────────────────────────────────────────────
  function exportCSV() {
    var rows = [['Priority','Service','Resource','Type','Details','Est Savings/mo','Region','Environment','Team']];
    allFindings.forEach(function(f) {
      rows.push([f.priority, f.service, '"'+f.resourceName.replace(/"/g,'""')+'"', f.type, '"'+f.details.replace(/"/g,'""')+'"',
        f.savings > 0 ? '$'+f.savings.toFixed(2) : '', f.region, f.environment, f.team]);
    });
    var blob = new Blob([rows.map(function(r){return r.join(',');}).join('\\n')], { type:'text/csv' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a'); a.href = url; a.download = 'cloudlens-findings.csv'; a.click();
    URL.revokeObjectURL(url);
  }
<\/script>
</body>
</html>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const METRIC_LABELS = {
  invocations:'Invocations', avgDurationMs:'Avg Duration', errors:'Errors', throttles:'Throttles',
  configuredMemMB:'Configured Memory', avgMemUsedMB:'Avg Memory Used', peakMemUsedMB:'Peak Memory Used',
  memUtilisationPct:'Memory Utilisation', avgColdStartMs:'Avg Cold Start', lastModifiedDaysAgo:'Last Modified',
  runtime:'Runtime', trafficDropPct:'Traffic Drop', provisionedRCU:'Provisioned RCU', provisionedWCU:'Provisioned WCU',
  consumedRCU:'Consumed RCU', consumedWCU:'Consumed WCU', rcuUtilisationPct:'RCU Utilisation',
  wcuUtilisationPct:'WCU Utilisation', messagesPublished:'Messages Published', messagesSent:'Messages Sent',
  messagesReceived:'Messages Received', currentlyVisible:'Visible Messages', oldestMessageAge:'Oldest Message Age',
  storedBytes:'Stored', retentionDays:'Retention', incomingEventsOverWindow:'Incoming Events',
  incomingEventsPerDay:'Avg Events/Day', objectCount:'Object Count', ruleType:'Rule Type', schedule:'Schedule',
};

function fmtKey(k) {
  if (METRIC_LABELS[k]) return METRIC_LABELS[k];
  const m1 = k.match(/^invocationsPrev(\d+)d$/); if (m1) return `Invocations (prev ${m1[1]}d)`;
  const m2 = k.match(/^invocationsCurr(\d+)d$/); if (m2) return `Invocations (last ${m2[1]}d)`;
  return k;
}

function fmtVal(k, v) {
  if (k.endsWith('Pct') || k === 'trafficDropPct') return v + '%';
  if (k.endsWith('MB'))                return v + ' MB';
  if (k === 'avgDurationMs' || k === 'avgColdStartMs') return v + ' ms';
  if (k === 'lastModifiedDaysAgo')     return v + ' days ago';
  if (k === 'storedBytes')             return fmtBytes(v);
  if (typeof v === 'number')           return v.toLocaleString();
  return String(v);
}

function fmtBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = { generateReport };
