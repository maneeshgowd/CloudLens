'use strict';

function generateReport({ findings, summary, provider, days }) {
  const isAzure = provider === 'azure';
  const isBoth = provider === 'both';
  const providerLabel = isBoth ? 'Multi-Cloud' : provider.toUpperCase();
  const now = new Date();
  const highCount = findings.filter((f) => f.priority === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.priority === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.priority === 'LOW').length;
  const scanned = (summary.aws?.resourcesScanned ?? 0) + (summary.azure?.resourcesScanned ?? 0);
  const totalSpend = (summary.aws?.costContext?.totalEstimatedCost ?? 0) + (summary.azure?.costContext?.totalEstimatedCost ?? 0);

  const anomalyCount = findings.filter((f) => f.type === 'ANOMALY_DROP').length;
  const deprecatedCount = findings.filter((f) => f.type === 'DEPRECATED_RUNTIME').length;
  const missingTagCount = findings.filter((f) => f.type === 'MISSING_TAGS').length;
  const pipelineCount = findings.filter((f) => f.type === 'PIPELINE_SILENT').length;
  const abandonedCount = findings.filter((f) => f.type === 'ABANDONED').length;
  const certCount = findings.filter((f) => f.type === 'CERT_EXPIRING').length;
  const appSecretCount = findings.filter((f) => f.type === 'APP_SECRET_EXPIRING').length;

  const byService = {};
  for (const f of findings) byService[f.service] = (byService[f.service] || 0) + 1;

  const serviceColors = {
    Lambda: '#FF9900',
    'Provisioned Concurrency': '#f59e0b',
    DynamoDB: '#4A4A9F',
    SNS: '#E7157B',
    S3: '#7AA116',
    EventBridge: '#E7157B',
    'Log Groups': '#2563eb',
    SQS: '#9333ea',
    ECS: '#06b6d4',
    'NAT Gateway': '#64748b',
    'API Gateway': '#8b5cf6',
    'Secrets Manager': '#ec4899',
    CloudFront: '#0ea5e9',
    MSK: '#FF6B35',
    'Security Groups': '#DC2626',
    IAM: '#DD344C',
    'Azure Functions': '#0078d4',
    'Virtual Machines': '#0078d4',
    'App Service': '#0078d4',
    'Blob Storage': '#0072c6',
    'Cosmos DB': '#0072c6',
    'Service Bus': '#0078d4',
    'Log Analytics': '#0078d4',
    'Azure Monitor': '#0072c6',
    'Key Vault': '#0072c6',
    'Event Grid': '#0078d4',
    'API Management': '#0072c6',
    CDN: '#0078d4',
    'Event Hubs': '#0072c6',
    'Container Apps': '#0078d4',
    'SQL Database': '#0078d4',
    'App Registrations': '#7C3AED'
  };
  const serviceIconLabel = {
    Lambda: 'λ',
    'Provisioned Concurrency': 'PC',
    DynamoDB: 'DB',
    SNS: 'SNS',
    S3: 'S3',
    EventBridge: 'EB',
    'Log Groups': 'CW',
    SQS: 'SQS',
    ECS: 'ECS',
    'NAT Gateway': 'NAT',
    'API Gateway': 'API',
    'Secrets Manager': 'SM',
    CloudFront: 'CF',
    MSK: 'MSK',
    'Azure Functions': 'fn',
    'Virtual Machines': 'VM',
    'App Service': 'APP',
    'Blob Storage': 'BLOB',
    'Cosmos DB': 'CDB',
    'Service Bus': 'SB',
    'Log Analytics': 'LA',
    'Azure Monitor': 'MON',
    'Key Vault': 'KV',
    'Event Grid': 'EG',
    'API Management': 'APIM',
    CDN: 'CDN',
    'Event Hubs': 'EH',
    'Container Apps': 'CA',
    'SQL Database': 'SQL',
    'App Registrations': 'AR'
  };

  // ── Type grouping ──────────────────────────────────────────────────────────
  const TYPE_TO_GROUP = {
    PIPELINE_SILENT: 'PIPELINE_SILENT',
    DEPRECATED_RUNTIME: 'DEPRECATED_RUNTIME',
    CERT_EXPIRING: 'SECURITY',
    ABANDONED: 'ABANDONED',
    ANOMALY_DROP: 'ANOMALY_DROP',
    HIGH_ERROR_RATE: 'HIGH_ERROR_RATE',
    MSK_DISK_CRITICAL: 'HIGH_ERROR_RATE',
    MSK_OFFLINE: 'OUTAGES',
    CA_NO_RUNNING_REPLICAS: 'OUTAGES',
    // Genuinely idle: stopped/disabled or literal zero activity — delete is appropriate.
    IDLE: 'IDLE',
    PC_IDLE: 'IDLE',
    MSK_IDLE: 'IDLE',
    STOPPED_NOT_DEALLOCATED: 'IDLE',
    API_IDLE: 'IDLE',
    CDN_IDLE: 'IDLE',
    EH_IDLE: 'IDLE',
    NAT_IDLE: 'IDLE',
    // Still running/receiving traffic, just oversized or low-activity — resize/downscale
    // only, never a delete recommendation.
    LOW_ACTIVITY: 'UNDERUTILIZED',
    MSK_UNDERUTILIZED: 'UNDERUTILIZED',
    PC_OVER_PROVISIONED: 'UNDERUTILIZED',
    OVER_ALLOCATED: 'UNDERUTILIZED',
    OVER_PROVISIONED: 'UNDERUTILIZED',
    EH_UNDERUTILIZED: 'UNDERUTILIZED',
    UNDERUTILISED: 'UNDERUTILIZED',
    NAT_LOW_UTILISATION: 'UNDERUTILIZED',
    // Throttling means too LITTLE capacity, not too much — it's a failure condition,
    // not idle/over-allocated capacity, so it belongs with other error-rate findings.
    THROTTLED: 'HIGH_ERROR_RATE',
    EH_THROTTLED: 'HIGH_ERROR_RATE',
    DLQ_MESSAGES: 'QUEUE',
    STALE_MESSAGES: 'QUEUE',
    MSK_DURABILITY_RISK: 'QUEUE',
    MISSING_TAGS: 'GOVERNANCE',
    NO_RETENTION: 'GOVERNANCE',
    S3_PUBLIC_ACCESS: 'SECURITY',
    SG_OPEN_INGRESS: 'SECURITY',
    IAM_KEY_STALE: 'SECURITY',
    SECRET_NO_ROTATION: 'SECURITY',
    KV_NO_SOFT_DELETE: 'GOVERNANCE',
    KV_NO_PURGE_PROTECTION: 'GOVERNANCE',
    KV_PUBLIC_ACCESS: 'GOVERNANCE',
    APP_SECRET_EXPIRING: 'SECURITY'
  };
  function typeGroupOf(t) {
    return TYPE_TO_GROUP[t] || 'OTHER';
  }

  const groupCounts = {};
  for (const f of findings) {
    const g = typeGroupOf(f.type);
    groupCounts[g] = (groupCounts[g] || 0) + 1;
  }

  // Builds every aggregate UI block (summary bar, narrative, service breakdown/chart,
  // type tabs, findings-heading count) scoped to one provider's findings, so the AWS/Azure
  // toggle can swap the whole page's context — not just filter table rows.
  function buildScopedView(viewFindings, vIsAzure, vIsBoth, resourcesScanned, totalEstimatedCost) {
    const highCount = viewFindings.filter((f) => f.priority === 'HIGH').length;
    const mediumCount = viewFindings.filter((f) => f.priority === 'MEDIUM').length;
    const lowCount = viewFindings.filter((f) => f.priority === 'LOW').length;
    const totalSavingsV = viewFindings.reduce((sum, f) => sum + (f.estimatedMonthlySavings || 0), 0);

    const anomalyCountV = viewFindings.filter((f) => f.type === 'ANOMALY_DROP').length;
    const deprecatedCountV = viewFindings.filter((f) => f.type === 'DEPRECATED_RUNTIME').length;
    const pipelineCountV = viewFindings.filter((f) => f.type === 'PIPELINE_SILENT').length;
    const certCountV = viewFindings.filter((f) => f.type === 'CERT_EXPIRING').length;
    const appSecretCountV = viewFindings.filter((f) => f.type === 'APP_SECRET_EXPIRING').length;

    const byServiceV = {};
    for (const f of viewFindings) byServiceV[f.service] = (byServiceV[f.service] || 0) + 1;

    const groupCountsV = {};
    for (const f of viewFindings) {
      const g = typeGroupOf(f.type);
      groupCountsV[g] = (groupCountsV[g] || 0) + 1;
    }

    const accessTermTabV = vIsBoth ? 'IAM/RBAC permissions' : vIsAzure ? 'RBAC role assignments' : 'IAM (access) permissions';
    const patcherTabV = vIsBoth ? 'the cloud provider' : vIsAzure ? 'Microsoft' : 'AWS';
    const pipelineSourceTabV = vIsBoth ? 'Scheduled rules (EventBridge / Event Grid)' : vIsAzure ? 'Event Grid topics' : 'Scheduled rules (EventBridge)';
    const pipelineTargetTabV = vIsBoth ? 'downstream function' : vIsAzure ? 'Azure Function' : 'Lambda function';

    const tabDefsV = [
      { type: 'ALL', icon: '≡', label: 'All', desc: '', color: '#2563EB' },
      {
        type: 'IDLE',
        icon: '□',
        label: 'Idle Resources',
        desc: 'Resources that are stopped, disabled, or have had zero actual usage for the whole scan window — genuinely not in use, so deletion is a safe recommendation.',
        color: '#EA580C'
      },
      {
        type: 'DEPRECATED_RUNTIME',
        icon: '⚠',
        label: 'Deprecations',
        desc: `Functions running software versions (Node.js, Python, etc.) that ${patcherTabV} no longer patches, or has flagged for removal. These need action before their EOL deadline — unpatched vulnerabilities accumulate with no fix available.`,
        color: '#B45309'
      },
      {
        type: 'UNDERUTILIZED',
        icon: '▽',
        label: 'Underutilized',
        desc: 'Resources that are still running and receiving traffic, but at a fraction of their provisioned capacity — over-allocated memory, oversized throughput units, underutilised clusters or gateways. Downscale or resize; these are still in use, so deletion is not recommended.',
        color: '#CA8A04'
      },
      {
        type: 'SECURITY',
        icon: '⚿',
        label: 'Security',
        desc: 'SSL/TLS certificates and cryptographic keys nearing or past their expiration date, Azure AD app registration client secrets/certificates due for renewal, plus other resources with direct security exposure — public access, open network ingress, stale credentials, or disabled rotation. These need action before their deadline to avoid outages or exposure.',
        color: '#7C3AED'
      },
      {
        type: 'PIPELINE_SILENT',
        icon: '⏸',
        label: 'Silent Pipelines',
        desc: `${pipelineSourceTabV} are active and provisioned, but zero events are reaching the target ${pipelineTargetTabV}. The automated pipeline is broken — and no alarm has fired to alert you.`,
        color: '#EA580C'
      },
      {
        type: 'ABANDONED',
        icon: '◌',
        label: 'Dead Code',
        desc: `Resources deployed with zero activity for an extended period — dead weight still holding live ${accessTermTabV} and accumulating unpatched vulnerabilities as the runtime ages.`,
        color: '#DC2626'
      },
      {
        type: 'ANOMALY_DROP',
        icon: '↘',
        label: 'Traffic Anomalies',
        desc: 'Functions showing a sharp drop in invocations vs the prior period — typically a broken upstream caller or a silent deployment failure that no alarm caught.',
        color: '#DC2626'
      },
      {
        type: 'HIGH_ERROR_RATE',
        icon: '✕',
        label: 'High Error Rate',
        desc: 'Resources where a significant percentage of operations are failing (errors, timeouts, dropped packets, restarts, or failed deliveries). Cost is being spent on failed work that produces no value for users or downstream systems.',
        color: '#DC2626'
      },
      {
        type: 'QUEUE',
        icon: '▣',
        label: 'Queue Issues',
        desc: 'Message queues and topics (SQS/Service Bus/Event Grid, dead-letter destinations) with stuck or unprocessed messages — indicating processing failures or backlog accumulation that may affect downstream consumers.',
        color: '#EA580C'
      },
      {
        type: 'OUTAGES',
        icon: '⛔',
        label: 'Outages',
        desc: 'Resources that were completely unavailable during the scan window — Kafka (MSK) clusters with offline partitions, and Container Apps running zero replicas. These are actual outages, not just degraded performance.',
        color: '#991B1B'
      }
    ];

    const tabsHTMLV = tabDefsV
      .filter((t) => t.type === 'ALL' || (groupCountsV[t.type] || 0) > 0)
      .map((t) => {
        const count = t.type === 'ALL' ? viewFindings.length : groupCountsV[t.type] || 0;
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
      })
      .join('');

    const narrativePartsV = [];
    if (deprecatedCountV > 0) {
      const eolRuntimes = [
        ...new Set(
          viewFindings
            .filter((f) => f.type === 'DEPRECATED_RUNTIME')
            .map((f) => f.metrics?.runtime)
            .filter(Boolean)
        )
      ];
      const runtimeList = eolRuntimes.length > 0 ? ` (${eolRuntimes.slice(0, 3).join(', ')})` : '';
      narrativePartsV.push(
        `<strong>${deprecatedCountV} function${deprecatedCountV > 1 ? 's' : ''} on end-of-life runtimes${runtimeList}</strong> — ${patcherTabV} has stopped shipping patches. CVEs published since the EOL date are permanently unpatched.`
      );
    }
    if (pipelineCountV > 0) {
      const pipelineProviders = new Set(viewFindings.filter((f) => f.type === 'PIPELINE_SILENT').map((f) => f.provider));
      const pipelineSourceNarr = pipelineProviders.size > 1 ? 'automated pipeline rule' : pipelineProviders.has('azure') ? 'Event Grid topic' : 'EventBridge rule';
      narrativePartsV.push(
        `<strong>${pipelineCountV} automated pipeline${pipelineCountV > 1 ? 's' : ''} completely silent</strong> — ${pipelineSourceNarr}${pipelineCountV > 1 ? 's' : ''} enabled and provisioned but zero events reaching target function${pipelineCountV > 1 ? 's' : ''}. No alarm has fired.`
      );
    }
    if (anomalyCountV > 0) {
      narrativePartsV.push(`<strong>${anomalyCountV} function${anomalyCountV > 1 ? 's' : ''} with sharp traffic drop</strong> — likely a broken upstream caller or silent deployment failure.`);
    }
    const abandonedFindingsV = viewFindings.filter((f) => f.type === 'ABANDONED').sort((a, b) => (b.metrics?.lastModifiedDaysAgo ?? 0) - (a.metrics?.lastModifiedDaysAgo ?? 0));
    if (abandonedFindingsV.length > 0) {
      const oldest = abandonedFindingsV[0];
      const age = oldest.metrics?.lastModifiedDaysAgo;
      const ageStr = age != null ? (age >= 365 ? `~${(age / 365).toFixed(1)} years` : `${age} days`) : 'an extended period';
      const abandonedProviders = new Set(abandonedFindingsV.map((f) => f.provider));
      const resourceNoun = abandonedProviders.size === 1 && !abandonedProviders.has('azure') ? 'Lambda function' : 'resource';
      narrativePartsV.push(
        `<strong>${abandonedFindingsV.length} ${resourceNoun}${abandonedFindingsV.length > 1 ? 's' : ''} deployed with zero activity</strong> — dead weight holding live ${accessTermTabV}. Oldest: <code>${escapeHtml(oldest.resourceName)}</code>, unmodified for ${ageStr}.`
      );
    }
    if (certCountV > 0) {
      const certFindings = viewFindings.filter((f) => f.type === 'CERT_EXPIRING').sort((a, b) => (a.metrics?.daysUntilExpiry ?? Infinity) - (b.metrics?.daysUntilExpiry ?? Infinity));
      const nearest = certFindings[0];
      const nearestDays = nearest.metrics?.daysUntilExpiry;
      const nearestStr = nearestDays != null ? (nearestDays < 0 ? `expired ${Math.abs(nearestDays)} day(s) ago` : `expires in ${nearestDays} day(s)`) : 'expiring soon';
      narrativePartsV.push(
        `<strong>${certCountV} certificate${certCountV > 1 ? 's' : ''}/key${certCountV > 1 ? 's' : ''} nearing expiry</strong> — must be renewed or rotated before the deadline to avoid TLS/crypto failures. Nearest: <code>${escapeHtml(nearest.resourceName)}</code>, ${nearestStr}.`
      );
    }
    if (appSecretCountV > 0) {
      const appSecretFindingsV = viewFindings.filter((f) => f.type === 'APP_SECRET_EXPIRING').sort((a, b) => (a.metrics?.daysUntilExpiry ?? Infinity) - (b.metrics?.daysUntilExpiry ?? Infinity));
      const nearest = appSecretFindingsV[0];
      const nearestDays = nearest.metrics?.daysUntilExpiry;
      const nearestStr = nearestDays != null ? (nearestDays < 0 ? `expired ${Math.abs(nearestDays)} day(s) ago` : `expires in ${nearestDays} day(s)`) : 'expiring soon';
      narrativePartsV.push(
        `<strong>${appSecretCountV} app registration credential${appSecretCountV > 1 ? 's' : ''} nearing expiry</strong> — client secrets/certs must be renewed before the deadline or client-credential sign-ins fail outright. Nearest: <code>${escapeHtml(nearest.resourceName)}</code>, ${nearestStr}.`
      );
    }

    const narrativeHTMLV =
      narrativePartsV.length > 0
        ? `<div class="narrative-bar">
          <div class="narrative-total">${narrativePartsV.length} issue${narrativePartsV.length > 1 ? 's' : ''} need${narrativePartsV.length > 1 ? '' : 's'} attention</div>
          ${narrativePartsV.map((p) => `<div class="narrative-item">${p}</div>`).join('')}
        </div>`
        : '';

    const serviceBreakdownHTMLV = Object.entries(byServiceV)
      .sort((a, b) => b[1] - a[1])
      .map(([svc, cnt]) => {
        const bg = serviceColors[svc] || '#64748b';
        const lbl = serviceIconLabel[svc] || svc[0];
        return `<div class="service-tile">
        <div class="service-icon-lg" style="background:${bg}">${lbl}</div>
        <div class="svc-count">${cnt}</div>
        <div class="svc-name">${svc}</div>
      </div>`;
      })
      .join('');

    const chartLabelsV = Object.keys(byServiceV);
    const chartCountsV = Object.values(byServiceV);
    const chartColorsV = chartLabelsV.map((s) => serviceColors[s] || '#64748b');

    const serviceListV = Object.keys(byServiceV)
      .sort((a, b) => byServiceV[b] - byServiceV[a])
      .slice(0, 8);
    const svcHighV = serviceListV.map((s) => viewFindings.filter((f) => f.service === s && f.priority === 'HIGH').length);
    const svcMedV = serviceListV.map((s) => viewFindings.filter((f) => f.service === s && f.priority === 'MEDIUM').length);
    const svcLowV = serviceListV.map((s) => viewFindings.filter((f) => f.service === s && f.priority === 'LOW').length);

    const serviceCountV = Object.keys(byServiceV).length;
    const serviceSectionHTMLV =
      serviceCountV > 0
        ? `
      <div class="section-heading">Findings by Service <span class="sh-sub">${serviceCountV} service${serviceCountV !== 1 ? 's' : ''} affected</span></div>
      <div class="services-row">
        <div class="service-tiles">${serviceBreakdownHTMLV}</div>
        <div class="chart-card"><canvas id="doughnut-chart"></canvas></div>
      </div>
      ${
        serviceListV.length > 0
          ? `
      <div class="insight-card" style="margin-bottom:1.75rem">
        <div class="insight-title">Findings by Service &amp; Severity</div>
        <div class="insight-subtitle">Breakdown of HIGH / MEDIUM / LOW findings per service</div>
        <canvas id="severity-chart"></canvas>
      </div>`
          : ''
      }`
        : '';

    const summaryBarHTMLV = `
      <div class="sum-item"><div class="sum-val">${resourcesScanned.toLocaleString()}</div><div class="sum-lbl">Resources Scanned</div></div>
      <div class="sum-item"><div class="sum-val">${viewFindings.length}</div><div class="sum-lbl">Total Findings</div></div>
      <div class="sum-item high"><div class="sum-val">${highCount}</div><div class="sum-lbl">High</div></div>
      <div class="sum-item medium"><div class="sum-val">${mediumCount}</div><div class="sum-lbl">Medium</div></div>
      <div class="sum-item low"><div class="sum-val">${lowCount}</div><div class="sum-lbl">Low</div></div>
      ${totalSavingsV > 0 ? `<div class="sum-item savings"><div class="sum-val">$${totalSavingsV.toFixed(0)}/mo</div><div class="sum-lbl">Recoverable</div></div>` : ''}
      ${totalEstimatedCost > 0 ? `<div class="sum-item spend"><div class="sum-val">$${totalEstimatedCost.toFixed(0)}/mo</div><div class="sum-lbl">Est. Spend</div></div>` : ''}
    `;

    const findingsHeadingCountHTMLV = `${viewFindings.length} total · ${highCount} high · ${mediumCount} medium · ${lowCount} low`;

    return {
      highCount,
      mediumCount,
      lowCount,
      summaryBarHTML: summaryBarHTMLV,
      narrativeHTML: narrativeHTMLV,
      serviceSectionHTML: serviceSectionHTMLV,
      tabsHTML: tabsHTMLV,
      findingsHeadingCountHTML: findingsHeadingCountHTMLV,
      chartLabels: chartLabelsV,
      chartCounts: chartCountsV,
      chartColors: chartColorsV,
      severityLabels: serviceListV,
      severityHigh: svcHighV,
      severityMed: svcMedV,
      severityLow: svcLowV
    };
  }

  const accessTermTab = isBoth ? 'IAM/RBAC permissions' : isAzure ? 'RBAC role assignments' : 'IAM (access) permissions';
  const patcherTab = isBoth ? 'the cloud provider' : isAzure ? 'Microsoft' : 'AWS';
  const pipelineSourceTab = isBoth ? 'Scheduled rules (EventBridge / Event Grid)' : isAzure ? 'Event Grid topics' : 'Scheduled rules (EventBridge)';
  const pipelineTargetTab = isBoth ? 'downstream function' : isAzure ? 'Azure Function' : 'Lambda function';
  const TAB_DEFS = [
    { type: 'ALL', icon: '≡', label: 'All', desc: '', color: '#2563EB' },
    {
      type: 'IDLE',
      icon: '□',
      label: 'Idle Resources',
      desc: 'Resources that are stopped, disabled, or have had zero actual usage for the whole scan window — genuinely not in use, so deletion is a safe recommendation.',
      color: '#EA580C'
    },
    {
      type: 'DEPRECATED_RUNTIME',
      icon: '⚠',
      label: 'Deprecations',
      desc: `Functions running software versions (Node.js, Python, etc.) that ${patcherTab} no longer patches, or has flagged for removal. These need action before their EOL deadline — unpatched vulnerabilities accumulate with no fix available.`,
      color: '#B45309'
    },
    {
      type: 'UNDERUTILIZED',
      icon: '▽',
      label: 'Underutilized',
      desc: 'Resources that are still running and receiving traffic, but at a fraction of their provisioned capacity — over-allocated memory, oversized throughput units, underutilised clusters or gateways. Downscale or resize; these are still in use, so deletion is not recommended.',
      color: '#CA8A04'
    },
    {
      type: 'SECURITY',
      icon: '⚿',
      label: 'Security',
      desc: 'SSL/TLS certificates and cryptographic keys nearing or past their expiration date, Azure AD app registration client secrets/certificates due for renewal, plus other resources with direct security exposure — public access, open network ingress, stale credentials, or disabled rotation. These need action before their deadline to avoid outages or exposure.',
      color: '#7C3AED'
    },
    {
      type: 'PIPELINE_SILENT',
      icon: '⏸',
      label: 'Silent Pipelines',
      desc: `${pipelineSourceTab} are active and provisioned, but zero events are reaching the target ${pipelineTargetTab}. The automated pipeline is broken — and no alarm has fired to alert you.`,
      color: '#EA580C'
    },
    {
      type: 'ABANDONED',
      icon: '◌',
      label: 'Dead Code',
      desc: `Resources deployed with zero activity for an extended period — dead weight still holding live ${accessTermTab} and accumulating unpatched vulnerabilities as the runtime ages.`,
      color: '#DC2626'
    },
    {
      type: 'ANOMALY_DROP',
      icon: '↘',
      label: 'Traffic Anomalies',
      desc: 'Functions showing a sharp drop in invocations vs the prior period — typically a broken upstream caller or a silent deployment failure that no alarm caught.',
      color: '#DC2626'
    },
    {
      type: 'HIGH_ERROR_RATE',
      icon: '✕',
      label: 'High Error Rate',
      desc: 'Resources where a significant percentage of operations are failing (errors, timeouts, dropped packets, restarts, or failed deliveries). Cost is being spent on failed work that produces no value for users or downstream systems.',
      color: '#DC2626'
    },
    {
      type: 'QUEUE',
      icon: '▣',
      label: 'Queue Issues',
      desc: 'Message queues and topics (SQS/Service Bus/Event Grid, dead-letter destinations) with stuck or unprocessed messages — indicating processing failures or backlog accumulation that may affect downstream consumers.',
      color: '#EA580C'
    },
    {
      type: 'OUTAGES',
      icon: '⛔',
      label: 'Outages',
      desc: 'Resources that were completely unavailable during the scan window — Kafka (MSK) clusters with offline partitions, and Container Apps running zero replicas. These are actual outages, not just degraded performance.',
      color: '#991B1B'
    }
  ];

  const tabsHTML = TAB_DEFS.filter((t) => t.type === 'ALL' || (groupCounts[t.type] || 0) > 0)
    .map((t) => {
      const count = t.type === 'ALL' ? findings.length : groupCounts[t.type] || 0;
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
    })
    .join('');

  const patcher = isAzure ? 'Microsoft' : 'AWS';
  const throttleExplainAws =
    'This function is being throttled — AWS is rejecting invocations because concurrent execution limits are reached. Affected calls may fail silently without a retry mechanism.';
  const throttleExplainAzure =
    "This function is being throttled — a large share of requests are returning HTTP 429 as the app hits its plan's concurrency or scale-out limits. Affected calls may fail silently without a retry mechanism.";
  const throttleExplain = isAzure ? throttleExplainAzure : throttleExplainAws;
  const abandonedExplainAws =
    'Zero invocations for an extended period with no recent code changes. This is dead code — but it still holds live IAM permissions and will accumulate unpatched vulnerabilities as its runtime ages. Every deployed Lambda is an attack surface, active or not.';
  const abandonedExplainAzure =
    'Zero executions over the window and the app is stopped or disabled. This is dead weight — but it still holds live RBAC role assignments, connection strings, and app settings, and will accumulate unpatched vulnerabilities as its runtime ages.';
  const abandonedExplain = isAzure ? abandonedExplainAzure : abandonedExplainAws;
  const pipelineExplainAws =
    'This EventBridge rule is enabled and scheduled to run, but zero events are arriving at its target Lambda function. The automated pipeline is completely broken — and no CloudWatch alarm has fired to alert you. This failure is only visible when EventBridge and Lambda are analysed together.';
  const pipelineExplainAzure =
    'This Event Grid topic is provisioned and enabled, but zero events are arriving at its target Azure Function. The automated pipeline is completely broken — and no Azure Monitor alert has fired to tell you. This failure is only visible when Event Grid and Functions are analysed together.';
  const pipelineExplain = isAzure ? pipelineExplainAzure : pipelineExplainAws;
  const deprecatedExplainAws =
    'AWS has stopped releasing security patches for this software version. Any CVE (security vulnerability) published after the end-of-life date is permanently unpatched in this function. These appear as open findings in security audits and can block compliance certifications.';
  const deprecatedExplainAzure =
    'Microsoft has stopped releasing security patches for this software version. Any CVE (security vulnerability) published after the end-of-life date is permanently unpatched in this function. These appear as open findings in security audits and can block compliance certifications.';

  const TYPE_EXPLAIN = {
    PIPELINE_SILENT: pipelineExplain,
    DEPRECATED_RUNTIME: `${patcher} has stopped releasing security patches for this software version. Any CVE (security vulnerability) published after the end-of-life date is permanently unpatched in this function. These appear as open findings in security audits and can block compliance certifications.`,
    CERT_EXPIRING:
      'This SSL/TLS certificate or cryptographic key is at or past its expiration date. Once expired, TLS handshakes and cryptographic operations that depend on it fail hard — this is an outage risk, not just a security-audit finding.',
    ABANDONED: abandonedExplain,
    LOW_ACTIVITY:
      'This resource is receiving minimal but non-zero traffic. It is not idle — usage-based billing (e.g. Azure Functions consumption plans) already scales cost to zero between invocations, so low traffic alone is not wasting reserved capacity. Confirm it is still needed rather than deleting it outright.',
    ANOMALY_DROP:
      "This function's invocations dropped sharply compared to the prior period. This is typically caused by a broken upstream caller that stopped sending requests, or a silent deployment failure that reduced traffic without triggering any monitoring alert.",
    HIGH_ERROR_RATE:
      'More than 20% of operations are failing (errors, timeouts, dropped packets, or failed deliveries, depending on the service). Cost is being spent on failed work, and any services or users depending on this resource may be receiving errors.',
    IDLE: 'This resource is consuming allocated capacity (and cost) with minimal or zero actual usage. Rightsizing or removing it recovers cost without impacting active workloads.',
    PC_IDLE: 'Provisioned Concurrency keeps instances warm to eliminate cold starts — but this function has had zero invocations. You are paying for warm instances that are never invoked.',
    PC_OVER_PROVISIONED: "Provisioned Concurrency is set higher than the function's peak utilisation. Reducing the setting saves cost without impacting cold-start performance.",
    DLQ_MESSAGES: 'Messages or events have accumulated in the dead-letter destination — the primary subscriber is failing to process them. These failed items have not been processed or reviewed.',
    STALE_MESSAGES: 'Messages in this queue are older than expected, suggesting the consumer stopped processing or the queue is backed up with unhandled messages.',
    MISSING_TAGS:
      'This resource is missing recommended tags (Environment, Team/Owner). Tags are required for cost attribution, security policies, and automated governance across the account/subscription.',
    NO_RETENTION: 'This log group has no retention policy — logs are kept indefinitely, accumulating storage costs and potentially complicating data-retention compliance.',
    THROTTLED: throttleExplain,
    OVER_ALLOCATED:
      'Configured memory is far above actual peak usage. Cloud providers charge for configured memory, not used memory — reducing the setting directly reduces compute cost per invocation.',
    OVER_PROVISIONED:
      'Provisioned capacity (throughput, RU/s, IOPS, gateway scale units) is far above actual usage. You are paying for capacity that sits idle — reducing it, or switching to an autoscale/on-demand mode, cuts cost without affecting performance.',
    STOPPED_NOT_DEALLOCATED:
      'This VM is stopped but not deallocated — Azure still reserves and bills for its compute capacity. Only a deallocated VM stops compute charges; a merely-stopped one keeps costing money while doing no work.',
    MSK_OFFLINE: 'This Kafka (MSK) cluster has offline partitions — topic partitions are unavailable, meaning producers cannot write and consumers cannot read the affected data.',
    MSK_DURABILITY_RISK: 'The replication factor is below the recommended minimum. A single broker failure could result in data loss on this cluster.',
    MSK_DISK_CRITICAL: 'Disk usage on this MSK cluster is critically high. When disks fill completely, Kafka brokers can fail and data can be lost.',
    MSK_IDLE: 'This Kafka (MSK) cluster has had minimal or zero message traffic. MSK is one of the more expensive AWS services — an idle cluster is significant cost waste.',
    MSK_UNDERUTILIZED: 'This MSK cluster has low throughput relative to its provisioned broker capacity. Consider scaling down to a smaller broker type to reduce cost.',
    S3_PUBLIC_ACCESS:
      'This S3 bucket does not have all four Block Public Access settings enabled. Depending on bucket ACLs and bucket policies, this bucket may be readable or writable by anyone on the internet — including its contents, which could contain sensitive data.',
    SG_OPEN_INGRESS:
      'This EC2 security group has an ingress rule that allows connections from any IP address on the internet (0.0.0.0/0). The exposed port gives any external actor a direct network path to your resources — a common entry point for automated scanning, credential brute-forcing, and exploitation.',
    IAM_KEY_STALE:
      'This IAM access key has not been rotated since it was created. Long-lived credentials are a primary vector for account compromise — if the key was ever exposed in code, logs, or a third-party tool, it remains valid until explicitly rotated. CIS AWS Benchmark 1.14 requires rotation every 90 days.',
    SECRET_NO_ROTATION:
      'This secret is being actively used but has automatic rotation disabled. A static credential that never rotates remains valid indefinitely — if it is ever leaked, there is no automatic recovery. AWS Secrets Manager supports fully-managed rotation for many secret types including RDS, Redshift, and custom Lambda-based rotators.',
    API_IDLE:
      'This API Management gateway has served zero requests over the window. Dedicated tiers (Developer, Basic, Standard, Premium) bill a fixed fee regardless of traffic — an idle gateway is pure waste. Consumption tier has no fixed cost, but an unused gateway is still clutter and an unnecessary attack surface.',
    CDN_IDLE:
      'This CDN endpoint is provisioned and configured but has served zero requests. It carries no direct data-transfer cost while idle, but represents an unused, unmonitored edge of your attack surface.',
    CDN_ACTIVE: 'This CDN endpoint is actively serving traffic. Shown for cost visibility — review cache hit ratio and compression settings to ensure you are not paying for avoidable origin fetches.',
    EH_IDLE:
      'This Event Hubs namespace has had zero messages in or out over the window. Throughput units are billed on a fixed hourly basis regardless of traffic — an idle namespace is a fixed, avoidable cost.',
    EH_UNDERUTILIZED: 'This Event Hubs namespace is provisioned with more throughput units than its actual traffic requires. You are paying for ingress/egress capacity that sits mostly idle.',
    EH_THROTTLED: 'Producers or consumers on this Event Hubs namespace are being throttled or hitting quota limits. This causes retries, added latency, or dropped events on the client side.',
    CA_NO_RUNNING_REPLICAS:
      'This Container App is configured to always run at least one replica (minReplicas > 0), but zero replicas actually ran during the window. You are paying the fixed per-replica charge for a container that never started successfully.',
    UNDERUTILISED:
      "This Container App's replicas are running well below their allocated CPU and memory. Container Apps bills per-replica resource allocation regardless of actual usage, so lowering the per-container CPU/memory (or replica count) directly reduces cost.",
    KV_NO_SOFT_DELETE:
      'Soft delete is disabled on this Key Vault. Without it, a deleted vault and every secret, key, and certificate inside it is unrecoverable — accidental deletion becomes permanent data loss.',
    KV_NO_PURGE_PROTECTION:
      'Purge protection is disabled. Soft delete alone still allows anyone with delete permissions to permanently purge the vault before its retention period ends, bypassing the recovery window soft delete is meant to provide.',
    KV_PUBLIC_ACCESS:
      "This vault's network ACLs default to allowing access from any public IP. Secrets, keys, and certificates are reachable over the public internet unless narrowed by an explicit allow-list, virtual network rule, or private endpoint.",
    NAT_IDLE: 'This NAT Gateway processed minimal or no traffic over the window. NAT Gateways bill a fixed hourly charge regardless of traffic volume, so an idle gateway is a fixed, avoidable cost.',
    NAT_LOW_UTILISATION:
      "This NAT Gateway is seeing low outbound traffic relative to a dedicated gateway's fixed cost. Consider consolidating with another subnet's gateway if this level of usage persists.",
    APP_SECRET_EXPIRING:
      'This Azure AD (Entra ID) app registration has a client secret or certificate credential at or past its expiration date. Once expired, every application or service authenticating as this app via client credentials fails sign-in outright — this is an outage risk, not just a security-audit finding.'
  };

  // Explain text for a finding's own provider — matters once a report can mix AWS and
  // Azure findings (provider === 'both'); for single-provider reports this always resolves
  // to the same string the ternaries above already picked.
  function explainTextFor(f) {
    const az = f.provider === 'azure';
    if (f.type === 'PIPELINE_SILENT') return az ? pipelineExplainAzure : pipelineExplainAws;
    if (f.type === 'DEPRECATED_RUNTIME') return az ? deprecatedExplainAzure : deprecatedExplainAws;
    if (f.type === 'ABANDONED') return az ? abandonedExplainAzure : abandonedExplainAws;
    if (f.type === 'THROTTLED') return az ? throttleExplainAzure : throttleExplainAws;
    return TYPE_EXPLAIN[f.type] || '';
  }

  const totalSavings = findings.reduce((sum, f) => sum + (f.estimatedMonthlySavings || 0), 0);
  const serviceCount = Object.keys(byService).length;

  // ── Narrative ──────────────────────────────────────────────────────────────
  const narrativeParts = [];
  if (deprecatedCount > 0) {
    const eolRuntimes = [
      ...new Set(
        findings
          .filter((f) => f.type === 'DEPRECATED_RUNTIME')
          .map((f) => f.metrics?.runtime)
          .filter(Boolean)
      )
    ];
    const runtimeList = eolRuntimes.length > 0 ? ` (${eolRuntimes.slice(0, 3).join(', ')})` : '';
    narrativeParts.push(
      `<strong>${deprecatedCount} function${deprecatedCount > 1 ? 's' : ''} on end-of-life runtimes${runtimeList}</strong> — ${patcherTab} has stopped shipping patches. CVEs published since the EOL date are permanently unpatched.`
    );
  }
  if (pipelineCount > 0) {
    const pipelineProviders = new Set(findings.filter((f) => f.type === 'PIPELINE_SILENT').map((f) => f.provider));
    const pipelineSourceNarr = pipelineProviders.size > 1 ? 'automated pipeline rule' : pipelineProviders.has('azure') ? 'Event Grid topic' : 'EventBridge rule';
    narrativeParts.push(
      `<strong>${pipelineCount} automated pipeline${pipelineCount > 1 ? 's' : ''} completely silent</strong> — ${pipelineSourceNarr}${pipelineCount > 1 ? 's' : ''} enabled and provisioned but zero events reaching target function${pipelineCount > 1 ? 's' : ''}. No alarm has fired.`
    );
  }
  if (anomalyCount > 0) {
    narrativeParts.push(`<strong>${anomalyCount} function${anomalyCount > 1 ? 's' : ''} with sharp traffic drop</strong> — likely a broken upstream caller or silent deployment failure.`);
  }
  const abandonedFindings = findings.filter((f) => f.type === 'ABANDONED').sort((a, b) => (b.metrics?.lastModifiedDaysAgo ?? 0) - (a.metrics?.lastModifiedDaysAgo ?? 0));
  if (abandonedFindings.length > 0) {
    const oldest = abandonedFindings[0];
    const age = oldest.metrics?.lastModifiedDaysAgo;
    const ageStr = age != null ? (age >= 365 ? `~${(age / 365).toFixed(1)} years` : `${age} days`) : 'an extended period';
    const abandonedProviders = new Set(abandonedFindings.map((f) => f.provider));
    const resourceNoun = abandonedProviders.size === 1 && !abandonedProviders.has('azure') ? 'Lambda function' : 'resource';
    narrativeParts.push(
      `<strong>${abandonedFindings.length} ${resourceNoun}${abandonedFindings.length > 1 ? 's' : ''} deployed with zero activity</strong> — dead weight holding live ${accessTermTab}. Oldest: <code>${escapeHtml(oldest.resourceName)}</code>, unmodified for ${ageStr}.`
    );
  }
  if (certCount > 0) {
    const certFindings = findings.filter((f) => f.type === 'CERT_EXPIRING').sort((a, b) => (a.metrics?.daysUntilExpiry ?? Infinity) - (b.metrics?.daysUntilExpiry ?? Infinity));
    const nearest = certFindings[0];
    const nearestDays = nearest.metrics?.daysUntilExpiry;
    const nearestStr = nearestDays != null ? (nearestDays < 0 ? `expired ${Math.abs(nearestDays)} day(s) ago` : `expires in ${nearestDays} day(s)`) : 'expiring soon';
    narrativeParts.push(
      `<strong>${certCount} certificate${certCount > 1 ? 's' : ''}/key${certCount > 1 ? 's' : ''} nearing expiry</strong> — must be renewed or rotated before the deadline to avoid TLS/crypto failures. Nearest: <code>${escapeHtml(nearest.resourceName)}</code>, ${nearestStr}.`
    );
  }
  if (appSecretCount > 0) {
    const appSecretFindings = findings.filter((f) => f.type === 'APP_SECRET_EXPIRING').sort((a, b) => (a.metrics?.daysUntilExpiry ?? Infinity) - (b.metrics?.daysUntilExpiry ?? Infinity));
    const nearest = appSecretFindings[0];
    const nearestDays = nearest.metrics?.daysUntilExpiry;
    const nearestStr = nearestDays != null ? (nearestDays < 0 ? `expired ${Math.abs(nearestDays)} day(s) ago` : `expires in ${nearestDays} day(s)`) : 'expiring soon';
    narrativeParts.push(
      `<strong>${appSecretCount} app registration credential${appSecretCount > 1 ? 's' : ''} nearing expiry</strong> — client secrets/certs must be renewed before the deadline or client-credential sign-ins fail outright. Nearest: <code>${escapeHtml(nearest.resourceName)}</code>, ${nearestStr}.`
    );
  }

  const narrativeHTML =
    narrativeParts.length > 0
      ? `<div class="narrative-bar">
        <div class="narrative-total">${narrativeParts.length} issue${narrativeParts.length > 1 ? 's' : ''} need${narrativeParts.length > 1 ? '' : 's'} attention</div>
        ${narrativeParts.map((p) => `<div class="narrative-item">${p}</div>`).join('')}
      </div>`
      : '';

  // ── Service breakdown ──────────────────────────────────────────────────────
  const serviceBreakdownHTML = Object.entries(byService)
    .sort((a, b) => b[1] - a[1])
    .map(([svc, cnt]) => {
      const bg = serviceColors[svc] || '#64748b';
      const lbl = serviceIconLabel[svc] || svc[0];
      return `<div class="service-tile">
      <div class="service-icon-lg" style="background:${bg}">${lbl}</div>
      <div class="svc-count">${cnt}</div>
      <div class="svc-name">${svc}</div>
    </div>`;
    })
    .join('');

  // ── Insights chart data ────────────────────────────────────────────────────
  const chartLabels = Object.keys(byService);
  const chartCounts = Object.values(byService);
  const chartColors = chartLabels.map((s) => serviceColors[s] || '#64748b');

  const serviceList = Object.keys(byService)
    .sort((a, b) => byService[b] - byService[a])
    .slice(0, 8);
  const svcHigh = serviceList.map((s) => findings.filter((f) => f.service === s && f.priority === 'HIGH').length);
  const svcMed = serviceList.map((s) => findings.filter((f) => f.service === s && f.priority === 'MEDIUM').length);
  const svcLow = serviceList.map((s) => findings.filter((f) => f.service === s && f.priority === 'LOW').length);

  const serviceSectionHTML =
    serviceCount > 0
      ? `
    <div class="section-heading">Findings by Service <span class="sh-sub">${serviceCount} service${serviceCount !== 1 ? 's' : ''} affected</span></div>
    <div class="services-row">
      <div class="service-tiles">${serviceBreakdownHTML}</div>
      <div class="chart-card"><canvas id="doughnut-chart"></canvas></div>
    </div>
    ${
      serviceList.length > 0
        ? `
    <div class="insight-card" style="margin-bottom:1.75rem">
      <div class="insight-title">Findings by Service &amp; Severity</div>
      <div class="insight-subtitle">Breakdown of HIGH / MEDIUM / LOW findings per service</div>
      <canvas id="severity-chart"></canvas>
    </div>`
        : ''
    }`
      : '';

  const summaryBarHTML = `
    <div class="sum-item"><div class="sum-val">${scanned.toLocaleString()}</div><div class="sum-lbl">Resources Scanned</div></div>
    <div class="sum-item"><div class="sum-val">${findings.length}</div><div class="sum-lbl">Total Findings</div></div>
    <div class="sum-item high"><div class="sum-val">${highCount}</div><div class="sum-lbl">High</div></div>
    <div class="sum-item medium"><div class="sum-val">${mediumCount}</div><div class="sum-lbl">Medium</div></div>
    <div class="sum-item low"><div class="sum-val">${lowCount}</div><div class="sum-lbl">Low</div></div>
    ${totalSavings > 0 ? `<div class="sum-item savings"><div class="sum-val">$${totalSavings.toFixed(0)}/mo</div><div class="sum-lbl">Recoverable</div></div>` : ''}
    ${totalSpend > 0 ? `<div class="sum-item spend"><div class="sum-val">$${totalSpend.toFixed(0)}/mo</div><div class="sum-lbl">Est. Spend</div></div>` : ''}
  `;

  // ── Per-cloud scoped views (All / AWS / Azure toggle) ──────────────────────
  // "All" reuses the combined computations above; AWS/Azure are rebuilt from that
  // cloud's findings alone so the toggle re-scopes the whole page, not just the table.
  const allView = {
    highCount,
    mediumCount,
    lowCount,
    summaryBarHTML,
    narrativeHTML,
    serviceSectionHTML,
    tabsHTML,
    findingsHeadingCountHTML: `${findings.length} total · ${highCount} high · ${mediumCount} medium · ${lowCount} low`,
    chartLabels,
    chartCounts,
    chartColors,
    severityLabels: serviceList,
    severityHigh: svcHigh,
    severityMed: svcMed,
    severityLow: svcLow
  };

  const cloudViews = isBoth
    ? {
        all: allView,
        aws: buildScopedView(
          findings.filter((f) => f.provider === 'aws'),
          false,
          false,
          summary.aws?.resourcesScanned ?? 0,
          summary.aws?.costContext?.totalEstimatedCost ?? 0
        ),
        azure: buildScopedView(
          findings.filter((f) => f.provider === 'azure'),
          true,
          false,
          summary.azure?.resourcesScanned ?? 0,
          summary.azure?.costContext?.totalEstimatedCost ?? 0
        )
      }
    : null;

  // ── Finding rows ──────────────────────────────────────────────────────────
  function typeLabel(type) {
    const labels = {
      ABANDONED: 'Dead Code',
      DEPRECATED_RUNTIME: 'EOL Runtime',
      PIPELINE_SILENT: 'Silent Pipeline',
      CERT_EXPIRING: 'Cert Expiring',
      ANOMALY_DROP: 'Traffic Anomaly',
      HIGH_ERROR_RATE: 'High Error Rate',
      IDLE: 'Idle',
      LOW_ACTIVITY: 'Low Activity',
      OVER_ALLOCATED: 'Over-allocated',
      THROTTLED: 'Throttled',
      DLQ_MESSAGES: 'Dead Letter Queue',
      STALE_MESSAGES: 'Stale Messages',
      PC_IDLE: 'Idle (Prov. Concurrency)',
      PC_OVER_PROVISIONED: 'Over-provisioned (PC)',
      MSK_IDLE: 'Idle Cluster',
      MSK_UNDERUTILIZED: 'Low Utilisation',
      MSK_OFFLINE: 'Offline Partitions',
      MSK_DURABILITY_RISK: 'Durability Risk',
      MSK_DISK_CRITICAL: 'Disk Critical',
      MISSING_TAGS: 'Missing Tags',
      NO_RETENTION: 'No Log Retention',
      S3_PUBLIC_ACCESS: 'Public Access',
      SG_OPEN_INGRESS: 'Open to Internet',
      IAM_KEY_STALE: 'Stale Key',
      SECRET_NO_ROTATION: 'No Rotation',
      OVER_PROVISIONED: 'Over-provisioned',
      STOPPED_NOT_DEALLOCATED: 'Stopped, Not Deallocated',
      API_IDLE: 'Idle Gateway',
      CDN_IDLE: 'Idle Endpoint',
      CDN_ACTIVE: 'Active (Cost Visibility)',
      EH_IDLE: 'Idle Namespace',
      EH_UNDERUTILIZED: 'Low Throughput',
      EH_THROTTLED: 'Throttled',
      CA_NO_RUNNING_REPLICAS: 'No Running Replicas',
      UNDERUTILISED: 'Underutilised',
      KV_NO_SOFT_DELETE: 'No Soft Delete',
      KV_NO_PURGE_PROTECTION: 'No Purge Protection',
      KV_PUBLIC_ACCESS: 'Public Network Access',
      NAT_IDLE: 'Idle Gateway',
      NAT_LOW_UTILISATION: 'Low Utilisation',
      APP_SECRET_EXPIRING: 'App Secret Expiring'
    };
    return labels[type] || type.replace(/_/g, ' ');
  }

  const findingsRowsHTML = findings
    .map((f, idx) => {
      const bg = serviceColors[f.service] || '#64748b';
      const lbl = serviceIconLabel[f.service] || f.service[0];
      const typeG = typeGroupOf(f.type);
      const metricsHTML = Object.entries(f.metrics || {})
        .map(([k, v]) => `<div class="metric-row"><span class="metric-label">${fmtKey(k)}</span><span class="metric-value">${fmtVal(k, v)}</span></div>`)
        .join('');
      const s = f.estimatedMonthlySavings;
      const savingsHTML = s > 0 ? `<span class="savings-badge">${s < 0.01 ? '< $0.01' : '~$' + s.toFixed(2)}/mo</span>` : '<span class="savings-nil">—</span>';
      const fixSection = f.fixCommand
        ? `
      <div class="fix-section">
        <h4>Fix Command</h4>
        <pre class="fix-command" id="fix-cmd-${idx}">${escapeHtml(f.fixCommand)}</pre>
        <button class="copy-btn fix-copy-btn" onclick="copyFix(${idx}, event)">Copy</button>
      </div>`
        : '';
      const alarmSection = f.suggestedAlarm
        ? `
      <div class="alarm-section">
        <h4>${f.type === 'NO_RETENTION' ? 'Remediation Command' : 'Suggested Alarm'}</h4>
        <pre class="alarm-command" id="alarm-cmd-${idx}">${escapeHtml(f.suggestedAlarm)}</pre>
        <button class="copy-btn" onclick="copyAlarm(${idx}, event)">Copy</button>
      </div>`
        : '';

      const explainText = explainTextFor(f);
      const explainBox = explainText
        ? `
      <div class="type-explain-box">
        <div class="explain-title">What does this mean?</div>
        <div class="explain-text">${escapeHtml(explainText)}</div>
      </div>`
        : '';

      return `
      <tr class="finding-row" id="frow-${idx}" onclick="toggleDetail(${idx})"
          data-priority="${f.priority}"
          data-service="${escapeHtml(f.service)}"
          data-name="${escapeHtml(f.resourceName).toLowerCase()}"
          data-env="${escapeHtml(f.environment || 'unknown')}"
          data-team="${escapeHtml(f.team || '')}"
          data-typegroup="${typeG}">
        <td><span class="priority-dot dot-${f.priority}"></span><span class="badge badge-${f.priority}">${f.priority}</span></td>
        <td><span class="service-icon-sm" style="background:${bg}">${lbl}</span>${escapeHtml(f.service)}</td>
        <td><span class="resource-name">${escapeHtml(f.resourceName)}</span></td>
        <td><span class="badge badge-type badge-type-${f.type}">${typeLabel(f.type)}</span></td>
        <td class="details-cell">${escapeHtml(f.details)}</td>
        <td class="savings-cell">${savingsHTML}</td>
        <td class="chevron-cell"><span class="chevron" id="chev-${idx}">▸</span></td>
      </tr>
      <tr class="detail-row" id="detail-${idx}">
        <td colspan="7">
          <div class="detail-content">
            <div class="detail-section">
              <h4>Metrics <span class="h4-sub">last ${days} days</span></h4>
              ${metricsHTML || '<div class="metric-row"><span class="metric-label muted">No metrics available</span></div>'}
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
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudLens — ${providerLabel} Health &amp; Cost Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"><\/script>
  <style>
    :root {
      --bg:       #F8FAFC;
      --surface:  #FFFFFF;
      --surface-2:#F1F5F9;
      --text:     #0F172A;
      --text-2:   #334155;
      --muted:    #64748B;
      --border:   #E2E8F0;
      --border-2: #CBD5E1;
      --high:     #DC2626;
      --medium:   #EA580C;
      --low:      #D97706;
      --blue:     #2563EB;
      --green:    #16A34A;
      --radius:   8px;
      --shadow:   0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
      --shadow-md:0 4px 6px rgba(0,0,0,0.06), 0 2px 4px rgba(0,0,0,0.04);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }

    /* ── Header ── */
    .header { background: var(--surface); border-bottom: 1px solid var(--border); border-top: 3px solid var(--blue); padding: 0 2.5rem; display: flex; align-items: center; justify-content: space-between; height: 70px; }
    .header-brand { display: flex; align-items: center; gap: 0.875rem; }
    .header-logo { font-size: 1.85rem; font-weight: 800; color: var(--text); letter-spacing: -1px; }
    .header-logo span { color: var(--blue); }
    .header-badge { background: var(--surface-2); border: 1px solid var(--border); border-radius: 99px; padding: 0.2rem 0.7rem; font-size: 0.72rem; font-weight: 600; color: var(--muted); }
    .header-meta { font-size: 0.78rem; color: var(--muted); display: flex; align-items: center; gap: 1.25rem; }
    .header-meta strong { color: var(--text-2); font-weight: 600; }
    .cloud-toggle { display: flex; background: var(--surface-2); border: 1px solid var(--border); border-radius: 99px; padding: 2px; gap: 2px; }
    .cloud-toggle-btn { border: none; background: transparent; padding: 0.25rem 0.7rem; border-radius: 99px; font-size: 0.72rem; font-weight: 600; color: var(--muted); cursor: pointer; font-family: inherit; transition: all 0.12s; }
    .cloud-toggle-btn:hover { color: var(--text-2); }
    .cloud-toggle-btn.active { background: var(--surface); color: var(--text-2); box-shadow: var(--shadow); }
    .cloud-toggle-btn.cloud-aws.active   { background: #FEF3E2; color: #C2410C; }
    .cloud-toggle-btn.cloud-azure.active { background: #DBEAFE; color: #1D4ED8; }

    .container { max-width: 1400px; margin: 0 auto; padding: 1.75rem 2.5rem; }

    /* ── Summary bar ── */
    .summary-bar { display: flex; align-items: stretch; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-md); margin-bottom: 1.75rem; overflow: hidden; }
    .sum-item { flex: 1; padding: 1.25rem 1.5rem; display: flex; flex-direction: column; gap: 0.25rem; border-right: 1px solid var(--border); }
    .sum-item:last-child { border-right: none; }
    .sum-val { font-size: 2rem; font-weight: 800; line-height: 1; color: var(--text); }
    .sum-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
    .sum-item.high   { border-top: 3px solid var(--high); }
    .sum-item.medium { border-top: 3px solid var(--medium); }
    .sum-item.low    { border-top: 3px solid var(--low); }
    .sum-item.high   .sum-val { color: var(--high); }
    .sum-item.medium .sum-val { color: var(--medium); }
    .sum-item.low    .sum-val { color: var(--low); }
    .sum-item.savings .sum-val { color: var(--green); }
    .sum-item.spend  .sum-val  { color: #92400e; }

    /* ── Section headings ── */
    .section-label { font-size: 0.7rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.6rem; }
    .section-heading { font-size: 1.35rem; font-weight: 800; color: var(--text); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.75rem; letter-spacing: -0.4px; padding-left: 0.85rem; border-left: 4px solid var(--blue); line-height: 1.2; }
    .section-heading .sh-sub { font-size: 0.85rem; font-weight: 500; color: var(--muted); letter-spacing: 0; }
    .findings-heading { font-size: 1.5rem; font-weight: 800; color: var(--text); margin-bottom: 1rem; letter-spacing: -0.5px; display: flex; align-items: center; gap: 0.875rem; padding-left: 0.85rem; border-left: 4px solid var(--blue); line-height: 1.2; }
    .findings-heading .fh-count { font-size: 0.88rem; font-weight: 500; color: var(--muted); letter-spacing: 0; }

    /* ── Service breakdown ── */
    .services-row { display: flex; gap: 1.5rem; align-items: flex-start; margin-bottom: 1.5rem; }
    .service-tiles { display: flex; gap: 0.5rem; flex-wrap: wrap; flex: 1; }
    .service-tile { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.6rem 0.875rem; text-align: center; min-width: 72px; box-shadow: var(--shadow); }
    .service-icon-lg { width: 28px; height: 28px; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.55rem; font-weight: 800; color: white; margin-bottom: 0.3rem; }
    .svc-count { font-size: 1.1rem; font-weight: 700; color: var(--text); }
    .svc-name  { font-size: 0.62rem; color: var(--muted); margin-top: 0.1rem; }
    /* ── Insights chart ── */
    .insight-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem 1.5rem; box-shadow: var(--shadow); }
    .insight-title { font-size: 1rem; font-weight: 700; color: var(--text); margin-bottom: 0.3rem; }
    .insight-subtitle { font-size: 0.75rem; color: var(--muted); margin-bottom: 1.1rem; }
    .insight-card canvas { max-height: 260px; }

    /* ── Narrative bar ── */
    .narrative-bar { background: #FFFBEB; border: 1px solid #FCD34D; border-left: 4px solid #F59E0B; border-radius: var(--radius); padding: 1rem 1.4rem; margin-bottom: 1.75rem; display: flex; flex-direction: column; gap: 0.6rem; }
    .narrative-total { font-size: 0.8rem; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; color: #92400E; }
    .narrative-item { font-size: 0.875rem; color: #78350F; line-height: 1.65; }
    .narrative-item strong { color: #92400E; font-weight: 700; }
    .narrative-item code { font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.78rem; background: rgba(0,0,0,0.06); padding: 0.1rem 0.35rem; border-radius: 3px; }

    /* ── Type tabs ── */
    .findings-header { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius) var(--radius) 0 0; border-bottom: none; padding: 0 1rem; }
    .type-tabs { display: flex; gap: 0; overflow-x: auto; scrollbar-width: none; }
    .type-tabs::-webkit-scrollbar { display: none; }
    .type-tab { display: flex; align-items: center; gap: 0.4rem; padding: 0.75rem 1rem; background: none; border: none; border-bottom: 2px solid transparent; cursor: pointer; white-space: nowrap; color: var(--muted); font-size: 0.8rem; transition: all 0.15s; flex-shrink: 0; font-family: inherit; }
    .type-tab:hover { color: var(--text-2); }
    .type-tab.active { color: var(--blue); border-bottom-color: var(--blue); font-weight: 600; }
    .tab-icon  { font-size: 0.85rem; }
    .tab-count { font-weight: 700; font-size: 0.78rem; background: var(--surface-2); border-radius: 99px; padding: 0.05rem 0.45rem; }
    .type-tab.active .tab-count { background: #DBEAFE; color: var(--blue); }

    /* ── Description bar ── */
    .type-desc-bar { display: none; padding: 0.6rem 1rem; background: #EFF6FF; border-top: 1px solid #BFDBFE; font-size: 0.78rem; color: #1E40AF; }
    .type-desc-bar.visible { display: block; }

    /* ── Toolbar ── */
    .toolbar { background: var(--surface); border: 1px solid var(--border); border-top: none; padding: 0.625rem 1rem; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
    .search-wrap { flex: 1; min-width: 200px; position: relative; }
    .search-wrap input { width: 100%; background: var(--surface); border: 1px solid var(--border-2); border-radius: 6px; padding: 0.4rem 0.75rem 0.4rem 1.8rem; color: var(--text); font-size: 0.82rem; outline: none; transition: border-color 0.15s; font-family: inherit; }
    .search-wrap input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37,99,235,0.08); }
    .search-wrap input::placeholder { color: var(--muted); }
    .search-icon { position: absolute; left: 0.6rem; top: 50%; transform: translateY(-50%); color: var(--muted); font-size: 0.8rem; pointer-events: none; }
    .filter-group { display: flex; gap: 0.25rem; align-items: center; }
    .filter-label { color: var(--muted); font-size: 0.72rem; margin-right: 0.15rem; }
    .filter-btn { padding: 0.3rem 0.65rem; border-radius: 6px; border: 1px solid var(--border-2); background: var(--surface); color: var(--muted); font-size: 0.75rem; cursor: pointer; transition: all 0.12s; font-family: inherit; }
    .filter-btn:hover { border-color: var(--border-2); color: var(--text-2); background: var(--surface-2); }
    .filter-btn.active { background: #DBEAFE; border-color: #93C5FD; color: #1D4ED8; font-weight: 600; }
    .filter-btn.high.active   { background: #FEE2E2; border-color: #FCA5A5; color: var(--high); }
    .filter-btn.medium.active { background: #FFEDD5; border-color: #FDBA74; color: var(--medium); }
    .filter-btn.low.active    { background: #FEF9C3; border-color: #FDE047; color: #92400E; }
    .filter-btn.env-prod.active { background: #FEE2E2; border-color: #FCA5A5; color: var(--high); }
    .filter-btn.env-tst.active  { background: #FFEDD5; border-color: #FDBA74; color: var(--medium); }
    .filter-btn.env-dev.active  { background: #DBEAFE; border-color: #93C5FD; color: #1D4ED8; }
    .results-count { font-size: 0.72rem; color: var(--muted); padding: 0.3rem 0.65rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; white-space: nowrap; margin-left: auto; }
    .results-count strong { color: var(--text-2); }
    .action-btn { padding: 0.3rem 0.75rem; border-radius: 6px; border: 1px solid var(--border-2); background: var(--surface); color: var(--muted); font-size: 0.75rem; cursor: pointer; white-space: nowrap; font-family: inherit; transition: all 0.12s; }
    .action-btn:hover { color: var(--text-2); background: var(--surface-2); }
    .action-btn.green { border-color: #86EFAC; color: var(--green); background: #F0FDF4; }
    .action-btn.green:hover { background: #DCFCE7; }

    /* ── Table ── */
    .table-wrap { background: var(--surface); border: 1px solid var(--border); border-top: none; border-radius: 0 0 var(--radius) var(--radius); overflow-x: auto; box-shadow: var(--shadow); }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    thead th { background: var(--surface-2); padding: 0.65rem 1rem; text-align: left; font-weight: 700; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; border-bottom: 1px solid var(--border); }
    thead th.sortable-th { cursor: pointer; user-select: none; transition: color 0.12s; }
    thead th.sortable-th:hover { color: var(--text-2); }
    thead th.sortable-th.sorted { color: var(--blue); }
    .sort-arrow { font-size: 0.65rem; display: inline-block; width: 0.8em; }
    tbody tr.finding-row { border-top: 1px solid var(--border); cursor: pointer; transition: background 0.1s; border-left: 3px solid transparent; }
    tbody tr.finding-row[data-priority="HIGH"]   { border-left-color: var(--high); }
    tbody tr.finding-row[data-priority="MEDIUM"] { border-left-color: var(--medium); }
    tbody tr.finding-row[data-priority="LOW"]    { border-left-color: var(--low); }
    tbody tr.finding-row:hover { background: #F8FAFC; }
    tbody tr.finding-row.filtered { display: none; }
    tbody tr.detail-row { display: none; }
    tbody tr.detail-row.open { display: table-row; }
    tbody tr.detail-row.filtered { display: none !important; }
    td { padding: 0.8rem 1rem; vertical-align: middle; color: var(--text-2); font-size: 0.84rem; }

    /* ── Badges ── */
    .badge { display: inline-block; padding: 0.18rem 0.55rem; border-radius: 4px; font-size: 0.63rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }
    .badge-HIGH   { background: #FEE2E2; color: #B91C1C; }
    .badge-MEDIUM { background: #FFEDD5; color: #C2410C; }
    .badge-LOW    { background: #FEF9C3; color: #A16207; }
    .badge-type   { background: var(--surface-2); color: var(--muted); font-size: 0.6rem; border: 1px solid var(--border); }
    .badge-type-ANOMALY_DROP       { background: #FEE2E2; color: #B91C1C; border-color: #FECACA; }
    .badge-type-PIPELINE_SILENT    { background: #FFEDD5; color: #C2410C; border-color: #FED7AA; }
    .badge-type-DEPRECATED_RUNTIME { background: #FEE2E2; color: #B91C1C; border-color: #FECACA; }
    .badge-type-CERT_EXPIRING      { background: #FEF3C7; color: #B45309; border-color: #FDE68A; }
    .badge-type-APP_SECRET_EXPIRING { background: #EDE9FE; color: #6D28D9; border-color: #DDD6FE; }
    .badge-type-ABANDONED          { background: #FEE2E2; color: #991B1B; border-color: #FCA5A5; font-weight: 800; }
    .badge-type-MISSING_TAGS       { background: var(--surface-2); color: var(--muted); border-color: var(--border); }

    .priority-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 0.4rem; vertical-align: middle; flex-shrink: 0; }
    .dot-HIGH   { background: var(--high); }
    .dot-MEDIUM { background: var(--medium); }
    .dot-LOW    { background: var(--low); }

    /* ── Env badges ── */
    .env-badge { display: inline-block; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.58rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; margin-right: 0.3rem; vertical-align: middle; }
    .env-prod    { background: #FEE2E2; color: var(--high); }
    .env-tst     { background: #FFEDD5; color: var(--medium); }
    .env-dev     { background: #DBEAFE; color: #1D4ED8; }
    .env-unknown { background: var(--surface-2); color: var(--muted); }

    .service-icon-sm { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 5px; font-size: 0.54rem; font-weight: 800; color: white; margin-right: 0.45rem; vertical-align: middle; flex-shrink: 0; }
    .resource-name { font-family: 'SF Mono','Cascadia Code','Fira Code',Consolas,monospace; font-size: 0.85rem; color: var(--text); font-weight: 600; }
    .details-cell  { color: var(--text-2); max-width: 360px; font-size: 0.84rem; }
    .chevron-cell  { color: var(--muted); font-size: 0.8rem; width: 28px; }
    .savings-cell  { white-space: nowrap; }
    .savings-badge { background: #F0FDF4; color: var(--green); border: 1px solid #86EFAC; border-radius: 99px; padding: 0.18rem 0.5rem; font-size: 0.68rem; font-weight: 700; }
    .savings-nil   { color: var(--border-2); font-size: 0.8rem; }

    /* ── Detail row ── */
    tr.detail-row td { background: var(--surface-2); padding: 1.1rem 1.5rem; border-top: 1px solid var(--border); }
    .detail-content { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
    .detail-section h4 { font-size: 0.72rem; color: var(--text-2); text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 0.65rem; font-weight: 800; border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; }
    .detail-section h4 .h4-sub { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--muted); font-size: 0.72rem; }
    .metric-row { display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
    .metric-row:last-child { border-bottom: none; }
    .metric-label { color: var(--muted); }
    .metric-label.muted { color: var(--border-2); }
    .metric-value { font-weight: 600; font-family: 'SF Mono',Consolas,monospace; color: var(--text-2); }
    .recommendation { background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 6px; padding: 0.7rem 1rem; font-size: 0.8rem; color: #1E40AF; line-height: 1.6; white-space: pre-wrap; }
    .resource-arn { margin-top: 0.45rem; font-size: 0.68rem; color: var(--muted); font-family: monospace; word-break: break-all; }

    /* "What does this mean?" */
    .type-explain-box { background: #FFFBEB; border: 1px solid #FDE68A; border-radius: 6px; padding: 0.7rem 1rem; margin-bottom: 0.875rem; }
    .explain-title { font-size: 0.72rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; color: #92400E; margin-bottom: 0.4rem; }
    .explain-text  { font-size: 0.8rem; color: #78350F; line-height: 1.6; }

    /* ── Fix / Alarm commands ── */
    .fix-section { margin-top: 0.875rem; }
    .fix-section h4 { color: #15803D; }
    .fix-command { background: #F0FDF4; border: 1px solid #86EFAC; border-radius: 6px; padding: 0.65rem 0.875rem; font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.72rem; color: #166534; white-space: pre; overflow-x: auto; margin-bottom: 0.4rem; line-height: 1.7; }
    .fix-copy-btn { background: #F0FDF4 !important; border-color: #86EFAC !important; color: #15803D !important; }
    .fix-copy-btn:hover { background: #DCFCE7 !important; }
    .alarm-section { margin-top: 0.875rem; }
    .alarm-section h4 { color: var(--muted); }
    .alarm-command { background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 6px; padding: 0.65rem 0.875rem; font-family: 'SF Mono','Cascadia Code',Consolas,monospace; font-size: 0.72rem; color: #1E40AF; white-space: pre; overflow-x: auto; margin-bottom: 0.4rem; line-height: 1.7; }
    .copy-btn { padding: 0.28rem 0.7rem; background: var(--surface); border: 1px solid var(--border-2); border-radius: 5px; color: var(--muted); font-size: 0.7rem; cursor: pointer; transition: all 0.12s; font-family: inherit; }
    .copy-btn:hover { background: var(--surface-2); color: var(--text-2); }
    .copy-btn.copied { color: var(--green); border-color: #86EFAC; background: #F0FDF4; }

    /* ── Empty / no-findings states ── */
    .no-results { display: none; flex-direction: column; align-items: center; justify-content: center; padding: 3rem 2rem; gap: 0.6rem; }
    .no-results-icon  { font-size: 1.75rem; opacity: 0.35; }
    .no-results-title { font-size: 0.95rem; font-weight: 600; color: var(--muted); }
    .no-results-text  { font-size: 0.8rem; color: var(--muted); text-align: center; max-width: 320px; line-height: 1.5; }
    .no-results-btn   { margin-top: 0.25rem; padding: 0.4rem 1rem; background: var(--surface-2); border: 1px solid var(--border-2); border-radius: 6px; color: var(--text-2); font-size: 0.78rem; cursor: pointer; font-family: inherit; }
    .no-results-btn:hover { background: #DBEAFE; border-color: #93C5FD; color: #1D4ED8; }
    .no-findings { text-align: center; padding: 3rem; color: var(--muted); font-size: 0.9rem; }

    footer { text-align: center; padding: 1.25rem; color: var(--muted); font-size: 0.72rem; border-top: 1px solid var(--border); margin-top: 2rem; }

    /* ── Responsive (narrow browser windows) ── */
    @media (max-width: 960px) {
      .container { padding: 1.25rem 1rem; }
      .header { flex-wrap: wrap; height: auto; padding: 0.75rem 1.25rem; gap: 0.5rem 1rem; }
      .header-meta { flex-wrap: wrap; gap: 0.5rem 1rem; }
      .summary-bar { flex-wrap: wrap; }
      .sum-item { flex: 1 1 45%; min-width: 140px; border-right: none; border-bottom: 1px solid var(--border); }
      .services-row { flex-direction: column; }
      .service-tiles { width: 100%; }
      .chart-card { width: 100%; }
      .detail-content { grid-template-columns: 1fr; gap: 1.25rem; }
      .toolbar { flex-direction: column; align-items: stretch; }
      .filter-group { flex-wrap: wrap; }
      .results-count { margin-left: 0; }
    }

    /* ── Print / PDF ── */
    @media print {
      * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      @page { margin: 1.5cm; size: A4 landscape; }
      body { background: white; font-size: 12px; }
      .header { box-shadow: none; -webkit-print-color-adjust: exact; }
      .toolbar, .type-tabs, .type-desc-bar, .chevron-cell, .results-count { display: none !important; }
      .filter-group, .search-wrap, .action-btn { display: none !important; }
      .summary-bar { box-shadow: none; page-break-inside: avoid; }
      .sum-item.high, .sum-item.medium, .sum-item.low { border-top-width: 3px; }
      .service-tile, .chart-card { box-shadow: none; }
      .findings-header { border-bottom: 1px solid #E2E8F0; border-radius: 8px 8px 0 0; }
      .table-wrap { box-shadow: none; border-top: 1px solid #E2E8F0; }
      tbody tr.finding-row { page-break-inside: avoid; }
      tbody tr.detail-row { display: none !important; }
      .narrative-bar { page-break-inside: avoid; }
      .services-row { page-break-inside: avoid; }
      footer { page-break-before: avoid; }
      .badge-HIGH   { background: #FEE2E2 !important; color: #B91C1C !important; }
      .badge-MEDIUM { background: #FFEDD5 !important; color: #C2410C !important; }
      .badge-LOW    { background: #FEF9C3 !important; color: #A16207 !important; }
    }

    /* ── Cloud-view transition ("page switch" illusion) ── */
    #main-content { transition: opacity 0.16s ease, transform 0.16s ease; }
    #main-content.view-fade-out { opacity: 0; transform: translateY(4px); }
    #main-content.view-fade-in  { animation: viewFadeIn 0.22s ease both; }
    @keyframes viewFadeIn {
      from { opacity: 0; transform: translateY(-4px); }
      to   { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>

<div class="header">
  <div class="header-brand">
    <div class="header-logo">Cloud<span>Lens</span></div>
    <span class="header-badge">${providerLabel}</span>
    <span class="header-badge">Last ${days} days</span>
  </div>
  <div class="header-meta">
    ${
      isBoth
        ? `
    <div class="cloud-toggle">
      <button class="cloud-toggle-btn active"      data-filter="ALL"   onclick="setCloudFilter('ALL',this)">All</button>
      <button class="cloud-toggle-btn cloud-aws"   data-filter="aws"   onclick="setCloudFilter('aws',this)">AWS</button>
      <button class="cloud-toggle-btn cloud-azure" data-filter="azure" onclick="setCloudFilter('azure',this)">Azure</button>
    </div>`
        : ''
    }
    <span>Generated <strong>${now.toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short', year: 'numeric' })}</strong></span>
    <span><strong>${now.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: 'numeric', minute: '2-digit', hour12: true }).toUpperCase()} IST</strong></span>
  </div>
</div>

<div class="container">

<div id="main-content">

  <!-- Summary numbers -->
  <div class="summary-bar" id="summary-bar">${summaryBarHTML}</div>

  <div id="narrative-container">${narrativeHTML}</div>

  <!-- Service breakdown -->
  <div id="service-section">${serviceSectionHTML}</div>

  <!-- Finding browser -->
  <div class="findings-heading">Findings <span class="fh-count" id="findings-heading-count">${findings.length} total · ${highCount} high · ${mediumCount} medium · ${lowCount} low</span></div>

  <div class="findings-header">
    <div class="type-tabs" id="type-tabs-container">${tabsHTML}</div>
    <div class="type-desc-bar" id="type-desc-bar"></div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="search-icon">⌕</span>
      <input type="text" id="search-input" placeholder="Search by resource name…" oninput="applySearch(this.value)">
    </div>
    <div class="filter-group">
      <span class="filter-label">Priority:</span>
      <button class="filter-btn priority-btn active" data-filter="ALL"    onclick="setPriorityFilter('ALL',this)">All</button>
      <button class="filter-btn priority-btn high"   data-filter="HIGH"   onclick="setPriorityFilter('HIGH',this)">High (<span id="count-high">${highCount}</span>)</button>
      <button class="filter-btn priority-btn medium" data-filter="MEDIUM" onclick="setPriorityFilter('MEDIUM',this)">Med (<span id="count-medium">${mediumCount}</span>)</button>
      <button class="filter-btn priority-btn low"    data-filter="LOW"    onclick="setPriorityFilter('LOW',this)">Low (<span id="count-low">${lowCount}</span>)</button>
    </div>
    <span class="results-count" id="results-count">Showing <strong>${findings.length}</strong> of <strong>${findings.length}</strong></span>
    <button class="action-btn"       onclick="exportCSV()">↓ CSV</button>
    <button class="action-btn green" onclick="downloadFixScript()">↓ Fix Script</button>
    <button class="action-btn"       onclick="window.print()">⎙ Print / PDF</button>
  </div>

  <div class="table-wrap">
    ${
      findings.length === 0
        ? '<div class="no-findings">No findings — infrastructure looks healthy for this window.</div>'
        : `<table id="findings-table">
          <thead><tr>
            <th>Priority</th><th>Service</th><th>Resource</th>
            <th>Finding Type</th><th>Details</th>
            <th class="sortable-th" id="th-savings" onclick="sortBySavings()" title="Sort by cost">Savings <span class="sort-arrow" id="sort-arrow-savings"></span></th>
            <th></th>
          </tr></thead>
          <tbody>${findingsRowsHTML}</tbody>
        </table>
        <div class="no-results" id="no-results">
          <div class="no-results-icon">○</div>
          <div class="no-results-title">No matching findings</div>
          <div class="no-results-text">Try a different category, or clear the search and priority filters.</div>
          <button class="no-results-btn" onclick="resetFilters()">Clear filters</button>
        </div>`
    }
  </div>

</div>

</div>

<footer>CloudLens — read-only scan, no changes made to any resource &nbsp;·&nbsp; ${now.toUTCString()}</footer>

<script>
  var allFindings = ${JSON.stringify(
    findings.map((f, i) => ({
      idx: i,
      priority: f.priority,
      service: f.service,
      resourceName: f.resourceName,
      type: f.type,
      typegroup: typeGroupOf(f.type),
      details: f.details,
      region: f.region,
      savings: f.estimatedMonthlySavings || 0,
      environment: f.environment || 'unknown',
      team: f.team || '',
      fixCommand: f.fixCommand || '',
      provider: f.provider || 'aws'
    }))
  )};

  var activeFilter      = 'ALL';
  var activeTypeFilter  = 'ALL';
  var activeCloudFilter = 'ALL';
  var activeSearch      = '';
  var savingsSortDir    = null; // null | 'desc' | 'asc'

  ${isBoth ? `var cloudViews = ${JSON.stringify(cloudViews)};` : ''}

  // ── Doughnut chart (re-created whenever #service-section is swapped, since
  // swapping innerHTML replaces the <canvas> node) ───────────────────────────
  var doughnutChart = null;
  function renderChart(labels, counts, colors) {
    var canvas = document.getElementById('doughnut-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    if (doughnutChart) { doughnutChart.destroy(); doughnutChart = null; }
    doughnutChart = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{ data: counts, backgroundColor: colors, borderWidth: 2, borderColor: '#FFFFFF' }]
      },
      options: {
        responsive: true,
        cutout: '65%',
        plugins: {
          legend: { position: 'bottom', labels: { color:'#64748B', font:{ size:11 }, padding:14, boxWidth:12 } }
        }
      }
    });
  }
  renderChart(${JSON.stringify(chartLabels)}, ${JSON.stringify(chartCounts)}, ${JSON.stringify(chartColors)});

  // ── Severity-by-service bar chart (re-created whenever #service-section is
  // swapped, since swapping innerHTML replaces the <canvas> node) ────────────
  var severityChart = null;
  function renderSeverityChart(labels, high, med, low) {
    var canvas = document.getElementById('severity-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    if (severityChart) { severityChart.destroy(); severityChart = null; }
    severityChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          { label: 'High',   data: high, backgroundColor: '#DC2626' },
          { label: 'Medium', data: med,  backgroundColor: '#F97316' },
          { label: 'Low',    data: low,  backgroundColor: '#EAB308' }
        ]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        scales: { x: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }, y: { stacked: true } },
        plugins: {
          legend: { position: 'bottom', labels: { color:'#64748B', font:{ size:11 }, padding:14, boxWidth:12 } }
        }
      }
    });
  }
  renderSeverityChart(${JSON.stringify(serviceList)}, ${JSON.stringify(svcHigh)}, ${JSON.stringify(svcMed)}, ${JSON.stringify(svcLow)});

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
      bar.textContent = '';
    } else {
      bar.textContent = btn.dataset.desc || '';
      bar.classList.add('visible');
    }
    renderVisibility();
    updatePriorityCounts();
    // Idle Resources is where "which one is costing me the most" matters most —
    // land on it pre-sorted highest-cost-first instead of making the user find
    // and click the Savings header themselves.
    if (type === 'IDLE') applyCostSort('desc');
  }

  // High/Med/Low counts next to the priority buttons — scoped to whichever
  // type tab (Idle Resources, Security, ...) and cloud filter are active, so
  // they reflect what's actually in view instead of the grand total.
  function updatePriorityCounts() {
    var high = 0, med = 0, low = 0;
    allFindings.forEach(function(f) {
      var matchType  = activeTypeFilter  === 'ALL' || activeTypeFilter  === f.typegroup;
      var matchCloud = activeCloudFilter === 'ALL' || activeCloudFilter === f.provider;
      if (!matchType || !matchCloud) return;
      if (f.priority === 'HIGH') high++;
      else if (f.priority === 'MEDIUM') med++;
      else if (f.priority === 'LOW') low++;
    });
    var ch = document.getElementById('count-high');   if (ch) ch.textContent = high;
    var cm = document.getElementById('count-medium'); if (cm) cm.textContent = med;
    var cl = document.getElementById('count-low');    if (cl) cl.textContent = low;
  }

  // ── Priority & env filters ────────────────────────────────────────────────
  function applySearch(val) { activeSearch = val.toLowerCase().trim(); renderVisibility(); }

  function setPriorityFilter(filter, btn) {
    document.querySelectorAll('.priority-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeFilter = filter;
    renderVisibility();
  }

  // ── Cloud scope switch — swaps the summary bar, narrative, service
  // breakdown/chart, and type tabs to that cloud's data, giving the illusion
  // of a full page switch instead of just filtering the findings table ──────
  function applyCloudView(key) {
    if (typeof cloudViews === 'undefined' || !cloudViews[key]) return;
    var v = cloudViews[key];
    document.getElementById('summary-bar').innerHTML        = v.summaryBarHTML;
    document.getElementById('narrative-container').innerHTML = v.narrativeHTML;
    document.getElementById('service-section').innerHTML     = v.serviceSectionHTML;
    document.getElementById('type-tabs-container').innerHTML = v.tabsHTML;
    document.getElementById('findings-heading-count').textContent = v.findingsHeadingCountHTML;
    var ch = document.getElementById('count-high');   if (ch) ch.textContent = v.highCount;
    var cm = document.getElementById('count-medium'); if (cm) cm.textContent = v.mediumCount;
    var cl = document.getElementById('count-low');    if (cl) cl.textContent = v.lowCount;
    renderChart(v.chartLabels, v.chartCounts, v.chartColors);
    renderSeverityChart(v.severityLabels, v.severityHigh, v.severityMed, v.severityLow);
    activeTypeFilter = 'ALL';
    var bar = document.getElementById('type-desc-bar');
    if (bar) { bar.classList.remove('visible'); bar.textContent = ''; }
  }

  function animateSwap(el, updateFn) {
    if (!el) { updateFn(); return; }
    el.classList.remove('view-fade-in');
    el.classList.add('view-fade-out');
    setTimeout(function() {
      updateFn();
      el.classList.remove('view-fade-out');
      el.classList.add('view-fade-in');
      setTimeout(function() { el.classList.remove('view-fade-in'); }, 250);
    }, 160);
  }

  function setCloudFilter(cloud, btn) {
    document.querySelectorAll('.cloud-toggle-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeCloudFilter = cloud;
    animateSwap(document.getElementById('main-content'), function() {
      applyCloudView(cloud === 'ALL' ? 'all' : cloud);
      renderVisibility();
    });
  }

  function resetFilters() {
    var cloudChanged = activeCloudFilter !== 'ALL';
    activeFilter = 'ALL'; activeTypeFilter = 'ALL'; activeCloudFilter = 'ALL'; activeSearch = '';
    document.getElementById('search-input').value = '';
    document.querySelectorAll('.priority-btn').forEach(function(b) { b.classList.remove('active'); });
    var allPri = document.querySelector('.priority-btn[data-filter="ALL"]');
    if (allPri) allPri.classList.add('active');
    document.querySelectorAll('.cloud-toggle-btn').forEach(function(b) { b.classList.remove('active'); });
    var allCloud = document.querySelector('.cloud-toggle-btn[data-filter="ALL"]');
    if (allCloud) allCloud.classList.add('active');
    function afterScope() {
      document.querySelectorAll('.type-tab').forEach(function(b) { b.classList.remove('active'); });
      var allTab = document.querySelector('.type-tab[data-type="ALL"]');
      if (allTab) allTab.classList.add('active');
      var bar = document.getElementById('type-desc-bar');
      if (bar) { bar.classList.remove('visible'); bar.textContent = ''; }
      renderVisibility();
      updatePriorityCounts();
    }
    if (cloudChanged) {
      animateSwap(document.getElementById('main-content'), function() { applyCloudView('all'); afterScope(); });
    } else {
      afterScope();
    }
  }

  // ── Sort by cost (Savings column) — reorders the finding/detail row pairs
  // in the DOM. Works within whatever tab/filter is active (e.g. the Idle
  // Resources tab), since filtering only toggles visibility, not row order.
  function applyCostSort(dir) {
    var tbody = document.querySelector('#findings-table tbody');
    var th    = document.getElementById('th-savings');
    var arrow = document.getElementById('sort-arrow-savings');
    if (!tbody) return;
    savingsSortDir = dir;
    var pairs = allFindings.map(function(f) {
      return { savings: f.savings, frow: document.getElementById('frow-' + f.idx), drow: document.getElementById('detail-' + f.idx) };
    }).filter(function(p) { return p.frow && p.drow; });
    pairs.sort(function(a, b) {
      return savingsSortDir === 'desc' ? (b.savings - a.savings) : (a.savings - b.savings);
    });
    pairs.forEach(function(p) { tbody.appendChild(p.frow); tbody.appendChild(p.drow); });
    if (th) th.classList.add('sorted');
    if (arrow) arrow.textContent = savingsSortDir === 'desc' ? '▼' : '▲';
  }
  function sortBySavings() {
    applyCostSort(savingsSortDir === 'desc' ? 'asc' : 'desc');
  }

  // ── Render visibility + result count ─────────────────────────────────────
  function renderVisibility() {
    var visibleCount = 0, scopeTotal = 0;
    allFindings.forEach(function(f) {
      var frow = document.getElementById('frow-'   + f.idx);
      var drow = document.getElementById('detail-' + f.idx);
      var chev = document.getElementById('chev-'   + f.idx);
      var matchPriority = activeFilter      === 'ALL' || activeFilter      === f.priority;
      var matchSearch   = !activeSearch             || f.resourceName.toLowerCase().includes(activeSearch);
      var matchType     = activeTypeFilter  === 'ALL' || activeTypeFilter  === f.typegroup;
      var matchCloud    = activeCloudFilter === 'ALL' || activeCloudFilter === f.provider;
      var visible = matchPriority && matchSearch && matchType && matchCloud;
      if (matchCloud) scopeTotal++;
      if (visible) visibleCount++;
      if (frow) frow.classList.toggle('filtered', !visible);
      if (drow) { drow.classList.toggle('filtered', !visible); drow.classList.remove('open'); }
      if (chev) chev.textContent = '▸';
    });
    var countEl = document.getElementById('results-count');
    if (countEl) countEl.innerHTML = 'Showing <strong>' + visibleCount + '</strong> of <strong>' + scopeTotal + '</strong>';
    var noRes = document.getElementById('no-results');
    var tbl   = document.getElementById('findings-table');
    if (noRes) noRes.style.display = (scopeTotal > 0 && visibleCount === 0) ? 'flex' : 'none';
    if (tbl)   tbl.style.display   = visibleCount === 0 ? 'none' : '';
  }

  // ── Copy commands ─────────────────────────────────────────────────────────
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

  // ── Fix script download ───────────────────────────────────────────────────
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

  // ── Animated counters ─────────────────────────────────────────────────────
  (function() {
    var els = document.querySelectorAll('.sum-val[data-count]');
    els.forEach(function(el) {
      var target   = parseFloat(el.dataset.count) || 0;
      var prefix   = el.dataset.prefix || '';
      var suffix   = el.dataset.suffix || '';
      var duration = 900;
      var startTime = null;
      function step(ts) {
        if (!startTime) startTime = ts;
        var progress = Math.min((ts - startTime) / duration, 1);
        var eased    = 1 - Math.pow(1 - progress, 3);
        var current  = Math.round(eased * target);
        el.textContent = prefix + current.toLocaleString() + suffix;
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = prefix + target.toLocaleString() + suffix;
      }
      requestAnimationFrame(step);
    });
  })();

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
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const METRIC_LABELS = {
  invocations: 'Invocations',
  avgDurationMs: 'Avg Duration',
  errors: 'Errors',
  throttles: 'Throttles',
  configuredMemMB: 'Configured Memory',
  avgMemUsedMB: 'Avg Memory Used',
  peakMemUsedMB: 'Peak Memory Used',
  memUtilisationPct: 'Memory Utilisation',
  avgColdStartMs: 'Avg Cold Start',
  lastModifiedDaysAgo: 'Last Modified',
  runtime: 'Runtime',
  recommendedRuntime: 'Recommended Runtime',
  trafficDropPct: 'Traffic Drop',
  provisionedRCU: 'Provisioned RCU',
  provisionedWCU: 'Provisioned WCU',
  consumedRCU: 'Consumed RCU',
  consumedWCU: 'Consumed WCU',
  rcuUtilisationPct: 'RCU Utilisation',
  wcuUtilisationPct: 'WCU Utilisation',
  messagesPublished: 'Messages Published',
  messagesSent: 'Messages Sent',
  messagesReceived: 'Messages Received',
  currentlyVisible: 'Visible Messages',
  oldestMessageAge: 'Oldest Message Age',
  storedBytes: 'Stored',
  retentionDays: 'Retention',
  incomingEventsOverWindow: 'Incoming Events',
  incomingEventsPerDay: 'Avg Events/Day',
  objectCount: 'Object Count',
  ruleType: 'Rule Type',
  schedule: 'Schedule'
};

function fmtKey(k) {
  if (METRIC_LABELS[k]) return METRIC_LABELS[k];
  const m1 = k.match(/^invocationsPrev(\d+)d$/);
  if (m1) return `Invocations (prev ${m1[1]}d)`;
  const m2 = k.match(/^invocationsCurr(\d+)d$/);
  if (m2) return `Invocations (last ${m2[1]}d)`;
  return k;
}

function fmtVal(k, v) {
  if (k.endsWith('Pct') || k === 'trafficDropPct') return v + '%';
  if (k.endsWith('MB')) return v + ' MB';
  if (k === 'avgDurationMs' || k === 'avgColdStartMs') return v + ' ms';
  if (k === 'lastModifiedDaysAgo') return v + ' days ago';
  if (k === 'storedBytes') return fmtBytes(v);
  if (typeof v === 'number') return v.toLocaleString();
  return String(v);
}

function fmtBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024,
    sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = { generateReport };
