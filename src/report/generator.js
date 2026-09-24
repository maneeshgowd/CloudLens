'use strict';

function generateReport({ findings, summary, provider, days }) {
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
    'Security Groups':         '#DC2626', 'IAM':                     '#DD344C',
    'Azure Functions':         '#0078d4', 'Virtual Machines':        '#0078d4',
    'App Service':             '#0078d4', 'Blob Storage':            '#0072c6',
    'Cosmos DB':               '#0072c6', 'Service Bus':             '#0078d4',
    'Log Analytics':           '#0078d4', 'Azure Monitor':           '#0072c6',
  };
  const serviceIconLabel = {
    'Lambda':'λ', 'Provisioned Concurrency':'PC', 'DynamoDB':'DB', 'SNS':'SNS',
    'S3':'S3', 'EventBridge':'EB', 'Log Groups':'CW', 'SQS':'SQS', 'ECS':'ECS',
    'NAT Gateway':'NAT', 'API Gateway':'API', 'Secrets Manager':'SM', 'CloudFront':'CF',
    'MSK':'MSK', 'Security Groups':'SG', 'IAM':'IAM',
    'Azure Functions':'fn', 'Virtual Machines':'VM', 'App Service':'APP',
    'Blob Storage':'BLOB', 'Cosmos DB':'DB', 'Service Bus':'SB', 'Log Analytics':'LA', 'Azure Monitor':'MON',
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
    THROTTLED:          'IDLE',
    DLQ_MESSAGES:       'QUEUE',
    STALE_MESSAGES:     'QUEUE',
    MSK_DURABILITY_RISK:'QUEUE',
    MISSING_TAGS:       'GOVERNANCE',
    NO_RETENTION:       'GOVERNANCE',
    S3_PUBLIC_ACCESS:   'SECURITY',
    SG_OPEN_INGRESS:    'SECURITY',
    IAM_KEY_STALE:      'SECURITY',
    SECRET_NO_ROTATION: 'SECURITY',
  };
  function typeGroupOf(t) { return TYPE_TO_GROUP[t] || 'OTHER'; }

  const groupCounts = {};
  for (const f of findings) {
    const g = typeGroupOf(f.type);
    groupCounts[g] = (groupCounts[g] || 0) + 1;
  }

  const TAB_DEFS = [
    { type:'ALL',                icon:'≡',  label:'All',              desc:'',          color:'#2563EB' },
    { type:'PIPELINE_SILENT',    icon:'⏸',  label:'Silent Pipelines', desc:'Scheduled rules (EventBridge) are active and running, but zero events are reaching the target Lambda function. The automated pipeline is broken — and no alarm has fired to alert you.', color:'#EA580C' },
    { type:'DEPRECATED_RUNTIME', icon:'⚠',  label:'EOL Runtimes',     desc:'Functions running software versions (Node.js, Python, etc.) that AWS no longer patches. Any security vulnerability published after the end-of-life date remains permanently unpatched in production.', color:'#DC2626' },
    { type:'ABANDONED',          icon:'◌',  label:'Dead Code',        desc:'Functions deployed with zero invocations for an extended period — dead code still holding live IAM (access) permissions and accumulating unpatched vulnerabilities as the runtime ages.', color:'#DC2626' },
    { type:'ANOMALY_DROP',       icon:'↘',  label:'Traffic Anomalies',desc:'Functions showing a sharp drop in invocations vs the prior period — typically a broken upstream caller or a silent deployment failure that no alarm caught.', color:'#DC2626' },
    { type:'HIGH_ERROR_RATE',    icon:'✕',  label:'High Error Rate',  desc:'Functions where a significant percentage of invocations are failing. Compute cost is being spent on failed work that produces no value for users or downstream systems.', color:'#DC2626' },
    { type:'IDLE',               icon:'□',  label:'Idle Resources',   desc:'Resources consuming allocated capacity (and cost) with minimal or zero actual usage — over-allocated memory, idle provisioned concurrency, underutilised clusters.', color:'#EA580C' },
    { type:'QUEUE',              icon:'▣',  label:'Queue Issues',     desc:'Message queues (SQS, dead-letter queues) with stuck or unprocessed messages — indicating processing failures or backlog accumulation that may affect downstream consumers.', color:'#EA580C' },
    { type:'SECURITY',           icon:'⚑',  label:'Security',         desc:'Critical security misconfigurations — publicly accessible S3 buckets, security groups open to the internet, IAM credentials overdue for rotation, and secrets with no automatic rotation. Each finding here represents an open attack vector.', color:'#DC2626' },
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

  const TYPE_EXPLAIN = {
    PIPELINE_SILENT:     'This EventBridge rule is enabled and scheduled to run, but zero events are arriving at its target Lambda function. The automated pipeline is completely broken — and no CloudWatch alarm has fired to alert you. This failure is only visible when EventBridge and Lambda are analysed together.',
    DEPRECATED_RUNTIME:  'AWS has stopped releasing security patches for this software version. Any CVE (security vulnerability) published after the end-of-life date is permanently unpatched in this function. These appear as open findings in security audits and can block compliance certifications.',
    ABANDONED:           'Zero invocations for an extended period with no recent code changes. This is dead code — but it still holds live IAM permissions and will accumulate unpatched vulnerabilities as its runtime ages. Every deployed Lambda is an attack surface, active or not.',
    ANOMALY_DROP:        "This function's invocations dropped sharply compared to the prior period. This is typically caused by a broken upstream caller that stopped sending requests, or a silent deployment failure that reduced traffic without triggering any monitoring alert.",
    HIGH_ERROR_RATE:     'More than 20% of invocations are failing (throwing errors or timing out). Compute cost is being spent on failed work, and any services or users depending on this function may be receiving errors.',
    IDLE:                'This resource is consuming allocated capacity (and cost) with minimal or zero actual usage. Rightsizing or removing it recovers cost without impacting active workloads.',
    PC_IDLE:             'Provisioned Concurrency keeps instances warm to eliminate cold starts — but this function has had zero invocations. You are paying for warm instances that are never invoked.',
    PC_OVER_PROVISIONED: 'Provisioned Concurrency is set higher than the function\'s peak utilisation. Reducing the setting saves cost without impacting cold-start performance.',
    DLQ_MESSAGES:        'Messages have accumulated in the dead-letter queue (DLQ) — the primary processor is failing to handle them. These failed messages have not been processed or reviewed.',
    STALE_MESSAGES:      'Messages in this queue are older than expected, suggesting the consumer stopped processing or the queue is backed up with unhandled messages.',
    MISSING_TAGS:        'This resource is missing recommended tags (Environment, Team/Owner). Tags are required for cost attribution, security policies, and automated governance across the account.',
    NO_RETENTION:        'This CloudWatch log group has no retention policy — logs are kept indefinitely, accumulating storage costs and potentially complicating data-retention compliance.',
    THROTTLED:           'This function is being throttled — AWS is rejecting invocations because concurrent execution limits are reached. Affected calls may fail silently without a retry mechanism.',
    OVER_ALLOCATED:      'Configured memory is far above actual peak usage. AWS charges for configured memory, not used memory — reducing the setting directly reduces compute cost per invocation.',
    MSK_OFFLINE:         'This Kafka (MSK) cluster has offline partitions — topic partitions are unavailable, meaning producers cannot write and consumers cannot read the affected data.',
    MSK_DURABILITY_RISK: 'The replication factor is below the recommended minimum. A single broker failure could result in data loss on this cluster.',
    MSK_DISK_CRITICAL:   'Disk usage on this MSK cluster is critically high. When disks fill completely, Kafka brokers can fail and data can be lost.',
    MSK_IDLE:            'This Kafka (MSK) cluster has had minimal or zero message traffic. MSK is one of the more expensive AWS services — an idle cluster is significant cost waste.',
    MSK_UNDERUTILIZED:   'This MSK cluster has low throughput relative to its provisioned broker capacity. Consider scaling down to a smaller broker type to reduce cost.',
    S3_PUBLIC_ACCESS:    'This S3 bucket does not have all four Block Public Access settings enabled. Depending on bucket ACLs and bucket policies, this bucket may be readable or writable by anyone on the internet — including its contents, which could contain sensitive data.',
    SG_OPEN_INGRESS:     'This EC2 security group has an ingress rule that allows connections from any IP address on the internet (0.0.0.0/0). The exposed port gives any external actor a direct network path to your resources — a common entry point for automated scanning, credential brute-forcing, and exploitation.',
    IAM_KEY_STALE:       'This IAM access key has not been rotated since it was created. Long-lived credentials are a primary vector for account compromise — if the key was ever exposed in code, logs, or a third-party tool, it remains valid until explicitly rotated. CIS AWS Benchmark 1.14 requires rotation every 90 days.',
    SECRET_NO_ROTATION:  'This secret is being actively used but has automatic rotation disabled. A static credential that never rotates remains valid indefinitely — if it is ever leaked, there is no automatic recovery. AWS Secrets Manager supports fully-managed rotation for many secret types including RDS, Redshift, and custom Lambda-based rotators.',
  };

  const totalSavings  = findings.reduce((sum, f) => sum + (f.estimatedMonthlySavings || 0), 0);
  const totalSpend    = costCtx?.totalEstimatedCost ?? 0;
  const serviceCount  = Object.keys(byService).length;

  // ── Narrative ──────────────────────────────────────────────────────────────
  const narrativeParts = [];
  if (deprecatedCount > 0) {
    const eolRuntimes = [...new Set(findings.filter(f => f.type === 'DEPRECATED_RUNTIME').map(f => f.metrics?.runtime).filter(Boolean))];
    const runtimeList = eolRuntimes.length > 0 ? ` (${eolRuntimes.slice(0, 3).join(', ')})` : '';
    narrativeParts.push(
      `<strong>${deprecatedCount} function${deprecatedCount > 1 ? 's' : ''} on end-of-life runtimes${runtimeList}</strong> — AWS has stopped shipping patches. CVEs published since the EOL date are permanently unpatched.`
    );
  }
  if (pipelineCount > 0) {
    narrativeParts.push(
      `<strong>${pipelineCount} automated pipeline${pipelineCount > 1 ? 's' : ''} completely silent</strong> — EventBridge rule${pipelineCount > 1 ? 's' : ''} enabled and scheduled but zero events reaching target function${pipelineCount > 1 ? 's' : ''}. No alarm has fired.`
    );
  }
  if (anomalyCount > 0) {
    narrativeParts.push(
      `<strong>${anomalyCount} function${anomalyCount > 1 ? 's' : ''} with sharp traffic drop</strong> — likely a broken upstream caller or silent deployment failure.`
    );
  }
  const abandonedFindings = findings.filter(f => f.type === 'ABANDONED')
    .sort((a, b) => (b.metrics?.lastModifiedDaysAgo ?? 0) - (a.metrics?.lastModifiedDaysAgo ?? 0));
  if (abandonedFindings.length > 0) {
    const oldest = abandonedFindings[0];
    const age    = oldest.metrics?.lastModifiedDaysAgo;
    const ageStr = age != null ? (age >= 365 ? `~${(age / 365).toFixed(1)} years` : `${age} days`) : 'an extended period';
    narrativeParts.push(
      `<strong>${abandonedFindings.length} function${abandonedFindings.length > 1 ? 's' : ''} deployed with zero activity</strong> — dead code holding live IAM permissions. Oldest: <code>${escapeHtml(oldest.resourceName)}</code>, unmodified for ${ageStr}.`
    );
  }

  const narrativeHTML = narrativeParts.length > 0
    ? `<div class="narrative-bar">${narrativeParts.map(p => `<div class="narrative-item">${p}</div>`).join('')}</div>`
    : '';

  // ── Service breakdown ──────────────────────────────────────────────────────
  const serviceBreakdownHTML = Object.entries(byService).sort((a, b) => b[1] - a[1]).map(([svc, cnt]) => {
    const bg  = serviceColors[svc] || '#64748b';
    const lbl = serviceIconLabel[svc] || svc[0];
    return `<div class="service-tile">
      <div class="service-icon-lg" style="background:${bg}">${lbl}</div>
      <div class="svc-count">${cnt}</div>
      <div class="svc-name">${svc}</div>
    </div>`;
  }).join('');

  // ── Insights chart data ────────────────────────────────────────────────────
  const serviceList = Object.keys(byService).sort((a, b) => byService[b] - byService[a]).slice(0, 8);
  const svcHigh = serviceList.map(s => findings.filter(f => f.service === s && f.priority === 'HIGH').length);
  const svcMed  = serviceList.map(s => findings.filter(f => f.service === s && f.priority === 'MEDIUM').length);
  const svcLow  = serviceList.map(s => findings.filter(f => f.service === s && f.priority === 'LOW').length);

  // ── Finding rows ──────────────────────────────────────────────────────────
  function typeLabel(type) {
    const labels = {
      ABANDONED:'Dead Code', DEPRECATED_RUNTIME:'EOL Runtime', PIPELINE_SILENT:'Silent Pipeline',
      ANOMALY_DROP:'Traffic Anomaly', HIGH_ERROR_RATE:'High Error Rate', IDLE:'Idle',
      OVER_ALLOCATED:'Over-allocated', THROTTLED:'Throttled', DLQ_MESSAGES:'Dead Letter Queue',
      STALE_MESSAGES:'Stale Messages', PC_IDLE:'Idle (Prov. Concurrency)', PC_OVER_PROVISIONED:'Over-provisioned (PC)',
      MSK_IDLE:'Idle Cluster', MSK_UNDERUTILIZED:'Low Utilisation', MSK_OFFLINE:'Offline Partitions',
      MSK_DURABILITY_RISK:'Durability Risk', MSK_DISK_CRITICAL:'Disk Critical',
      MISSING_TAGS:'Missing Tags', NO_RETENTION:'No Log Retention',
      S3_PUBLIC_ACCESS:'Public Access', SG_OPEN_INGRESS:'Open to Internet',
      IAM_KEY_STALE:'Stale Key', SECRET_NO_ROTATION:'No Rotation',
    };
    return labels[type] || type.replace(/_/g, ' ');
  }

  const findingsRowsHTML = findings.map((f, idx) => {
    const bg    = serviceColors[f.service] || '#64748b';
    const lbl   = serviceIconLabel[f.service] || f.service[0];
    const typeG = typeGroupOf(f.type);
    const metricsHTML = Object.entries(f.metrics || {})
      .map(([k, v]) => `<div class="metric-row"><span class="metric-label">${fmtKey(k)}</span><span class="metric-value">${fmtVal(k, v)}</span></div>`)
      .join('');
    const s = f.estimatedMonthlySavings;
    const savingsHTML = s > 0
      ? `<span class="savings-badge">${s < 0.01 ? '< $0.01' : '~$' + s.toFixed(2)}/mo</span>`
      : '<span class="savings-nil">—</span>';
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
    .header-meta { font-size: 0.78rem; color: var(--muted); display: flex; gap: 1.25rem; }
    .header-meta strong { color: var(--text-2); font-weight: 600; }

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
    .table-wrap { background: var(--surface); border: 1px solid var(--border); border-top: none; border-radius: 0 0 var(--radius) var(--radius); overflow: hidden; box-shadow: var(--shadow); }
    table { width: 100%; border-collapse: collapse; }
    thead th { background: var(--surface-2); padding: 0.65rem 1rem; text-align: left; font-weight: 700; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; border-bottom: 1px solid var(--border); }
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
  </style>
</head>
<body>

<div class="header">
  <div class="header-brand">
    <div class="header-logo">Cloud<span>Lens</span></div>
    <span class="header-badge">${provider.toUpperCase()}</span>
    <span class="header-badge">Last ${days} days</span>
  </div>
  <div class="header-meta">
    <span>Generated <strong>${now.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' })}</strong></span>
    <span><strong>${now.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' })} UTC</strong></span>
  </div>
</div>

<div class="container">

  <!-- Summary numbers -->
  <div class="summary-bar">
    <div class="sum-item"><div class="sum-val" data-count="${scanned}">${scanned.toLocaleString()}</div><div class="sum-lbl">Resources Scanned</div></div>
    <div class="sum-item"><div class="sum-val" data-count="${findings.length}">${findings.length}</div><div class="sum-lbl">Total Findings</div></div>
    <div class="sum-item high"><div class="sum-val" data-count="${highCount}">${highCount}</div><div class="sum-lbl">High</div></div>
    <div class="sum-item medium"><div class="sum-val" data-count="${mediumCount}">${mediumCount}</div><div class="sum-lbl">Medium</div></div>
    <div class="sum-item low"><div class="sum-val" data-count="${lowCount}">${lowCount}</div><div class="sum-lbl">Low</div></div>
    ${totalSavings > 0 ? `<div class="sum-item savings"><div class="sum-val" data-count="${totalSavings.toFixed(0)}" data-prefix="$" data-suffix="/mo">$${totalSavings.toFixed(0)}/mo</div><div class="sum-lbl">Recoverable</div></div>` : ''}
    ${totalSpend   > 0 ? `<div class="sum-item spend"><div class="sum-val" data-count="${totalSpend.toFixed(0)}" data-prefix="$" data-suffix="/mo">$${totalSpend.toFixed(0)}/mo</div><div class="sum-lbl">Est. Spend</div></div>` : ''}
  </div>

  ${narrativeHTML}

  <!-- Service breakdown -->
  ${Object.keys(byService).length > 0 ? `
  <div class="section-heading">Findings by Service <span class="sh-sub">${serviceCount} service${serviceCount !== 1 ? 's' : ''} affected</span></div>
  <div class="services-row">
    <div class="service-tiles">${serviceBreakdownHTML}</div>
  </div>` : ''}

  <!-- Insights charts -->
  ${serviceList.length > 0 ? `
  <div class="insight-card" style="margin-bottom:1.75rem">
    <div class="insight-title">Findings by Service &amp; Severity</div>
    <div class="insight-subtitle">Breakdown of HIGH / MEDIUM / LOW findings per service</div>
    <canvas id="severity-chart"></canvas>
  </div>` : ''}

  <!-- Finding browser -->
  <div class="findings-heading">Findings <span class="fh-count">${findings.length} total · ${highCount} high · ${mediumCount} medium · ${lowCount} low</span></div>

  <div class="findings-header">
    <div class="type-tabs">${tabsHTML}</div>
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
      <button class="filter-btn priority-btn high"   data-filter="HIGH"   onclick="setPriorityFilter('HIGH',this)">High (${highCount})</button>
      <button class="filter-btn priority-btn medium" data-filter="MEDIUM" onclick="setPriorityFilter('MEDIUM',this)">Med (${mediumCount})</button>
      <button class="filter-btn priority-btn low"    data-filter="LOW"    onclick="setPriorityFilter('LOW',this)">Low (${lowCount})</button>
    </div>
    <span class="results-count" id="results-count">Showing <strong>${findings.length}</strong> of <strong>${findings.length}</strong></span>
    <button class="action-btn"       onclick="exportCSV()">↓ CSV</button>
    <button class="action-btn green" onclick="downloadFixScript()">↓ Fix Script</button>
    <button class="action-btn"       onclick="window.print()">⎙ Print / PDF</button>
  </div>

  <div class="table-wrap">
    ${findings.length === 0
      ? '<div class="no-findings">No findings — infrastructure looks healthy for this window.</div>'
      : `<table id="findings-table">
          <thead><tr>
            <th>Priority</th><th>Service</th><th>Resource</th>
            <th>Finding Type</th><th>Details</th><th>Savings</th><th></th>
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

<footer>CloudLens — read-only scan, no changes made to any resource &nbsp;·&nbsp; ${now.toUTCString()}</footer>

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
  var activeTypeFilter = 'ALL';
  var activeSearch     = '';

  // ── Severity by service chart ─────────────────────────────────────────────
  (function() {
    var canvas = document.getElementById('severity-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ${JSON.stringify(serviceList)},
        datasets: [
          { label: 'HIGH',   data: ${JSON.stringify(svcHigh)}, backgroundColor: 'rgba(220,38,38,0.85)',  borderRadius: 3 },
          { label: 'MEDIUM', data: ${JSON.stringify(svcMed)},  backgroundColor: 'rgba(234,88,12,0.85)',  borderRadius: 3 },
          { label: 'LOW',    data: ${JSON.stringify(svcLow)},  backgroundColor: 'rgba(217,119,6,0.75)',  borderRadius: 3 },
        ]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: { position: 'bottom', labels: { color:'#64748B', font:{ size:11 }, padding:14, boxWidth:12 } }
        },
        scales: {
          x: { stacked: true, grid: { color:'#F1F5F9' }, ticks: { color:'#64748B', font:{ size:11 } } },
          y: { stacked: true, grid: { display:false },   ticks: { color:'#334155', font:{ size:11 } } }
        }
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
      bar.textContent = '';
    } else {
      bar.textContent = btn.dataset.desc || '';
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

  function resetFilters() {
    activeFilter = 'ALL'; activeTypeFilter = 'ALL'; activeSearch = '';
    document.getElementById('search-input').value = '';
    document.querySelectorAll('.type-tab').forEach(function(b) { b.classList.remove('active'); });
    var allTab = document.querySelector('.type-tab[data-type="ALL"]');
    if (allTab) allTab.classList.add('active');
    document.getElementById('type-desc-bar').classList.remove('visible');
    document.getElementById('type-desc-bar').textContent = '';
    document.querySelectorAll('.priority-btn').forEach(function(b) { b.classList.remove('active'); });
    var allPri = document.querySelector('.priority-btn[data-filter="ALL"]');
    if (allPri) allPri.classList.add('active');
    renderVisibility();
  }

  // ── Render visibility + result count ─────────────────────────────────────
  function renderVisibility() {
    var visibleCount = 0;
    allFindings.forEach(function(f) {
      var frow = document.getElementById('frow-'   + f.idx);
      var drow = document.getElementById('detail-' + f.idx);
      var chev = document.getElementById('chev-'   + f.idx);
      var matchPriority = activeFilter     === 'ALL' || activeFilter     === f.priority;
      var matchSearch   = !activeSearch            || f.resourceName.toLowerCase().includes(activeSearch);
      var matchType     = activeTypeFilter === 'ALL' || activeTypeFilter === f.typegroup;
      var visible = matchPriority && matchSearch && matchType;
      if (visible) visibleCount++;
      if (frow) frow.classList.toggle('filtered', !visible);
      if (drow) { drow.classList.toggle('filtered', !visible); drow.classList.remove('open'); }
      if (chev) chev.textContent = '▸';
    });
    var countEl = document.getElementById('results-count');
    if (countEl) countEl.innerHTML = 'Showing <strong>' + visibleCount + '</strong> of <strong>' + allFindings.length + '</strong>';
    var noRes = document.getElementById('no-results');
    var tbl   = document.getElementById('findings-table');
    if (noRes) noRes.style.display = (allFindings.length > 0 && visibleCount === 0) ? 'flex' : 'none';
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
