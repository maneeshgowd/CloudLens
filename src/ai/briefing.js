'use strict';

// Generates a plain-English executive risk briefing using Claude.
// Called after the scan completes. Returns null if no API key is set
// or if the call fails — the report renders fine without it.

const CLAUDE_MODEL = 'claude-haiku-4-5'; // fast, cheap — change to claude-sonnet-4-6 for richer output

async function generateAIBriefing(findings, { provider, days, scanned }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;
  if (findings.length === 0) return null;

  const highCount   = findings.filter(f => f.priority === 'HIGH').length;
  const mediumCount = findings.filter(f => f.priority === 'MEDIUM').length;

  // Group findings by type for context
  const byType = {};
  for (const f of findings) {
    if (!byType[f.type]) byType[f.type] = [];
    byType[f.type].push(f);
  }

  const contextLines = [];

  const pipelines = byType['PIPELINE_SILENT'] || [];
  if (pipelines.length > 0) {
    const names = pipelines.slice(0, 2).map(f => f.resourceName).join(', ');
    contextLines.push(
      `${pipelines.length} automated pipeline(s) completely silent — EventBridge rules are enabled ` +
      `and scheduled but zero events are reaching their target Lambda functions. No CloudWatch alarm ` +
      `has fired. Examples: ${names}`
    );
  }

  const deprecated = byType['DEPRECATED_RUNTIME'] || [];
  if (deprecated.length > 0) {
    const runtimes = [...new Set(deprecated.map(f => f.metrics?.runtime).filter(Boolean))];
    const eol  = deprecated.filter(f => {
      const info = (f.details || '').toLowerCase();
      return info.includes('eol') || info.includes('end-of-life');
    });
    contextLines.push(
      `${deprecated.length} Lambda function(s) running EOL runtimes: ${runtimes.slice(0, 4).join(', ')}. ` +
      `AWS has stopped shipping security patches — any CVE published after EOL date is permanently ` +
      `unpatched in production.${eol.length > 0 ? ` ${eol.length} are fully EOL (not just deprecated).` : ''}`
    );
  }

  const abandoned = byType['ABANDONED'] || [];
  if (abandoned.length > 0) {
    const oldest = abandoned.slice().sort(
      (a, b) => (b.metrics?.lastModifiedDaysAgo ?? 0) - (a.metrics?.lastModifiedDaysAgo ?? 0)
    )[0];
    const age = oldest.metrics?.lastModifiedDaysAgo;
    const ageStr = age != null
      ? (age >= 365 ? `~${(age / 365).toFixed(1)} years` : `${age} days`)
      : 'an extended period';
    contextLines.push(
      `${abandoned.length} Lambda function(s) deployed with zero invocations — dead code still holding ` +
      `live IAM permissions and accumulating CVEs as runtimes age. Oldest: ${oldest.resourceName}, ` +
      `unmodified for ${ageStr}.`
    );
  }

  const anomalies = byType['ANOMALY_DROP'] || [];
  if (anomalies.length > 0) {
    const worst = anomalies.slice().sort(
      (a, b) => (b.metrics?.trafficDropPct ?? 0) - (a.metrics?.trafficDropPct ?? 0)
    )[0];
    contextLines.push(
      `${anomalies.length} function(s) show a sharp traffic drop vs the prior period — likely a broken ` +
      `upstream dependency or silent deployment failure.` +
      (worst.metrics?.trafficDropPct ? ` Worst drop: ${worst.metrics.trafficDropPct}% on ${worst.resourceName}.` : '')
    );
  }

  const errors = byType['HIGH_ERROR_RATE'] || [];
  if (errors.length > 0) {
    contextLines.push(
      `${errors.length} function(s) have an error rate above 20% — compute cost is being spent on ` +
      `failed invocations with no useful work done.`
    );
  }

  if (contextLines.length === 0) return null;

  const prompt =
    `You are a cloud security and operations expert writing a concise executive risk briefing ` +
    `for engineering leadership.\n\n` +
    `Scan context:\n` +
    `- Cloud provider: ${provider.toUpperCase()}\n` +
    `- Resources scanned: ${scanned}\n` +
    `- Analysis window: last ${days} days\n` +
    `- Total findings: ${findings.length} (${highCount} HIGH, ${mediumCount} MEDIUM)\n\n` +
    `Key findings:\n` +
    contextLines.map(l => `- ${l}`).join('\n') +
    `\n\nWrite a 3–4 sentence executive briefing in plain business English. ` +
    `Rules: specific numbers only (no vague language), no bullet points, no markdown, ` +
    `no technical jargon, do not mention the tool name. ` +
    `Tone: a senior engineer briefing a CTO — direct, factual, urgent where warranted.`;

  try {
    const Anthropic = require('@anthropic-ai/sdk');
    const client = new Anthropic.default({ apiKey });
    const msg = await client.messages.create({
      model:      CLAUDE_MODEL,
      max_tokens: 350,
      messages:   [{ role: 'user', content: prompt }],
    });
    return msg.content[0]?.text?.trim() || null;
  } catch (err) {
    if (process.env.DEBUG) console.error('  [AI briefing] failed:', err.message);
    return null;
  }
}

module.exports = { generateAIBriefing };
