'use strict';

const { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } = require('@aws-sdk/client-sns');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { thresholds, managedPrefixes, snsAnalysisLimit } = require('../config');

async function listAllTopics(client) {
  const topics = [];
  let nextToken;
  do {
    const res = await client.send(new ListTopicsCommand({ NextToken: nextToken }));
    topics.push(...(res.Topics || []));
    nextToken = res.NextToken;
  } while (nextToken);
  return topics;
}

// Fetch subscription counts for a list of topic ARNs (20 concurrent).
// Returns a Map<arn, count> where count = confirmed + pending subscriptions.
// Returns -1 for any topic that fails the attributes call.
async function batchGetSubscriptionCounts(client, arns, concurrency = 20) {
  const counts = new Map();
  for (let i = 0; i < arns.length; i += concurrency) {
    const batch = arns.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(arn =>
        client.send(new GetTopicAttributesCommand({ TopicArn: arn }))
          .then(r => {
            const a   = r.Attributes || {};
            const cnt = parseInt(a.SubscriptionsConfirmed || '0', 10)
                      + parseInt(a.SubscriptionsPending   || '0', 10);
            return { arn, cnt };
          })
          .catch(() => ({ arn, cnt: -1 }))
      )
    );
    for (const { arn, cnt } of results) counts.set(arn, cnt);
  }
  return counts;
}

async function analyzeSNS({ region, startTime, endTime, days, filter }) {
  const snsClient = new SNSClient({ region });
  const cwClient  = new CloudWatchClient({ region });

  process.stdout.write('  SNS: listing topics... ');
  const allTopics = await listAllTopics(snsClient);
  let topics = (filter
    ? allTopics.filter(t => t.TopicArn.split(':').pop().toLowerCase().includes(filter.toLowerCase()))
    : allTopics
  ).filter(t => !managedPrefixes.some(p => t.TopicArn.split(':').pop().toLowerCase().startsWith(p)));

  const totalFound = topics.length;
  const capped     = totalFound > snsAnalysisLimit;

  if (capped) {
    topics = topics.slice(0, snsAnalysisLimit);
    console.log(`${totalFound} found — analysing first ${snsAnalysisLimit} (use --filter to target specific topics)`);
  } else {
    console.log(`${totalFound} found${filter ? ` matching "${filter}"` : ''}`);
  }

  if (topics.length === 0) return { findings: [], resourcesScanned: totalFound };

  const topicMeta = topics.map(t => ({
    arn:  t.TopicArn,
    name: t.TopicArn.split(':').pop(),
  }));

  // ── CloudWatch: messages published ───────────────────────────────────────
  const querySpecs = topicMeta.map((t, i) => ({
    id:         metricId('sn', i, 'msg'),
    namespace:  'AWS/SNS',
    metricName: 'NumberOfMessagesPublished',
    dimensions: [{ Name: 'TopicName', Value: t.name }],
    stat:       'Sum',
  }));

  process.stdout.write(`  SNS: fetching message metrics for ${topics.length} topics... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  // ── Subscription counts — only for zero-message topics ───────────────────
  // Distinguishes truly orphaned (0 subs + 0 messages) from event-driven quiet topics.
  const zeroMessageArns = topicMeta
    .filter((_, i) => (cwMetrics[metricId('sn', i, 'msg')]?.sum ?? 0) === 0)
    .map(t => t.arn);

  let subCounts = new Map();
  if (zeroMessageArns.length > 0) {
    process.stdout.write(`  SNS: checking subscriptions for ${zeroMessageArns.length} inactive topics... `);
    subCounts = await batchGetSubscriptionCounts(snsClient, zeroMessageArns);
    console.log('done');
  }

  const findings = [];

  topicMeta.forEach((t, i) => {
    const messages = cwMetrics[metricId('sn', i, 'msg')]?.sum ?? 0;

    if (messages >= thresholds.sns.idleMessages) return; // active enough — skip

    const subscriptions = subCounts.get(t.arn) ?? -1; // -1 = not fetched (had messages)
    const isOrphaned    = messages === 0 && subscriptions === 0;

    // Priority logic:
    //   MEDIUM — 0 messages AND 0 subscriptions (truly orphaned, no one listening)
    //   LOW    — 0 messages but has subscribers (event-driven topic, just quiet in this window)
    //   LOW    — low but non-zero messages
    const priority = isOrphaned ? 'MEDIUM' : 'LOW';

    const details = messages === 0
      ? isOrphaned
        ? `No messages published and no active subscriptions — likely an orphaned topic`
        : `No messages published in the last ${days} days`
      : `Only ${Math.round(messages)} messages published in the last ${days} days`;

    const recommendation = isOrphaned
      ? `This topic has no subscribers and no recent traffic. Confirm it is not referenced by any IaC stack, then delete it to keep your architecture clean.`
      : `Verify this topic still has active publishers. If it belongs to a decommissioned feature, delete it to reduce clutter.`;

    findings.push({
      provider:     'aws',
      service:      'SNS',
      resourceName: t.name,
      resourceId:   t.arn,
      region,
      priority,
      type:         'IDLE',
      details,
      recommendation,
      metrics: {
        messagesPublished: Math.round(messages),
        ...(subscriptions >= 0 && { subscriptions }),
      },
    });
  });

  return { findings, resourcesScanned: totalFound };
}

module.exports = { analyzeSNS };
