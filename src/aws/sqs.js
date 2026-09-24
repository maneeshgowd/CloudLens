'use strict';

const { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } = require('@aws-sdk/client-sqs');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');

async function listAllQueues(client) {
  const urls = [];
  let nextToken;

  do {
    const res = await client.send(new ListQueuesCommand({ NextToken: nextToken, MaxResults: 1000 }));
    urls.push(...(res.QueueUrls || []));
    nextToken = res.NextToken;
  } while (nextToken);

  return urls;
}

async function getQueueAttributes(client, url) {
  try {
    const res = await client.send(new GetQueueAttributesCommand({
      QueueUrl: url,
      AttributeNames: ['All'],
    }));
    return res.Attributes || {};
  } catch {
    return {};
  }
}

// Extract queue name from URL: https://sqs.region.amazonaws.com/account/queue-name
function queueName(url) {
  return url.split('/').pop();
}

async function analyzeSQS({ region, startTime, endTime, days, filter }) {
  const sqsClient = new SQSClient({ region });
  const cwClient  = new CloudWatchClient({ region });

  process.stdout.write('  SQS: listing queues... ');
  let allUrls = await listAllQueues(sqsClient);
  if (filter) {
    const needle = filter.toLowerCase();
    allUrls = allUrls.filter(u => queueName(u).toLowerCase().includes(needle));
  }
  console.log(`${allUrls.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (allUrls.length === 0) return { findings: [], resourcesScanned: 0 };

  // Fetch queue attributes (in parallel, capped at 20 concurrent)
  process.stdout.write(`  SQS: fetching queue attributes... `);
  const queues = [];
  const CONCURRENCY = 20;
  for (let i = 0; i < allUrls.length; i += CONCURRENCY) {
    const batch = allUrls.slice(i, i + CONCURRENCY);
    const attrs = await Promise.all(batch.map(url => getQueueAttributes(sqsClient, url)));
    batch.forEach((url, j) => queues.push({ url, name: queueName(url), attrs: attrs[j] }));
  }
  console.log('done');

  // CloudWatch metrics for each queue
  const querySpecs = [];
  queues.forEach((q, i) => {
    const dims = [{ Name: 'QueueName', Value: q.name }];
    querySpecs.push(
      { id: metricId('sq', i, 'snt'), namespace: 'AWS/SQS', metricName: 'NumberOfMessagesSent',     dimensions: dims, stat: 'Sum' },
      { id: metricId('sq', i, 'rcv'), namespace: 'AWS/SQS', metricName: 'NumberOfMessagesReceived', dimensions: dims, stat: 'Sum' },
      { id: metricId('sq', i, 'age'), namespace: 'AWS/SQS', metricName: 'ApproximateAgeOfOldestMessage', dimensions: dims, stat: 'Maximum' }
    );
  });

  process.stdout.write(`  SQS: fetching metrics for ${queues.length} queues... `);
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  const findings = [];

  queues.forEach((q, i) => {
    const sent     = cwMetrics[metricId('sq', i, 'snt')]?.sum ?? 0;
    const received = cwMetrics[metricId('sq', i, 'rcv')]?.sum ?? 0;
    const ageSeconds = cwMetrics[metricId('sq', i, 'age')]?.max ?? 0;
    const visibleMessages = parseInt(q.attrs.ApproximateNumberOfMessages || '0', 10);
    const isDLQ = q.name.toLowerCase().includes('dlq') || q.name.toLowerCase().includes('dead');
    const hasRedrive = !!q.attrs.RedrivePolicy;
    const arn = q.attrs.QueueArn || q.url;

    const baseMetrics = {
      messagesSent:     Math.round(sent),
      messagesReceived: Math.round(received),
      currentlyVisible: visibleMessages,
      oldestMessageAge: ageSeconds > 0 ? fmtDuration(ageSeconds) : 'n/a',
    };

    // ── DLQ with messages sitting in it ──────────────────────────────────
    if (isDLQ && visibleMessages > 0) {
      findings.push({
        provider: 'aws',
        service: 'SQS',
        resourceName: q.name,
        resourceId: arn,
        region,
        priority: visibleMessages > 100 ? 'HIGH' : 'MEDIUM',
        type: 'DLQ_MESSAGES',
        details: `Dead Letter Queue has ${visibleMessages.toLocaleString()} unprocessed messages${ageSeconds > 0 ? ` — oldest is ${fmtDuration(ageSeconds)} old` : ''}`,
        recommendation: `Messages in a DLQ indicate failed processing. Investigate the source queue's Lambda/consumer for errors, fix the root cause, then replay messages using the SQS console "Start DLQ redrive" feature.`,
        metrics: { ...baseMetrics },
        estimatedMonthlySavings: null,
        suggestedAlarm: `aws cloudwatch put-metric-alarm \\
  --alarm-name "cloudlens-dlq-${q.name.substring(0, 50)}" \\
  --namespace AWS/SQS --metric-name ApproximateNumberOfMessagesVisible \\
  --dimensions Name=QueueName,Value="${q.name}" \\
  --statistic Maximum --period 300 \\
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1`,
      });
    }

    // ── Idle queue ────────────────────────────────────────────────────────
    if (sent === 0 && received === 0 && visibleMessages === 0) {
      findings.push({
        provider: 'aws',
        service: 'SQS',
        resourceName: q.name,
        resourceId: arn,
        region,
        priority: 'LOW',
        type: 'IDLE',
        details: `No messages sent or received in the last ${days} days`,
        recommendation: `Verify whether this queue is still needed. SQS charges per request so idle queues cost very little, but they add operational overhead. Delete if no longer needed.`,
        metrics: { ...baseMetrics },
        estimatedMonthlySavings: null,
      });
    }

    // ── Queue with very old unprocessed messages ──────────────────────────
    if (!isDLQ && visibleMessages > 0 && ageSeconds > days * 86400 * 0.5) {
      findings.push({
        provider: 'aws',
        service: 'SQS',
        resourceName: q.name,
        resourceId: arn,
        region,
        priority: 'MEDIUM',
        type: 'STALE_MESSAGES',
        details: `${visibleMessages.toLocaleString()} messages visible, oldest is ${fmtDuration(ageSeconds)} — consumer may be stalled`,
        recommendation: `Check the consumer (Lambda, ECS task, EC2) for errors or scaling issues. Messages approaching the queue's visibility timeout will be redelivered and may cause duplicate processing.`,
        metrics: { ...baseMetrics },
        estimatedMonthlySavings: null,
      });
    }
  });

  return { findings, resourcesScanned: queues.length };
}

function fmtDuration(seconds) {
  if (seconds < 3600)  return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

module.exports = { analyzeSQS };
