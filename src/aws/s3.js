'use strict';

const { S3Client, ListBucketsCommand, GetBucketLocationCommand, GetPublicAccessBlockCommand } = require('@aws-sdk/client-s3');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { batchGetMetrics, metricId } = require('./cloudwatch');
const { thresholds } = require('../config');

async function analyzS3({ region, startTime, endTime, days, filter }) {
  const s3Client = new S3Client({ region });

  process.stdout.write('  S3: listing buckets... ');
  const { Buckets: allBuckets = [] } = await s3Client.send(new ListBucketsCommand({}));
  const buckets = filter
    ? allBuckets.filter(b => b.Name.toLowerCase().includes(filter.toLowerCase()))
    : allBuckets;
  console.log(`${buckets.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (buckets.length === 0) return { findings: [], resourcesScanned: 0 };

  // S3 storage metrics are published to CloudWatch us-east-1 regardless of bucket region
  const cwClient = new CloudWatchClient({ region: 'us-east-1' });

  // BucketSizeBytes and NumberOfObjects are daily metrics — always available, no setup needed
  const querySpecs = [];

  buckets.forEach((b, i) => {
    const dims = [
      { Name: 'BucketName', Value: b.Name },
      { Name: 'StorageType', Value: 'StandardStorage' },
    ];
    querySpecs.push(
      {
        id: metricId('s3', i, 'sz'),
        namespace: 'AWS/S3',
        metricName: 'BucketSizeBytes',
        dimensions: dims,
        stat: 'Average', // daily snapshot — Average makes sense here
      },
      {
        id: metricId('s3', i, 'obj'),
        namespace: 'AWS/S3',
        metricName: 'NumberOfObjects',
        dimensions: [
          { Name: 'BucketName', Value: b.Name },
          { Name: 'StorageType', Value: 'AllStorageTypes' },
        ],
        stat: 'Average',
      }
    );
  });

  process.stdout.write(`  S3: fetching storage metrics for ${buckets.length} buckets... `);
  // S3 storage metrics use 86400s (1 day) period — finer periods return no data
  const cwMetrics = await batchGetMetrics(cwClient, querySpecs, startTime, endTime, 86400);
  console.log('done');

  // ── Public access block check ─────────────────────────────────────────────
  process.stdout.write(`  S3: checking public access settings for ${buckets.length} buckets... `);
  const publicAccessResults = await Promise.all(
    buckets.map(b =>
      s3Client.send(new GetPublicAccessBlockCommand({ Bucket: b.Name }))
        .then(res => ({ name: b.Name, config: res.PublicAccessBlockConfiguration || {}, missing: false }))
        .catch(err => ({
          name:    b.Name,
          config:  {},
          missing: err.name === 'NoSuchPublicAccessBlockConfiguration',
          error:   err.name !== 'NoSuchPublicAccessBlockConfiguration',
        }))
    )
  );
  console.log('done');

  const findings = [];

  // Public access findings
  for (const r of publicAccessResults) {
    if (r.error) continue;
    const c = r.config;
    const fullyBlocked = c.BlockPublicAcls && c.BlockPublicPolicy && c.IgnorePublicAcls && c.RestrictPublicBuckets;
    if (!fullyBlocked) {
      const missing = r.missing
        ? 'No public access block configured'
        : `BlockPublicAcls:${c.BlockPublicAcls} BlockPublicPolicy:${c.BlockPublicPolicy} IgnorePublicAcls:${c.IgnorePublicAcls} RestrictPublicBuckets:${c.RestrictPublicBuckets}`;
      findings.push({
        provider:       'aws',
        service:        'S3',
        resourceName:   r.name,
        resourceId:     `arn:aws:s3:::${r.name}`,
        region:         'global',
        priority:       'HIGH',
        type:           'S3_PUBLIC_ACCESS',
        details:        r.missing
          ? `No S3 Block Public Access settings configured — bucket may be publicly accessible`
          : `S3 Block Public Access is not fully enabled — bucket data may be exposed to the internet`,
        recommendation: `Enable all four S3 Block Public Access settings on this bucket (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets). Unless this bucket intentionally serves public content, all four should be on.`,
        metrics:        { publicAccessBlock: missing },
      });
    }
  }

  buckets.forEach((b, i) => {
    const sizeBytes   = cwMetrics[metricId('s3', i, 'sz')]?.avg  ?? 0;
    const objectCount = cwMetrics[metricId('s3', i, 'obj')]?.avg ?? 0;

    // Empty bucket — nothing stored, still costs nothing but indicates clutter
    if (objectCount === 0 && sizeBytes === 0) {
      findings.push({
        provider:       'aws',
        service:        'S3',
        resourceName:   b.Name,
        resourceId:     `arn:aws:s3:::${b.Name}`,
        region:         'global',
        priority:       'LOW',
        type:           'IDLE',
        details:        `Bucket contains no objects and has 0 bytes stored`,
        recommendation: `Delete empty buckets to keep your account tidy. Empty buckets incur no storage cost but add operational overhead and IAM surface area.`,
        metrics:        { objectCount: 0, sizeBytes: 0 },
      });
    }
  });

  return { findings, resourcesScanned: buckets.length };
}

module.exports = { analyzS3 };
