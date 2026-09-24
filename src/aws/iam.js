'use strict';

const {
  IAMClient,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
} = require('@aws-sdk/client-iam');

const KEY_WARN_DAYS     = 90;   // MEDIUM: key older than 90 days
const KEY_CRITICAL_DAYS = 180;  // HIGH:   key older than 180 days

async function analyzeIAM({ filter }) {
  // IAM is a global service — always use us-east-1
  const iam = new IAMClient({ region: 'us-east-1' });

  process.stdout.write('  IAM: listing users and access keys... ');

  const users = [];
  let marker;
  do {
    const res = await iam.send(new ListUsersCommand({ Marker: marker }));
    users.push(...(res.Users || []));
    marker = res.IsTruncated ? res.Marker : null;
  } while (marker);

  const filtered = filter
    ? users.filter(u => u.UserName?.toLowerCase().includes(filter.toLowerCase()))
    : users;

  const now      = new Date();
  const findings = [];
  let   keysScanned = 0;

  for (const user of filtered) {
    let keys;
    try {
      const res = await iam.send(new ListAccessKeysCommand({ UserName: user.UserName }));
      keys = res.AccessKeyMetadata || [];
    } catch (_) {
      continue;
    }

    for (const key of keys) {
      if (key.Status !== 'Active') continue;
      keysScanned++;

      const ageDays = Math.floor((now - new Date(key.CreateDate)) / 86400000);
      if (ageDays < KEY_WARN_DAYS) continue;

      let lastUsedDays = null;
      try {
        const lu = await iam.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }));
        if (lu.AccessKeyLastUsed?.LastUsedDate) {
          lastUsedDays = Math.floor((now - new Date(lu.AccessKeyLastUsed.LastUsedDate)) / 86400000);
        }
      } catch (_) {}

      const priority   = ageDays >= KEY_CRITICAL_DAYS ? 'HIGH' : 'MEDIUM';
      const lastUsedStr = lastUsedDays != null
        ? `last used ${lastUsedDays} days ago`
        : 'never used';

      findings.push({
        provider:       'aws',
        service:        'IAM',
        resourceName:   `${user.UserName} / …${key.AccessKeyId.slice(-4)}`,
        resourceId:     `arn:aws:iam::*:user/${user.UserName}`,
        region:         'global',
        priority,
        type:           'IAM_KEY_STALE',
        details:        `Access key is ${ageDays} days old (${lastUsedStr}) — rotation overdue`,
        recommendation: `Rotate this access key. Create a new key, update all consumers, then deactivate and delete this one. Keys older than 90 days violate CIS AWS Benchmark 1.14 and SOC 2 CC6.1.`,
        metrics: {
          keyAgeDays:      ageDays,
          lastUsedDaysAgo: lastUsedDays ?? 'never',
          keyIdSuffix:     `…${key.AccessKeyId.slice(-4)}`,
          userName:        user.UserName,
        },
      });
    }
  }

  console.log(`${filtered.length} users, ${keysScanned} active keys checked`);
  return { findings, resourcesScanned: keysScanned };
}

module.exports = { analyzeIAM };
