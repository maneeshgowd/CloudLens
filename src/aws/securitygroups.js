'use strict';

const { EC2Client, DescribeSecurityGroupsCommand } = require('@aws-sdk/client-ec2');

// Ports that must never be open to 0.0.0.0/0 or ::/0
const SENSITIVE_PORTS = {
  22:    'SSH',
  3389:  'RDP',
  3306:  'MySQL',
  5432:  'PostgreSQL',
  1433:  'MSSQL',
  27017: 'MongoDB',
  6379:  'Redis',
  9200:  'Elasticsearch',
  9300:  'Elasticsearch',
};

function openToWorld(ipRanges, ipv6Ranges) {
  return (ipRanges  || []).some(r => r.CidrIp   === '0.0.0.0/0') ||
         (ipv6Ranges || []).some(r => r.CidrIpv6 === '::/0');
}

async function analyzeSecurityGroups({ region, filter }) {
  const ec2 = new EC2Client({ region });

  process.stdout.write('  Security Groups: listing... ');

  const sgs = [];
  let nextToken;
  do {
    const res = await ec2.send(new DescribeSecurityGroupsCommand({ NextToken: nextToken }));
    sgs.push(...(res.SecurityGroups || []));
    nextToken = res.NextToken;
  } while (nextToken);

  const filtered = filter
    ? sgs.filter(sg => sg.GroupName?.toLowerCase().includes(filter.toLowerCase()))
    : sgs;

  console.log(`${filtered.length} found`);
  if (filtered.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];
  const seen = new Set(); // dedupe: one finding per (groupId, port)

  for (const sg of filtered) {
    const name = sg.GroupName || sg.GroupId;

    for (const perm of (sg.IpPermissions || [])) {
      if (!openToWorld(perm.IpRanges, perm.Ipv6Ranges)) continue;

      const proto = perm.IpProtocol;

      // All traffic open (-1 = all protocols)
      if (proto === '-1') {
        const key = `${sg.GroupId}:ALL`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push({
            provider:       'aws',
            service:        'Security Groups',
            resourceName:   name,
            resourceId:     sg.GroupId,
            region,
            priority:       'HIGH',
            type:           'SG_OPEN_INGRESS',
            details:        `All ports and protocols open to 0.0.0.0/0 — fully exposed to the internet`,
            recommendation: `Remove the all-traffic ingress rule immediately. Restrict access to specific ports and known IP ranges or security groups. Open-world access on all ports is a critical security misconfiguration.`,
            metrics:        { protocol: 'All', ports: 'All', exposure: '0.0.0.0/0' },
          });
        }
        continue;
      }

      const fromPort = perm.FromPort ?? 0;
      const toPort   = perm.ToPort   ?? 65535;

      for (const [portStr, svcName] of Object.entries(SENSITIVE_PORTS)) {
        const port = parseInt(portStr, 10);
        if (fromPort <= port && toPort >= port) {
          const key = `${sg.GroupId}:${port}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              provider:       'aws',
              service:        'Security Groups',
              resourceName:   name,
              resourceId:     sg.GroupId,
              region,
              priority:       'HIGH',
              type:           'SG_OPEN_INGRESS',
              details:        `Port ${port} (${svcName}) open to 0.0.0.0/0 — accessible from the entire internet`,
              recommendation: `Restrict ${svcName} (port ${port}) to specific trusted IP ranges or private security groups. Exposing ${svcName} to the public internet is a critical security risk.`,
              metrics:        { protocol: proto, port, service: svcName, exposure: '0.0.0.0/0' },
            });
          }
        }
      }
    }
  }

  return { findings, resourcesScanned: filtered.length };
}

module.exports = { analyzeSecurityGroups };
