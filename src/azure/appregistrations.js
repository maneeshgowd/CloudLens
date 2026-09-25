'use strict';

const { thresholds } = require('../config');

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';

async function graphGet(url, token) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Graph API returned ${res.status} ${res.statusText}${body ? ` — ${body.slice(0, 300)}` : ''}`);
  }
  return res.json();
}

async function listAllApplications(token, filter) {
  const apps = [];
  const params = new URLSearchParams({ $select: 'id,appId,displayName,passwordCredentials,keyCredentials', $top: '999' });
  if (filter) params.set('$filter', `startswith(displayName,'${filter.replace(/'/g, "''")}')`);
  let url = `${GRAPH_BASE}/applications?${params.toString()}`;

  while (url) {
    const page = await graphGet(url, token);
    apps.push(...(page.value || []));
    url = page['@odata.nextLink'] || null;
  }
  return apps;
}

// Azure AD (Entra ID) App Registrations — client secrets and certificate credentials
// nearing or past their expiration date. Unlike every other Azure analyser, these
// resources live in the tenant's directory, not a subscription, so they require
// Microsoft Graph's Application.Read.All application permission (admin-consented)
// rather than subscription-scoped Azure RBAC. Best-effort: if that permission isn't
// granted, Graph returns 403 and this analyser is skipped like any other failed
// service in analyzer.js.
async function analyzeAppRegistrations({ credential, filter }) {
  process.stdout.write('  App Registrations: listing applications... ');

  const tokenResponse = await credential.getToken(GRAPH_SCOPE);
  const token = tokenResponse?.token;
  if (!token) {
    console.log('skipped (no Microsoft Graph token)');
    return { findings: [], resourcesScanned: 0 };
  }

  const apps = await listAllApplications(token, filter);
  console.log(`${apps.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (apps.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];
  const now = Date.now();
  const { expiryWarningDays, expiryCriticalDays } = thresholds.azure.appRegistrations;

  for (const app of apps) {
    const appName = app.displayName || app.appId;
    const credentials = [
      ...(app.passwordCredentials || []).map((c) => ({ ...c, kind: 'Client secret' })),
      ...(app.keyCredentials || []).map((c) => ({ ...c, kind: 'Certificate credential' }))
    ];

    for (const cred of credentials) {
      if (!cred.endDateTime) continue;

      const daysUntilExpiry = Math.floor((new Date(cred.endDateTime).getTime() - now) / (24 * 60 * 60 * 1000));
      if (daysUntilExpiry > expiryWarningDays) continue;

      const isExpired = daysUntilExpiry < 0;
      const isCritical = daysUntilExpiry <= expiryCriticalDays;
      const credLabel = cred.displayName ? `"${cred.displayName}"` : `(unnamed, key ID ${cred.keyId})`;
      const credSlug = cred.kind === 'Client secret' ? 'secrets' : 'keyCredentials';

      findings.push({
        provider: 'azure',
        service: 'App Registrations',
        resourceName: `${appName}/${credSlug}/${cred.keyId}`,
        resourceId: app.id,
        region: null,
        environment: null,
        team: null,
        tags: {},
        priority: isCritical ? 'HIGH' : 'MEDIUM',
        type: 'APP_SECRET_EXPIRING',
        details: isExpired
          ? `${cred.kind} ${credLabel} on app "${appName}" expired ${Math.abs(daysUntilExpiry)} day(s) ago`
          : `${cred.kind} ${credLabel} on app "${appName}" expires in ${daysUntilExpiry} day(s)`,
        recommendation: `Generate a replacement ${cred.kind.toLowerCase()} and roll it out to every application/service that authenticates as "${appName}" before the old one expires — once it lapses, client-credential sign-ins for this app fail outright.`,
        metrics: {
          appDisplayName: app.displayName || null,
          appId: app.appId,
          credentialType: cred.kind,
          endDateTime: new Date(cred.endDateTime).toISOString(),
          daysUntilExpiry
        },
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        fixCommand: cred.kind === 'Client secret' ? `az ad app credential reset --id ${app.appId} --append --display-name "renewed-$(date +%Y%m%d)"` : null,
        suggestedAlarm: null
      });
    }
  }

  return { findings, resourcesScanned: apps.length };
}

module.exports = { analyzeAppRegistrations };
