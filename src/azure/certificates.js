'use strict';

const { WebSiteManagementClient } = require('@azure/arm-appservice');
const { thresholds, azureManagedPrefixes } = require('../config');
const { detectEnvironment, detectTeam, missingTagGroups, resourceGroupFromId, matchesLocation } = require('./tagging');

async function listAll(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

// App Service (management-plane) SSL certificates only — Key Vault certs/keys are
// covered separately in keyvault.js via data-plane calls, since they require
// different RBAC and a different SDK.
async function analyzeCertificates({ credential, subscriptionId, filter, location }) {
  const webClient = new WebSiteManagementClient(credential, subscriptionId);

  process.stdout.write('  SSL Certificates: listing certificates... ');
  const allCerts = await listAll(webClient.certificates.list());
  let certs = allCerts;
  if (filter) {
    const needle = filter.toLowerCase();
    certs = certs.filter(c => c.name.toLowerCase().includes(needle));
  }
  certs = certs.filter(c => !azureManagedPrefixes.some(p => c.name.toLowerCase().startsWith(p)));
  certs = certs.filter(c => matchesLocation(c.location, location));
  console.log(`${certs.length} found${filter ? ` matching "${filter}"` : ''}`);

  if (certs.length === 0) return { findings: [], resourcesScanned: 0 };

  const findings = [];
  const now = Date.now();

  certs.forEach(cert => {
    const expirationDate = cert.expirationDate ? new Date(cert.expirationDate) : null;
    if (!expirationDate) return;

    const daysUntilExpiry = Math.floor((expirationDate.getTime() - now) / (24 * 60 * 60 * 1000));
    if (daysUntilExpiry > thresholds.azure.certificates.expiryWarningDays) return;

    const tags = cert.tags || {};
    const environment = detectEnvironment(tags, cert.name);
    const team = detectTeam(tags);
    const rg = resourceGroupFromId(cert.id);
    const isExpired = daysUntilExpiry < 0;
    const isCritical = daysUntilExpiry <= thresholds.azure.certificates.expiryCriticalDays;
    const hostNames = (cert.hostNames || []).join(', ') || 'unknown host(s)';

    findings.push({
      provider: 'azure',
      service: 'SSL Certificates',
      resourceName: cert.name,
      resourceId: cert.id,
      region: cert.location,
      environment,
      team,
      tags,
      priority: isCritical ? 'HIGH' : 'MEDIUM',
      type: 'CERT_EXPIRING',
      details: isExpired
        ? `App Service certificate for ${hostNames} expired ${Math.abs(daysUntilExpiry)} day(s) ago`
        : `App Service certificate for ${hostNames} expires in ${daysUntilExpiry} day(s)`,
      recommendation: `Renew or replace this certificate before it expires to avoid TLS handshake failures for ${hostNames}. Upload the new certificate and rebind it to the affected app(s).`,
      metrics: { hostNames: cert.hostNames || [], expirationDate: expirationDate.toISOString(), daysUntilExpiry, thumbprint: cert.thumbprint },
      estimatedCurrentCost: null,
      estimatedMonthlySavings: null,
      fixCommand: `az webapp config ssl upload --certificate-file <path-to-new-cert.pfx> --certificate-password <password> --name <app-name> --resource-group "${rg}"\naz webapp config ssl bind --certificate-thumbprint <new-thumbprint> --ssl-type SNI --name <app-name> --resource-group "${rg}"`,
      suggestedAlarm: null,
    });

    const missing = missingTagGroups(tags);
    if (missing.length > 0) {
      findings.push({
        provider: 'azure',
        service: 'SSL Certificates',
        resourceName: cert.name,
        resourceId: cert.id,
        region: cert.location,
        environment,
        team,
        tags,
        priority: 'LOW',
        type: 'MISSING_TAGS',
        details: `Missing recommended tags: ${missing.map(g => g[0]).join(', ')}`,
        recommendation: `Tag resources to enable cost allocation and ownership routing:\naz resource tag --ids "${cert.id}" --tags Environment=${environment} Team=your-team`,
        estimatedCurrentCost: null,
        estimatedMonthlySavings: null,
        suggestedAlarm: null,
      });
    }
  });

  return { findings, resourcesScanned: certs.length };
}

module.exports = { analyzeCertificates };
