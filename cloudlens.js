#!/usr/bin/env node
'use strict';

const { Command } = require('commander');
const fs   = require('fs');
const path = require('path');

const program = new Command();

program
  .name('cloudlens')
  .description('Multi-cloud operational health & cost intelligence')
  .version('1.0.0')
  .option('--provider <provider>',  'Cloud provider: aws | azure',        'aws')
  .option('--days <number>',        'Analysis window in days',             '28')
  // AWS options
  .option('--region <region>',      'AWS region to analyse',               'us-east-1')
  // Azure options — values are read from --azure-env-file (a .sh-style
  // credentials file) by default; any of these flags overrides the file.
  .option('--azure-subscription <id>',    'Azure Subscription ID')
  .option('--azure-tenant <id>',          'Azure Tenant ID')
  .option('--azure-client-id <id>',       'Azure Client ID (service principal)')
  .option('--azure-client-secret <secret>','Azure Client Secret')
  .option('--azure-location <location>',  'Azure location to analyse')
  .option('--azure-env-file <path>',      'Path to a .sh file with AZURE_SUBSCRIPTION_ID/AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_LOCATION', './.run-creds.sh')
  // Output
  .option('--output <path>',        'Output path for HTML report',         './cloudlens-report.html')
  .option('--filter <string>',      'Only include resources whose name contains this string (case-insensitive)')
  .option('--exclude-service <services>', 'Comma-separated services to skip')
  .parse(process.argv);

const opts = program.opts();

async function main() {
  const provider = opts.provider.toLowerCase();
  const days     = parseInt(opts.days, 10);
  const output   = opts.output;

  if (isNaN(days) || days < 1 || days > 90) {
    console.error('Error: --days must be between 1 and 90');
    process.exit(1);
  }

  if (!['aws', 'azure'].includes(provider)) {
    console.error('Error: --provider must be aws or azure');
    process.exit(1);
  }

  let azureConfig = null;
  if (provider === 'azure') {
    const { loadShellEnvFile } = require('./src/azure/envfile');
    const envFileVars = loadShellEnvFile(opts.azureEnvFile);
    const envFileUsed = Object.keys(envFileVars).length > 0;

    azureConfig = {
      subscriptionId: opts.azureSubscription || envFileVars.AZURE_SUBSCRIPTION_ID,
      tenantId:       opts.azureTenant       || envFileVars.AZURE_TENANT_ID,
      clientId:       opts.azureClientId     || envFileVars.AZURE_CLIENT_ID,
      clientSecret:   opts.azureClientSecret || envFileVars.AZURE_CLIENT_SECRET,
      location:       opts.azureLocation     || envFileVars.AZURE_LOCATION || 'eastus',
    };

    if (envFileUsed) azureConfig.envFilePath = path.resolve(opts.azureEnvFile);
  }

  printBanner();
  console.log(`  Provider : ${provider.toUpperCase()}`);
  if (provider === 'aws')   console.log(`  Region   : ${opts.region}`);
  if (provider === 'azure') {
    console.log(`  Location : ${azureConfig.location}`);
    if (azureConfig.envFilePath) console.log(`  Config   : ${azureConfig.envFilePath}`);
  }
  console.log(`  Window   : last ${days} days`);
  if (opts.filter) console.log(`  Filter   : applied`);
  if (opts.excludeService) console.log(`  Excluding: ${opts.excludeService}`);
  console.log(`  Output   : ${path.resolve(output)}`);
  console.log('');

  const findings = [];
  let awsSummary   = null;
  let azureSummary = null;

  const exclude = opts.excludeService
    ? opts.excludeService.split(',').map(s => s.trim().toLowerCase())
    : [];

  // ── AWS analysis ──────────────────────────────────────────────────────────
  if (provider === 'aws') {
    try {
      const { analyzeAWS } = require('./src/aws/analyzer');
      console.log('Scanning AWS resources...\n');
      const result = await analyzeAWS({ days, region: opts.region, filter: opts.filter, exclude });
      findings.push(...result.findings);
      awsSummary = result.summary;
    } catch (err) {
      console.error(`\nAWS analysis failed: ${err.message}`);
      if (err.name === 'CredentialsProviderError' || err.message.includes('credential')) {
        console.error('\nHint: configure AWS credentials via environment variables or ~/.aws/credentials');
      }
      if (process.env.DEBUG) console.error(err.stack);
      process.exit(1);
    }
  }

  // ── Azure analysis ────────────────────────────────────────────────────────
  if (provider === 'azure') {
    try {
      const { analyzeAzure } = require('./src/azure/analyzer');
      console.log('Scanning Azure resources...\n');
      const result = await analyzeAzure({
        days,
        subscriptionId: azureConfig.subscriptionId,
        tenantId:       azureConfig.tenantId,
        clientId:       azureConfig.clientId,
        clientSecret:   azureConfig.clientSecret,
        location:       azureConfig.location,
        filter:         opts.filter,
        exclude,
      });
      findings.push(...result.findings);
      azureSummary = result.summary;
    } catch (err) {
      console.error(`\nAzure analysis failed: ${err.message}`);
      if (err.message.includes('credential') || err.message.includes('authentication')) {
        console.error(`\nHint: set AZURE_SUBSCRIPTION_ID/AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET in ${opts.azureEnvFile} (see .run-creds.sh.example), or pass --azure-subscription/--azure-tenant/--azure-client-id/--azure-client-secret`);
      }
      if (process.env.DEBUG) console.error(err.stack);
      process.exit(1);
    }
  }

  // Sort: HIGH → MEDIUM → LOW, then by service
  const priorityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  findings.sort((a, b) => {
    const p = (priorityOrder[a.priority] ?? 3) - (priorityOrder[b.priority] ?? 3);
    return p !== 0 ? p : a.service.localeCompare(b.service);
  });

  const { generateReport } = require('./src/report/generator');
  const html = generateReport({
    findings,
    summary: { aws: awsSummary, azure: azureSummary },
    provider,
    days,
  });

  fs.writeFileSync(output, html, 'utf8');
  printSummary(findings, awsSummary, azureSummary, output);
}

function printBanner() {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║  CloudLens — Multi-Cloud Health & Cost Intel  ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
}

function printSummary(findings, awsSummary, azureSummary, output) {
  const high   = findings.filter(f => f.priority === 'HIGH').length;
  const medium = findings.filter(f => f.priority === 'MEDIUM').length;
  const low    = findings.filter(f => f.priority === 'LOW').length;

  console.log('\n─────────────────────────────────────────');
  console.log('  Results\n');
  if (awsSummary)   console.log(`  AWS resources scanned   : ${awsSummary.resourcesScanned ?? 0}`);
  if (azureSummary) console.log(`  Azure resources scanned : ${azureSummary.resourcesScanned ?? 0}`);
  console.log(`  Total findings    : ${findings.length}`);
  console.log(`  HIGH              : ${high}`);
  console.log(`  MEDIUM            : ${medium}`);
  console.log(`  LOW               : ${low}`);
  console.log('');

  if (findings.length > 0) {
    console.log('  Top findings:');
    findings.slice(0, 5).forEach(f => {
      const flag = f.priority === 'HIGH' ? '●' : f.priority === 'MEDIUM' ? '○' : '·';
      const prov = (f.provider || 'aws').toUpperCase().padEnd(5);
      console.log(`  ${flag} [${f.priority.padEnd(6)}] [${prov}] ${f.service.padEnd(12)} ${f.resourceName}`);
    });
    if (findings.length > 5) {
      console.log(`  ... and ${findings.length - 5} more in the report`);
    }
  }

  console.log('');
  console.log(`  Report: ${path.resolve(output)}`);
  console.log('─────────────────────────────────────────\n');
}

main().catch(err => {
  console.error('\nUnexpected error:', err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
