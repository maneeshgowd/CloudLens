'use strict';

// Shared tag helpers for Azure analysers — mirrors the detectEnvironment/detectTeam/
// missingTagGroups/adjustIdlePriority pattern in src/aws/lambda.js. Reused across all
// Azure service modules since Azure resource tags come back as a plain object already
// (no separate tag-fetch call needed, unlike Lambda's ListTagsCommand).

const REQUIRED_TAG_GROUPS = [
  ['Environment', 'environment', 'Env', 'env'],
  ['Team', 'team', 'Owner', 'owner', 'Squad', 'squad'],
];

function detectEnvironment(tags = {}, resourceName = '') {
  const envTag = tags.Environment || tags.environment || tags.Env || tags.env;
  if (envTag) return envTag.toLowerCase();

  const name = resourceName.toLowerCase();
  if (/-prd-|-prod-|-production-/.test(name) || name.endsWith('-prod') || name.endsWith('-prd')) return 'prod';
  if (/-tst-|-test-|-staging-|-stg-/.test(name)) return 'tst';
  if (/-dev-/.test(name)) return 'dev';
  return 'unknown';
}

function detectTeam(tags = {}) {
  const checks = [
    ['Team', 'Team'], ['team', 'Team'],
    ['Owner', 'Owner'], ['owner', 'Owner'],
    ['Squad', 'Squad'], ['squad', 'Squad'],
    ['Project', 'Project'], ['project', 'Project'],
  ];
  for (const [tagKey, label] of checks) {
    if (tags[tagKey]) return `${label}: ${tags[tagKey]}`;
  }
  return null;
}

function missingTagGroups(tags = {}) {
  return REQUIRED_TAG_GROUPS.filter(group => !group.some(key => key in tags));
}

function adjustIdlePriority(priority, environment) {
  if (environment === 'tst' || environment === 'test' || environment === 'staging' || environment === 'stg') {
    return priority === 'HIGH' ? 'MEDIUM' : priority;
  }
  if (environment === 'dev' || environment === 'development') {
    return priority === 'HIGH' || priority === 'MEDIUM' ? 'LOW' : priority;
  }
  return priority;
}

// Extracts the resource group name from a full ARM resource ID.
function resourceGroupFromId(resourceId) {
  const match = resourceId.match(/resourceGroups\/([^/]+)/i);
  return match ? match[1] : null;
}

// True if a resource's location matches the configured scan target, so analysers can
// skip resources outside AZURE_LOCATION. Global-scoped resources (e.g. classic CDN
// profiles) aren't tied to any region and always match.
function matchesLocation(resourceLocation, targetLocation) {
  if (!targetLocation) return true;
  const norm = (loc) => (loc || '').toLowerCase().replace(/\s+/g, '');
  const rl = norm(resourceLocation);
  if (!rl || rl === 'global') return true;
  return rl === norm(targetLocation);
}

module.exports = { detectEnvironment, detectTeam, missingTagGroups, adjustIdlePriority, resourceGroupFromId, matchesLocation };
