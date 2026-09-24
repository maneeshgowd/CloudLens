'use strict';

// Azure Functions runtime stack deprecation status, as of Sep 2026.
// Source: https://learn.microsoft.com/en-us/azure/azure-functions/language-support-policy
// Keyed by "<runtime>|<majorVersion>" lowercase, same shape as src/aws/runtimes.js.
const STACK_STATUS = {
  'node|14': { status: 'EOL', label: 'Node.js 14', upgrade: 'NODE|22-lts', eolDate: '2023-04-30' },
  'node|16': { status: 'EOL', label: 'Node.js 16', upgrade: 'NODE|22-lts', eolDate: '2024-09-11' },
  'node|18': { status: 'EOL', label: 'Node.js 18', upgrade: 'NODE|22-lts', eolDate: '2025-09-01' },
  'node|20': { status: 'DEPRECATED', label: 'Node.js 20', upgrade: 'NODE|22-lts', eolDate: '2026-10-31' },
  'python|3.7': { status: 'EOL', label: 'Python 3.7', upgrade: 'PYTHON|3.13', eolDate: '2023-11-27' },
  'python|3.8': { status: 'EOL', label: 'Python 3.8', upgrade: 'PYTHON|3.13', eolDate: '2024-10-14' },
  'python|3.9': { status: 'EOL', label: 'Python 3.9', upgrade: 'PYTHON|3.13', eolDate: '2025-12-15' },
  'dotnet|6.0': { status: 'EOL', label: '.NET 6', upgrade: 'DOTNET-ISOLATED|9.0', eolDate: '2024-12-20' },
  'dotnet|7.0': { status: 'EOL', label: '.NET 7', upgrade: 'DOTNET-ISOLATED|9.0', eolDate: '2024-05-14' },
  'dotnet|8.0': { status: 'DEPRECATED', label: '.NET 8', upgrade: 'DOTNET-ISOLATED|9.0', eolDate: '2026-11-10' },
  'java|8': { status: 'EOL', label: 'Java 8', upgrade: 'JAVA|21', eolDate: '2023-01-01' },
  'java|11': { status: 'DEPRECATED', label: 'Java 11', upgrade: 'JAVA|21', eolDate: '2026-12-31' },
  'powershell|7.0': { status: 'EOL', label: 'PowerShell 7.0', upgrade: 'POWERSHELL|7.4', eolDate: '2022-12-13' },
  'powershell|7.2': { status: 'EOL', label: 'PowerShell 7.2', upgrade: 'POWERSHELL|7.4', eolDate: '2024-04-24' },
};

// Parses a Function App's siteConfig (Linux `linuxFxVersion` like "NODE|18-lts",
// or Windows-stack fields like `nodeVersion`/`netFrameworkVersion`) and returns
// deprecation info, or null when the stack is current/unrecognized.
function getRuntimeStatus(siteConfig = {}) {
  const raw = siteConfig.linuxFxVersion || windowsStackKey(siteConfig);
  if (!raw) return null;

  const parts = raw.split('|');
  if (parts.length < 2) return null;

  const runtime = parts[0].toLowerCase().replace('-isolated', '');
  const versionMatch = parts[1].match(/[\d.]+/);
  if (!versionMatch) return null;

  const info = STACK_STATUS[`${runtime}|${versionMatch[0]}`];
  return info ? { ...info, raw } : null;
}

function windowsStackKey(siteConfig) {
  if (siteConfig.nodeVersion) return `node|${siteConfig.nodeVersion.replace('~', '')}`;
  if (siteConfig.netFrameworkVersion) return `dotnet|${siteConfig.netFrameworkVersion.replace(/^v/i, '')}`;
  if (siteConfig.javaVersion) return `java|${siteConfig.javaVersion.replace('~', '')}`;
  if (siteConfig.powerShellVersion) return `powershell|${siteConfig.powerShellVersion}`;
  return null;
}

module.exports = { getRuntimeStatus };
