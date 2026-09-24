'use strict';

// Lambda runtime deprecation status as of September 2026.
// Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
//
// status: 'EOL'        = end-of-life reached; AWS no longer ships security patches
//         'DEPRECATED' = not yet EOL but deprecated for new deployments or within
//                        180-day advance-notice window; migration should start now
const RUNTIME_STATUS = {
  // ── Fully end-of-life ─────────────────────────────────────────────────────
  'dotnetcore3.1': { status: 'EOL', label: '.NET Core 3.1', upgrade: 'dotnet9',        eolDate: '2023-04-03' },
  'dotnet5.0':     { status: 'EOL', label: '.NET 5.0',      upgrade: 'dotnet9',        eolDate: '2022-05-14' },
  'dotnet6':       { status: 'EOL', label: '.NET 6',        upgrade: 'dotnet9',        eolDate: '2024-12-20' },
  'go1.x':         { status: 'EOL', label: 'Go 1.x',        upgrade: 'provided.al2023', eolDate: '2024-01-08' },
  'java8':         { status: 'EOL', label: 'Java 8 (AL1)',   upgrade: 'java21',         eolDate: '2024-01-08' },
  'nodejs12.x':    { status: 'EOL', label: 'Node.js 12',    upgrade: 'nodejs22.x',     eolDate: '2023-03-31' },
  'nodejs14.x':    { status: 'EOL', label: 'Node.js 14',    upgrade: 'nodejs22.x',     eolDate: '2023-12-04' },
  'nodejs16.x':    { status: 'EOL', label: 'Node.js 16',    upgrade: 'nodejs22.x',     eolDate: '2024-06-12' },
  'nodejs18.x':    { status: 'EOL', label: 'Node.js 18',    upgrade: 'nodejs22.x',     eolDate: '2025-09-01' },
  'nodejs20.x':    { status: 'EOL', label: 'Node.js 20',    upgrade: 'nodejs22.x',     eolDate: '2026-04-30' },
  'provided.al2':  { status: 'EOL', label: 'AL2 (custom runtime)', upgrade: 'provided.al2023', eolDate: '2026-07-31' },
  'python3.7':     { status: 'EOL', label: 'Python 3.7',    upgrade: 'python3.13',     eolDate: '2023-12-04' },
  'python3.8':     { status: 'EOL', label: 'Python 3.8',    upgrade: 'python3.13',     eolDate: '2024-10-14' },
  'python3.9':     { status: 'EOL', label: 'Python 3.9',    upgrade: 'python3.13',     eolDate: '2025-12-15' },
  'ruby2.7':       { status: 'EOL', label: 'Ruby 2.7',      upgrade: 'ruby3.3',        eolDate: '2023-12-07' },
  'ruby3.2':       { status: 'EOL', label: 'Ruby 3.2',      upgrade: 'ruby3.3',        eolDate: '2026-03-31' },

  // ── Deprecated — EOL imminent, migrate now ────────────────────────────────
  // python3.10 EOL: 2026-10-31  |  dotnet8 EOL: 2026-11-10
  'python3.10':    { status: 'DEPRECATED', label: 'Python 3.10', upgrade: 'python3.13', eolDate: '2026-10-31' },
  'dotnet8':       { status: 'DEPRECATED', label: '.NET 8',       upgrade: 'dotnet9',   eolDate: '2026-11-10' },
};

module.exports = { RUNTIME_STATUS };
