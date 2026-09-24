'use strict';

const fs = require('fs');

// Parses a shell-script-style credentials file (lines like `export KEY=VALUE`
// or plain `KEY=VALUE`) into a plain object. Lets users keep Azure config in
// a .sh file — the same file can also be `source`d directly in bash — instead
// of setting environment variables or passing everything as CLI flags.
function loadShellEnvFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return {};

  const content = fs.readFileSync(filePath, 'utf8');
  const values = {};

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const match = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;

    let [, key, value] = match;
    value = value.trim();

    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else {
      // Unquoted value — drop a trailing inline comment, e.g. `KEY=value # note`.
      value = value.split(/\s+#/)[0].trim();
    }

    values[key] = value;
  }

  return values;
}

module.exports = { loadShellEnvFile };
