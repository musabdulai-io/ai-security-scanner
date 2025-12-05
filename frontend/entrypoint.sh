#!/usr/bin/env bash
set -euo pipefail

# Runtime Environment Variable Generator
# Generates /public/runtime-env.js from template at container start

REV="${K_REVISION:-}"
REV="${REV:-${VERCEL_GIT_COMMIT_SHA:-}}"
REV="${REV:-$(date +%s)}"

echo "Generating runtime environment (revision: ${REV})"

# Build window.__ENV from all NEXT_PUBLIC_* vars (no defaults)
json=$(node -e '
  const out = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith("NEXT_PUBLIC_") && typeof v === "string" && v.length > 0) {
      out[k] = v;
    }
  }
  process.stdout.write(JSON.stringify(out));
')

echo "Collected $(echo "$json" | node -e 'const data = JSON.parse(require("fs").readFileSync(0, "utf-8")); console.log(Object.keys(data).length)') public environment variables"

# Generate runtime-env.js (fails if template missing - this is intentional)
export RUNTIME_ENV_JSON="$json"
node <<'NODE'
const fs = require('fs');
const path = require('path');
const runtimeJson = process.env.RUNTIME_ENV_JSON || '{}';
const templatePath = path.join(process.cwd(), 'public', 'runtime-env.js.template');
const outputPath = path.join(process.cwd(), 'public', 'runtime-env.js');
const template = fs.readFileSync(templatePath, 'utf8');
fs.writeFileSync(outputPath, template.replace('$_RUNTIME_ENV_JSON', runtimeJson));
NODE

echo "Generated public/runtime-env.js"
echo "Starting Next.js server..."
exec "$@"
