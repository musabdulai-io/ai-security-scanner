#!/usr/bin/env node

/**
 * Generates public/runtime-env.js for local development.
 * Mirrors the logic from entrypoint.sh so dev and production stay in sync.
 */

import fs from 'fs';
import path from 'path';

const projectRoot = process.cwd();
const templatePath = path.join(projectRoot, 'public', 'runtime-env.js.template');
const outputPath = path.join(projectRoot, 'public', 'runtime-env.js');

if (!fs.existsSync(templatePath)) {
  console.error(`[runtime-env] Missing template file at ${templatePath}`);
  process.exit(1);
}

const publicEnv = {};
for (const [key, value] of Object.entries(process.env)) {
  if (key.startsWith('NEXT_PUBLIC_') && typeof value === 'string' && value.length > 0) {
    publicEnv[key] = value;
  }
}

const template = fs.readFileSync(templatePath, 'utf8');
const result = template.replace('$_RUNTIME_ENV_JSON', JSON.stringify(publicEnv));
fs.writeFileSync(outputPath, result);

console.log(
  `[runtime-env] Wrote ${outputPath} with ${Object.keys(publicEnv).length} public env vars`,
);
