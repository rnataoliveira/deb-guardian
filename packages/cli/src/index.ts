#!/usr/bin/env node
import { program } from 'commander';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { scanCommand } from './commands/scan.js';
import { fixCommand } from './commands/fix.js';
import { statusCommand } from './commands/status.js';
import { initCommand } from './commands/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const pkg = JSON.parse(
  readFileSync(join(__dirname, '..', 'package.json'), 'utf8')
) as { version: string };

program
  .name('dep-guardian')
  .aliases(['dg'])
  .description('Automated dependency security fixer for npm projects')
  .version(pkg.version);

scanCommand(program);
fixCommand(program);
statusCommand(program);
initCommand(program);

program.parse();
