import type { Command } from 'commander';
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';

const CONFIG_TEMPLATE = {
  repo: 'owner/repo',
  baseBranch: 'main',
  sources: ['dependabot', 'codeql', 'npm-audit', 'secret-scanning'],
  majorBumpMode: 'issue',
  validate: ['lint', 'typecheck', 'build', 'test'],
  scripts: {},
  protected: [],
  maxAlerts: 50,
};

const WORKFLOW_TEMPLATE = `name: dep-guardian

on:
  schedule:
    # Every Monday at 09:00 UTC
    - cron: '0 9 * * 1'
  workflow_dispatch:
    inputs:
      dry_run:
        description: 'Dry run (no changes)'
        type: boolean
        default: false

permissions:
  contents: write
  pull-requests: write
  issues: write
  security-events: read

jobs:
  dep-guardian:
    name: Fix security vulnerabilities
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: \${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run dep-guardian
        uses: rnataoliveira/dep-guardian@main
        with:
          github-token: \${{ secrets.GITHUB_TOKEN }}
          dry-run: \${{ inputs.dry_run || 'false' }}
          major-bump-mode: issue
`;

export function initCommand(program: Command): void {
  program
    .command('init')
    .description('Initialise dep-guardian config and GitHub Actions workflow')
    .option('-p, --path <dir>', 'Project root directory', process.cwd())
    .option('--workflow-only', 'Only create the GitHub Actions workflow')
    .option('--config-only', 'Only create dep-guardian.config.json')
    .action((opts: { path: string; workflowOnly?: boolean; configOnly?: boolean }) => {
      const configPath = join(opts.path, 'dep-guardian.config.json');
      const workflowDir = join(opts.path, '.github', 'workflows');
      const workflowPath = join(workflowDir, 'dep-guardian.yml');

      let created = 0;

      if (!opts.workflowOnly) {
        if (existsSync(configPath)) {
          console.log(chalk.yellow(`  skip  dep-guardian.config.json (already exists)`));
        } else {
          writeFileSync(configPath, JSON.stringify(CONFIG_TEMPLATE, null, 2) + '\n', 'utf8');
          console.log(chalk.green(`  create dep-guardian.config.json`));
          created++;
        }
      }

      if (!opts.configOnly) {
        if (existsSync(workflowPath)) {
          console.log(chalk.yellow(`  skip  .github/workflows/dep-guardian.yml (already exists)`));
        } else {
          try {
            mkdirSync(workflowDir, { recursive: true });
          } catch {
            // already exists
          }
          writeFileSync(workflowPath, WORKFLOW_TEMPLATE, 'utf8');
          console.log(chalk.green(`  create .github/workflows/dep-guardian.yml`));
          created++;
        }
      }

      if (created > 0) {
        console.log();
        console.log(chalk.bold('Next steps:'));
        if (!opts.workflowOnly) {
          console.log(`  1. Edit ${chalk.cyan('dep-guardian.config.json')} and set your repo name`);
        }
        console.log(`  2. Set ${chalk.cyan('GITHUB_TOKEN')} in your environment or CI secrets`);
        console.log(`  3. Run ${chalk.cyan('dep-guardian scan')} to see current vulnerabilities`);
        console.log(`  4. Run ${chalk.cyan('dep-guardian fix')} to auto-fix minor/patch issues`);
      }
    });
}
