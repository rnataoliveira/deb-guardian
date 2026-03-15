import type { Command } from 'commander';
import chalk from 'chalk';
import ora, { type Ora } from 'ora';
import {
  buildConfig,
  createOctokit,
  fetchDependabotAlerts,
  fetchCodeQLAlerts,
  fetchSecretScanningAlerts,
  runNpmAudit,
  deduplicateAlerts,
  buildDepGraph,
  buildFixStrategies,
} from '@dep-guardian/core';
import type { RawAlert, GuardianConfig, DepGraph, AlertSeverity } from '@dep-guardian/core';

const SEVERITY_COLOR: Record<AlertSeverity, (s: string) => string> = {
  critical: chalk.bgRed.white,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

function badge(severity: AlertSeverity): string {
  const color = SEVERITY_COLOR[severity];
  return color(` ${severity.toUpperCase()} `);
}

function spin(spinner: Ora | null, text: string): void {
  if (spinner) spinner.text = text;
}

export function scanCommand(program: Command): void {
  program
    .command('scan [repo]')
    .description('Scan a repository for security vulnerabilities (read-only)')
    .option('-p, --path <dir>', 'Local path to the repository checkout', process.cwd())
    .option('-t, --token <token>', 'GitHub token')
    .option('--json', 'Output results as JSON')
    .option('--source <sources>', 'Comma-separated sources: dependabot,codeql,npm-audit,secret-scanning')
    .action(async (repo: string | undefined, opts: {
      path: string;
      token?: string;
      json?: boolean;
      source?: string;
    }) => {
      try {
        const sources = opts.source
          ? (opts.source.split(',').map((s) => s.trim()) as GuardianConfig['sources'])
          : undefined;

        const config = buildConfig({
          repo,
          repoPath: opts.path,
          token: opts.token,
          validate: false,
          sources,
        });

        if (!opts.json) {
          console.log(chalk.bold(`\ndep-guardian scan — ${chalk.cyan(config.repo)}\n`));
        }

        const spinner = opts.json ? null : ora('Fetching alerts...').start();
        const octokit = createOctokit(config.githubToken);
        const rawAlerts: RawAlert[] = [];

        if (config.sources.includes('dependabot')) {
          spin(spinner, 'Fetching Dependabot alerts...');
          rawAlerts.push(...await fetchDependabotAlerts(octokit, config.repo));
        }
        if (config.sources.includes('codeql')) {
          spin(spinner, 'Fetching CodeQL alerts...');
          rawAlerts.push(...await fetchCodeQLAlerts(octokit, config.repo));
        }
        if (config.sources.includes('secret-scanning')) {
          spin(spinner, 'Fetching Secret Scanning alerts...');
          rawAlerts.push(...await fetchSecretScanningAlerts(octokit, config.repo));
        }
        if (config.sources.includes('npm-audit')) {
          spin(spinner, 'Running npm audit...');
          try {
            rawAlerts.push(...runNpmAudit(config.repoPath, config.packageManager));
          } catch {
            if (spinner) spinner.warn('npm audit failed (is the project installed?)');
          }
        }

        spin(spinner, 'Analysing dependency graph...');
        let graph: DepGraph;
        try {
          graph = buildDepGraph(config.repoPath);
        } catch {
          if (spinner) spinner.warn('Could not build dep graph — skipping transitive analysis');
          if (spinner) spinner.stop();
          if (opts.json) {
            console.log(JSON.stringify({ alerts: deduplicateAlerts(rawAlerts) }, null, 2));
          }
          return;
        }

        spin(spinner, 'Planning fix strategies...');
        const analysed = deduplicateAlerts(rawAlerts);
        const strategies = await buildFixStrategies(analysed, graph, config.repo, octokit);
        if (spinner) spinner.stop();

        if (opts.json) {
          console.log(JSON.stringify({ alerts: analysed, strategies }, null, 2));
          return;
        }

        if (analysed.length === 0) {
          console.log(chalk.green('No open vulnerabilities found.'));
          return;
        }

        // Summary counts
        const bySev: Record<AlertSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const a of analysed) bySev[a.severity]++;

        console.log(chalk.bold('Vulnerability Summary'));
        for (const [sev, count] of Object.entries(bySev) as [AlertSeverity, number][]) {
          if (count > 0) {
            console.log(`  ${badge(sev)} ${count}`);
          }
        }
        console.log();

        // Detailed list
        for (const alert of analysed) {
          const fixable = strategies.find(
            (s) => s.alert.key === alert.key && (s.kind === 'bump-direct' || s.kind === 'bump-owner')
          );
          const strategy = strategies.find((s) => s.alert.key === alert.key);

          const statusIcon = fixable
            ? chalk.green('✔ auto-fixable')
            : strategy?.kind === 'alert-major-change'
              ? chalk.yellow('⚠ major bump (issue)')
              : chalk.red('✖ no fix');

          console.log(`  ${badge(alert.severity)} ${chalk.bold(alert.packageName ?? alert.key)}`);
          console.log(`    ${alert.summary}`);
          if (alert.packageName && fixable && strategy) {
            console.log(
              `    ${chalk.dim('fix:')} ${strategy.currentSpecifier} → ${chalk.green(strategy.proposedSpecifier ?? '')}`
            );
          }
          console.log(`    ${statusIcon}`);
          console.log();
        }

        const autoFixCount = strategies.filter(
          (s) => s.kind === 'bump-direct' || s.kind === 'bump-owner'
        ).length;
        const majorCount = strategies.filter((s) => s.kind === 'alert-major-change').length;

        console.log(
          chalk.bold(`Run ${chalk.cyan('dep-guardian fix')} to auto-fix ${autoFixCount} vulnerabilit${autoFixCount === 1 ? 'y' : 'ies'}`) +
          (majorCount > 0 ? chalk.yellow(` (${majorCount} major bump${majorCount === 1 ? '' : 's'} will create GitHub issues)`) : '')
        );
      } catch (err) {
        console.error(chalk.red(`\nError: ${String(err)}`));
        process.exit(1);
      }
    });
}
