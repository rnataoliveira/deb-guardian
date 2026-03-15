import type { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import {
  buildConfig,
  createOctokit,
  fetchDependabotAlerts,
  fetchCodeQLAlerts,
  fetchSecretScanningAlerts,
} from '@dep-guardian/core';
import type { AlertSeverity } from '@dep-guardian/core';

function bar(count: number, max: number, width = 20): string {
  const filled = max > 0 ? Math.round((count / max) * width) : 0;
  return chalk.green('█'.repeat(filled)) + chalk.dim('░'.repeat(width - filled));
}

export function statusCommand(program: Command): void {
  program
    .command('status [repo]')
    .description('Show current security status of a repository')
    .option('-p, --path <dir>', 'Local path to repo', process.cwd())
    .option('-t, --token <token>', 'GitHub token')
    .option('--json', 'Output as JSON')
    .action(async (repo: string | undefined, opts: {
      path: string;
      token?: string;
      json?: boolean;
    }) => {
      const spinner = opts.json ? null : ora('Fetching status...').start();

      try {
        const config = buildConfig({ repo, repoPath: opts.path, token: opts.token, validate: false });
        const octokit = createOctokit(config.githubToken);

        const [dependabot, codeql, secrets] = await Promise.all([
          fetchDependabotAlerts(octokit, config.repo).catch(() => []),
          fetchCodeQLAlerts(octokit, config.repo).catch(() => []),
          fetchSecretScanningAlerts(octokit, config.repo).catch(() => []),
        ]);

        if (spinner) spinner.stop();

        const bySev: Record<AlertSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const a of dependabot) bySev[a.severity]++;

        const data = {
          repo: config.repo,
          dependabot: { total: dependabot.length, bySeverity: bySev },
          codeql: codeql.length,
          secrets: secrets.length,
        };

        if (opts.json) {
          console.log(JSON.stringify(data, null, 2));
          return;
        }

        const total = dependabot.length + codeql.length + secrets.length;
        const criticalCount = bySev.critical ?? 0;
        const highCount = bySev.high ?? 0;
        const overallHealth = total === 0
          ? chalk.green('HEALTHY')
          : criticalCount > 0 || secrets.length > 0
            ? chalk.bgRed.white(' CRITICAL ')
            : highCount > 0
              ? chalk.red('AT RISK')
              : chalk.yellow('ATTENTION NEEDED');

        console.log();
        console.log(chalk.bold(`Security Status — ${chalk.cyan(config.repo)}`));
        console.log(`Overall: ${overallHealth}`);
        console.log();

        const maxSev = Math.max(...Object.values(bySev));

        console.log(chalk.bold('Dependabot Alerts'));
        const sevOrder: AlertSeverity[] = ['critical', 'high', 'medium', 'low'];
        for (const sev of sevOrder) {
          const count = bySev[sev] ?? 0;
          if (count > 0 || sev === 'critical' || sev === 'high') {
            const countStr = count > 0 ? chalk.bold(String(count)) : chalk.dim('0');
            console.log(`  ${sev.padEnd(8)} ${bar(count, maxSev || 1)} ${countStr}`);
          }
        }
        console.log();

        console.log(chalk.bold('Other Findings'));
        console.log(`  CodeQL findings:  ${codeql.length > 0 ? chalk.yellow(codeql.length) : chalk.dim('0')}`);
        console.log(`  Exposed secrets:  ${secrets.length > 0 ? chalk.bgRed.white(` ${secrets.length} `) : chalk.dim('0')}`);
        console.log();

        if (total > 0) {
          console.log(`Run ${chalk.cyan('dep-guardian fix')} to auto-fix minor/patch vulnerabilities`);
        }
      } catch (err) {
        spinner?.fail(chalk.red(String(err)));
        process.exit(1);
      }
    });
}
