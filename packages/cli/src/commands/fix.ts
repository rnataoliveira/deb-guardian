import type { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { run, buildConfig } from '@dep-guardian/core';
import type { ProgressEvent, GuardianConfig } from '@dep-guardian/core';

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function handleProgress(event: ProgressEvent, spinner: ReturnType<typeof ora>): void {
  switch (event.type) {
    case 'fetching-alerts':
      spinner.text = `Fetching ${event.source} alerts...`;
      break;
    case 'alerts-fetched':
      spinner.text = `${event.source}: ${chalk.yellow(event.count)} alerts`;
      break;
    case 'building-graph':
      spinner.text = 'Building dependency graph...';
      break;
    case 'graph-built':
      spinner.text = `Graph: ${event.directCount} direct, ${event.transitiveCount} transitive deps`;
      break;
    case 'planning-strategies':
      spinner.text = `Planning fixes for ${event.alertCount} alerts...`;
      break;
    case 'applying-fix': {
      const s = event.strategy;
      spinner.text = `Fixing ${chalk.bold(s.targetPackage)}: ${s.currentSpecifier} → ${chalk.green(s.proposedSpecifier ?? '')}`;
      break;
    }
    case 'fix-applied':
      spinner.succeed(
        `Fixed ${chalk.bold(event.strategy.targetPackage)} ` +
        (event.verified ? chalk.dim('(verified)') : chalk.yellow('(unverified)'))
      );
      spinner.start();
      break;
    case 'fix-rolled-back':
      spinner.warn(
        `Rolled back ${chalk.bold(event.strategy.targetPackage)}: ${chalk.red(event.error)}`
      );
      spinner.start();
      break;
    case 'validating':
      spinner.text = `Running ${event.step}...`;
      break;
    case 'validation-done':
      if (event.passed) {
        spinner.succeed('All validation checks passed');
      } else {
        spinner.warn('Some validation checks failed (see PR for details)');
      }
      spinner.start();
      break;
    case 'creating-pr':
      spinner.text = 'Creating pull request...';
      break;
    case 'pr-created':
      spinner.succeed(`PR #${event.number} created: ${chalk.cyan(event.url)}`);
      spinner.start();
      break;
    case 'creating-issue':
      spinner.text = `Creating issue: ${event.title}`;
      break;
    case 'issue-created':
      spinner.succeed(`Issue created: ${chalk.cyan(event.url)}`);
      spinner.start();
      break;
  }
}

export function fixCommand(program: Command): void {
  program
    .command('fix [repo]')
    .description('Scan, fix minor/patch vulnerabilities, and open a PR')
    .option('-p, --path <dir>', 'Local path to the repository checkout', process.cwd())
    .option('-t, --token <token>', 'GitHub token')
    .option('--dry-run', 'Plan fixes without modifying files or creating PRs')
    .option('--no-validate', 'Skip lint/build/test validation after fix')
    .option('--base <branch>', 'Base branch for PRs (default: repo default branch)')
    .option('--major-mode <mode>', 'What to do with major bumps: issue | pr | skip', 'issue')
    .option('--source <sources>', 'Comma-separated alert sources')
    .option('--protected <packages>', 'Comma-separated packages to never auto-fix')
    .action(async (repo: string | undefined, opts: {
      path: string;
      token?: string;
      dryRun?: boolean;
      validate: boolean;
      base?: string;
      majorMode?: 'issue' | 'pr' | 'skip';
      source?: string;
      protected?: string;
    }) => {
      const spinner = ora('Starting dep-guardian...').start();

      try {
        const sources = opts.source
          ? opts.source.split(',').map((s) => s.trim()) as GuardianConfig['sources']
          : undefined;

        const protectedPkgs = opts.protected
          ? opts.protected.split(',').map((s) => s.trim())
          : undefined;

        const config = buildConfig({
          repo,
          repoPath: opts.path,
          token: opts.token,
          dryRun: opts.dryRun,
          validate: opts.validate,
          sources,
        });

        if (opts.base) config.baseBranch = opts.base;
        if (opts.majorMode) config.majorBumpMode = opts.majorMode;
        if (protectedPkgs) config.protected = protectedPkgs;

        if (!opts.dryRun) {
          console.log(chalk.bold(`\ndep-guardian fix — ${chalk.cyan(config.repo)}\n`));
        } else {
          console.log(chalk.bold(`\ndep-guardian fix (DRY RUN) — ${chalk.cyan(config.repo)}\n`));
        }

        const summary = await run(config, (event) => handleProgress(event, spinner));
        spinner.stop();

        // ── Summary output
        console.log();
        console.log(chalk.bold('Summary'));
        console.log(`  Alerts:   ${chalk.yellow(summary.totalAlerts)} total`);
        console.log(`  Fixed:    ${chalk.green(summary.fixesApplied)} applied, ${summary.fixesVerified} verified`);

        if (summary.fixesRolledBack > 0) {
          console.log(`  Rolled back: ${chalk.red(summary.fixesRolledBack)}`);
        }
        if (summary.fixesSkipped > 0) {
          console.log(`  Skipped:  ${chalk.dim(summary.fixesSkipped)}`);
        }

        if (summary.createdPrs.length > 0) {
          console.log();
          console.log(chalk.bold('Pull Requests'));
          for (const pr of summary.createdPrs) {
            console.log(`  ${chalk.green('✔')} #${pr.number} ${chalk.cyan(pr.url)}`);
          }
        }

        if (summary.createdIssues.length > 0) {
          console.log();
          console.log(chalk.bold('Issues (major bumps require manual review)'));
          for (const issue of summary.createdIssues) {
            console.log(`  ${chalk.yellow('⚠')} #${issue.number} ${chalk.cyan(issue.url)}`);
          }
        }

        if (summary.manualReviewRequired.length > 0) {
          console.log();
          console.log(chalk.bold('Manual Review Required'));
          for (const a of summary.manualReviewRequired) {
            console.log(`  ${chalk.red('✖')} ${a.summary}`);
          }
        }

        if (summary.secretsFound.length > 0) {
          console.log();
          console.log(chalk.bgRed.white.bold(' SECRETS FOUND — REVOKE IMMEDIATELY '));
          for (const s of summary.secretsFound) {
            console.log(`  ${chalk.red(s.secretTypeDisplay)} — ${chalk.cyan(s.url)}`);
          }
        }

        if (summary.validation) {
          console.log();
          console.log(chalk.bold('Validation'));
          for (const step of summary.validation.steps) {
            const icon = step.passed ? chalk.green('✔') : chalk.red('✖');
            console.log(`  ${icon} ${step.name} (${formatDuration(step.durationMs)})`);
            if (!step.passed) {
              const lines = step.output.split('\n').slice(-10);
              for (const line of lines) {
                console.log(`    ${chalk.dim(line)}`);
              }
            }
          }
        }

        if (summary.errors.length > 0) {
          console.log();
          console.log(chalk.bold('Errors'));
          for (const err of summary.errors) {
            console.log(`  ${chalk.red('!')} ${err}`);
          }
        }

        console.log();
        const exitCode = summary.fixesApplied === 0 && summary.totalAlerts > 0 ? 1 : 0;
        process.exit(exitCode);
      } catch (err) {
        spinner.fail(chalk.red(String(err)));
        process.exit(1);
      }
    });
}
