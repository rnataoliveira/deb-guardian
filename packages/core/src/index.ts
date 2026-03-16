import { execFileSync } from 'node:child_process';
import type { Octokit } from '@octokit/rest';
import type {
  GuardianConfig,
  RunSummary,
  FixStrategy,
  SecretFinding,
  AnalysedAlert,
} from './types.js';
import { createOctokit, fetchDependabotAlerts, fetchCodeQLAlerts, fetchSecretScanningAlerts, createPr, createIssue, findExistingDepGuardianIssue, getDefaultBranch } from './github/client.js';
import { runNpmAudit } from './analyzers/npm-audit.js';
import { buildDepGraph, buildDepGraphFromNpmLs } from './resolvers/transitive-tracer.js';
import { deduplicateAlerts, buildFixStrategies } from './resolvers/strategy.js';
import { applyFix } from './resolvers/fixer.js';
import { runValidationPipeline } from './validators/pipeline.js';
import {
  buildFixPrBody,
  buildMajorBumpIssueBody,
  buildPrTitle,
  buildMajorBumpIssueTitle,
  buildBranchName,
} from './github/pr-builder.js';

export type {
  GuardianConfig,
  RunSummary,
  FixStrategy,
  AnalysedAlert,
  RawAlert,
  DepGraph,
  AlertSeverity,
  AlertSource,
  ValidationResult,
} from './types.js';
export { buildConfig, isCoreDep } from './config.js';
export { createOctokit, fetchDependabotAlerts, fetchCodeQLAlerts, fetchSecretScanningAlerts } from './github/client.js';
export { runNpmAudit } from './analyzers/npm-audit.js';
export { deduplicateAlerts, buildFixStrategies } from './resolvers/strategy.js';
export { buildDepGraph, buildDepGraphFromNpmLs } from './resolvers/transitive-tracer.js';

// ─── Progress events ──────────────────────────────────────────────────────────

export type ProgressEvent =
  | { type: 'fetching-alerts'; source: string }
  | { type: 'alerts-fetched'; count: number; source: string }
  | { type: 'building-graph' }
  | { type: 'graph-built'; directCount: number; transitiveCount: number }
  | { type: 'planning-strategies'; alertCount: number }
  | { type: 'strategy-planned'; strategy: FixStrategy }
  | { type: 'applying-fix'; strategy: FixStrategy }
  | { type: 'fix-applied'; strategy: FixStrategy; verified: boolean }
  | { type: 'fix-rolled-back'; strategy: FixStrategy; error: string }
  | { type: 'validating'; step: string }
  | { type: 'validation-done'; passed: boolean }
  | { type: 'creating-pr' }
  | { type: 'pr-created'; url: string; number: number }
  | { type: 'creating-issue'; title: string }
  | { type: 'issue-created'; url: string; number: number }
  | { type: 'done'; summary: RunSummary };

export type ProgressHandler = (event: ProgressEvent) => void;

// ─── Git helpers ──────────────────────────────────────────────────────────────

function hasUncommittedChanges(repoPath: string): boolean {
  try {
    const out = execFileSync('git', ['status', '--porcelain'], {
      cwd: repoPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

function createBranch(repoPath: string, branchName: string): void {
  execFileSync('git', ['checkout', '-b', branchName], { cwd: repoPath, stdio: 'pipe' });
}

function stageAndCommit(repoPath: string, message: string): void {
  execFileSync('git', ['add', 'package.json', 'package-lock.json'], {
    cwd: repoPath,
    stdio: 'pipe',
  });
  execFileSync('git', ['commit', '-m', message], { cwd: repoPath, stdio: 'pipe' });
}

function pushBranch(repoPath: string, branchName: string): void {
  execFileSync('git', ['push', 'origin', branchName], { cwd: repoPath, stdio: 'pipe' });
}

// ─── Main orchestrator ────────────────────────────────────────────────────────

export async function run(
  config: GuardianConfig,
  onProgress?: ProgressHandler
): Promise<RunSummary> {
  const emit = (event: ProgressEvent) => onProgress?.(event);
  const startedAt = new Date();
  const errors: string[] = [];

  // Check for uncommitted changes before we start modifying anything
  if (!config.dryRun && hasUncommittedChanges(config.repoPath)) {
    throw new Error(
      'Working directory has uncommitted changes. Commit or stash them before running dep-guardian.'
    );
  }

  const octokit: Octokit = createOctokit(config.githubToken);

  // ── 1. Fetch alerts from all configured sources
  const rawAlerts: import('./types.js').RawAlert[] = [];

  const fetchTasks: Promise<void>[] = [];

  if (config.sources.includes('dependabot')) {
    fetchTasks.push((async () => {
      emit({ type: 'fetching-alerts', source: 'dependabot' });
      try {
        const alerts = await fetchDependabotAlerts(octokit, config.repo);
        emit({ type: 'alerts-fetched', count: alerts.length, source: 'dependabot' });
        rawAlerts.push(...alerts);
      } catch (err) {
        errors.push(`Dependabot: ${String(err)}`);
      }
    })());
  }

  if (config.sources.includes('codeql')) {
    fetchTasks.push((async () => {
      emit({ type: 'fetching-alerts', source: 'codeql' });
      try {
        const alerts = await fetchCodeQLAlerts(octokit, config.repo);
        emit({ type: 'alerts-fetched', count: alerts.length, source: 'codeql' });
        rawAlerts.push(...alerts);
      } catch (err) {
        errors.push(`CodeQL: ${String(err)}`);
      }
    })());
  }

  if (config.sources.includes('secret-scanning')) {
    fetchTasks.push((async () => {
      emit({ type: 'fetching-alerts', source: 'secret-scanning' });
      try {
        const alerts = await fetchSecretScanningAlerts(octokit, config.repo);
        emit({ type: 'alerts-fetched', count: alerts.length, source: 'secret-scanning' });
        rawAlerts.push(...alerts);
      } catch (err) {
        errors.push(`Secret scanning: ${String(err)}`);
      }
    })());
  }

  if (config.sources.includes('npm-audit')) {
    fetchTasks.push((async () => {
      emit({ type: 'fetching-alerts', source: 'npm-audit' });
      try {
        const alerts = runNpmAudit(config.repoPath, config.packageManager);
        emit({ type: 'alerts-fetched', count: alerts.length, source: 'npm-audit' });
        rawAlerts.push(...alerts);
      } catch (err) {
        errors.push(`npm audit: ${String(err)}`);
      }
    })());
  }

  await Promise.all(fetchTasks);

  // ── 2. Deduplicate and analyse
  const analysedAlerts = deduplicateAlerts(rawAlerts);

  if (config.maxAlerts) {
    analysedAlerts.splice(config.maxAlerts);
  }

  // ── 3. Build dependency graph
  emit({ type: 'building-graph' });
  let graph: import('./types.js').DepGraph;
  try {
    graph = buildDepGraph(config.repoPath);
  } catch {
    // Fallback to npm ls
    graph = buildDepGraphFromNpmLs(config.repoPath, config.packageManager);
  }
  emit({
    type: 'graph-built',
    directCount: graph.direct.size,
    transitiveCount: graph.all.size - graph.direct.size,
  });

  // ── 4. Build strategies
  emit({ type: 'planning-strategies', alertCount: analysedAlerts.length });
  const allStrategies = await buildFixStrategies(analysedAlerts, graph, config.repo, octokit);
  allStrategies.forEach((s) => emit({ type: 'strategy-planned', strategy: s }));

  // Separate auto-fixable from major/manual
  const autoFixable = allStrategies.filter(
    (s) => s.kind === 'bump-direct' || s.kind === 'bump-owner'
  );
  const majorChanges = allStrategies.filter((s) => s.kind === 'alert-major-change');
  const skipped = allStrategies.filter(
    (s) => s.kind === 'no-fix-available' || s.kind === 'skip-peer' || s.kind === 'manual-review'
  );

  // Apply protected package filter
  const protected_ = new Set(config.protected ?? []);
  const toFix = autoFixable.filter((s) => !protected_.has(s.targetPackage ?? ''));
  const skippedProtected = autoFixable.filter((s) => protected_.has(s.targetPackage ?? ''));
  skipped.push(...skippedProtected);

  // ── 5. Apply fixes
  const fixResults: import('./types.js').FixResult[] = [];
  let branchName: string | null = null;

  if (toFix.length > 0 && !config.dryRun) {
    branchName = buildBranchName();
    createBranch(config.repoPath, branchName);
  }

  for (const strategy of toFix) {
    emit({ type: 'applying-fix', strategy });
    const result = await applyFix(strategy, config.repoPath, config.packageManager, config.dryRun);
    fixResults.push(result);

    if (result.applied) {
      emit({ type: 'fix-applied', strategy, verified: result.verified });
    } else {
      emit({ type: 'fix-rolled-back', strategy, error: result.error ?? 'unknown' });
    }
  }

  const appliedFixes = fixResults.filter((r) => r.applied);

  // ── 6. Validate
  let validation: import('./types.js').ValidationResult | null = null;

  if (appliedFixes.length > 0 && config.validate.length > 0 && !config.dryRun) {
    config.validate.forEach((step) => emit({ type: 'validating', step }));
    validation = runValidationPipeline(config.repoPath, config.validate, config.scripts);
    emit({ type: 'validation-done', passed: validation.passed });
  }

  // ── 7. Commit and create PR
  const createdPrs: import('./types.js').CreatedPr[] = [];
  const createdIssues: import('./types.js').CreatedIssue[] = [];

  if (appliedFixes.length > 0 && branchName && !config.dryRun) {
    const fixCount = appliedFixes.length;
    const severities = appliedFixes.map((r) => r.strategy.alert.severity);
    const commitMsg = `fix(security): resolve ${fixCount} vulnerabilit${fixCount === 1 ? 'y' : 'ies'} via dep-guardian`;

    stageAndCommit(config.repoPath, commitMsg);
    pushBranch(config.repoPath, branchName);

    emit({ type: 'creating-pr' });

    const baseBranch = config.baseBranch || (await getDefaultBranch(octokit, config.repo));
    const codeqlAlerts = analysedAlerts.filter((a) => a.codeqlFindings && a.codeqlFindings.length > 0);
    const secretAlerts = analysedAlerts.flatMap((a) => a.secretFindings ?? []);

    const prBody = buildFixPrBody(fixResults, skipped, codeqlAlerts, secretAlerts, validation);
    const prTitle = buildPrTitle(fixCount, severities);

    const pr = await createPr(octokit, {
      repo: config.repo,
      title: prTitle,
      body: prBody,
      head: branchName,
      base: baseBranch,
    });

    createdPrs.push({ kind: 'fix-pr', number: pr.number, url: pr.url, branchName, title: prTitle });
    emit({ type: 'pr-created', url: pr.url, number: pr.number });
  }

  // ── 8. Create issues for major bumps (skip if one already exists for the package)
  if (majorChanges.length > 0 && config.majorBumpMode !== 'skip' && !config.dryRun) {
    for (const strategy of majorChanges) {
      const packageName = strategy.targetPackage ?? strategy.alert.packageName ?? '';

      // Deduplication: skip if an open dep-guardian issue already exists for this package
      const existing = await findExistingDepGuardianIssue(octokit, config.repo, packageName);
      if (existing) {
        createdIssues.push({ kind: 'major-bump-issue', number: existing.number, url: existing.url, title: buildMajorBumpIssueTitle(strategy) });
        continue;
      }

      emit({ type: 'creating-issue', title: buildMajorBumpIssueTitle(strategy) });
      const issueBody = buildMajorBumpIssueBody(strategy);
      const issue = await createIssue(octokit, {
        repo: config.repo,
        title: buildMajorBumpIssueTitle(strategy),
        body: issueBody,
        labels: ['dep-guardian', 'security', 'major-update'],
      });
      createdIssues.push({ kind: 'major-bump-issue', number: issue.number, url: issue.url, title: buildMajorBumpIssueTitle(strategy) });
      emit({ type: 'issue-created', url: issue.url, number: issue.number });
    }
  }

  // ── 9. Build summary
  const summary: RunSummary = {
    repo: config.repo,
    startedAt,
    finishedAt: new Date(),
    totalAlerts: analysedAlerts.length,
    alertsBySource: {
      dependabot: rawAlerts.filter((a) => a.source === 'dependabot').length,
      codeql: rawAlerts.filter((a) => a.source === 'codeql').length,
      'npm-audit': rawAlerts.filter((a) => a.source === 'npm-audit').length,
      'secret-scanning': rawAlerts.filter((a) => a.source === 'secret-scanning').length,
    },
    alertsBySeverity: {
      critical: analysedAlerts.filter((a) => a.severity === 'critical').length,
      high: analysedAlerts.filter((a) => a.severity === 'high').length,
      medium: analysedAlerts.filter((a) => a.severity === 'medium').length,
      low: analysedAlerts.filter((a) => a.severity === 'low').length,
      info: analysedAlerts.filter((a) => a.severity === 'info').length,
    },
    strategiesPlanned: allStrategies.length,
    fixesApplied: appliedFixes.length,
    fixesVerified: fixResults.filter((r) => r.verified).length,
    fixesRolledBack: fixResults.filter((r) => r.rolledBack).length,
    fixesSkipped: skipped.length,
    validation: validation ?? undefined,
    createdPrs,
    createdIssues,
    manualReviewRequired: analysedAlerts.filter(
      (a) => (a.codeqlFindings?.length ?? 0) > 0 && !a.packageName
    ),
    secretsFound: analysedAlerts.flatMap((a) => a.secretFindings ?? []),
    errors,
  };

  emit({ type: 'done', summary });
  return summary;
}
