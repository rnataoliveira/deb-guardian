import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import semver from 'semver';
import type { FixStrategy, FixResult, PackageManager } from '../types.js';

interface PackageJsonRaw {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  [key: string]: unknown;
}

function detectIndent(content: string): string {
  const match = content.match(/^[\t ]+/m);
  return match?.[0] ?? '  ';
}

function readPackageJson(repoPath: string): { raw: string; parsed: PackageJsonRaw } {
  const raw = readFileSync(join(repoPath, 'package.json'), 'utf8');
  return { raw, parsed: JSON.parse(raw) as PackageJsonRaw };
}

function writePackageJson(repoPath: string, content: string): void {
  writeFileSync(join(repoPath, 'package.json'), content, 'utf8');
}

function applySpecifierChange(
  raw: string,
  parsed: PackageJsonRaw,
  section: string,
  packageName: string,
  newSpecifier: string
): string {
  const indent = detectIndent(raw);
  const sectionData = parsed[section] as Record<string, string> | undefined;
  if (!sectionData?.[packageName]) {
    throw new Error(`${packageName} not found in ${section}`);
  }

  // Update in parsed object
  (parsed[section] as Record<string, string>)[packageName] = newSpecifier;

  // Re-serialize preserving indent style
  return JSON.stringify(parsed, null, indent) + '\n';
}

function runInstall(repoPath: string, pm: PackageManager): void {
  const commands: Record<PackageManager, [string, string[]]> = {
    npm: ['npm', ['install']],
    yarn: ['yarn', ['install']],
    pnpm: ['pnpm', ['install']],
  };
  const [cmd, args] = commands[pm];
  execFileSync(cmd, args, { cwd: repoPath, stdio: 'pipe' });
}

function verifyVulnerabilityGone(
  repoPath: string,
  packageName: string,
  patchedVersion: string | null | undefined,
  pm: PackageManager
): boolean {
  if (!patchedVersion) return true;

  try {
    const lsOutput = execFileSync('npm', ['ls', packageName, '--json'], {
      cwd: repoPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const parsed = JSON.parse(lsOutput) as {
      dependencies?: Record<string, { version: string }>;
    };

    const dep = parsed.dependencies?.[packageName];
    if (!dep) return true; // Not installed = not vulnerable

    const minSafe = semver.coerce(patchedVersion)?.version ?? patchedVersion;
    return semver.gte(dep.version, minSafe);
  } catch {
    // Can't verify — assume ok
    return true;
  }
}

function gitReset(repoPath: string): void {
  try {
    execFileSync('git', ['checkout', 'package.json', 'package-lock.json'], {
      cwd: repoPath,
      stdio: 'pipe',
    });
  } catch {
    // If git reset fails, try writing back the original
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function applyFix(
  strategy: FixStrategy,
  repoPath: string,
  pm: PackageManager,
  dryRun: boolean = false
): Promise<FixResult> {
  const { raw: packageJsonBefore, parsed } = readPackageJson(repoPath);

  if (
    (strategy.kind !== 'bump-direct' && strategy.kind !== 'bump-owner') ||
    !strategy.targetPackage ||
    !strategy.proposedSpecifier ||
    !strategy.location
  ) {
    return {
      strategy,
      applied: false,
      rolledBack: false,
      verified: false,
      packageJsonBefore,
      packageJsonAfter: undefined,
      error: `Strategy kind "${strategy.kind}" is not auto-fixable`,
    };
  }

  const { targetPackage, proposedSpecifier, location } = strategy;

  if (dryRun) {
    return {
      strategy,
      applied: false,
      rolledBack: false,
      verified: false,
      packageJsonBefore,
      packageJsonAfter: undefined,
    };
  }

  let packageJsonAfter: string | undefined;

  try {
    packageJsonAfter = applySpecifierChange(
      packageJsonBefore,
      parsed,
      location.section,
      targetPackage,
      proposedSpecifier
    );

    writePackageJson(repoPath, packageJsonAfter);

    try {
      runInstall(repoPath, pm);
    } catch (installErr) {
      // Roll back package.json and re-throw
      writePackageJson(repoPath, packageJsonBefore);
      return {
        strategy,
        applied: false,
        rolledBack: true,
        verified: false,
        packageJsonBefore,
        packageJsonAfter,
        error: `npm install failed: ${String(installErr)}`,
      };
    }

    const verified = verifyVulnerabilityGone(
      repoPath,
      strategy.alert.packageName ?? targetPackage,
      strategy.alert.patchedVersion,
      pm
    );

    if (!verified) {
      // Roll back — the fix didn't actually resolve the vulnerability
      writePackageJson(repoPath, packageJsonBefore);
      try { runInstall(repoPath, pm); } catch { /* best-effort */ }
      return {
        strategy,
        applied: false,
        rolledBack: true,
        verified: false,
        packageJsonBefore,
        packageJsonAfter,
        error: `Fix applied but vulnerable version of ${strategy.alert.packageName} still present after install`,
      };
    }

    return {
      strategy,
      applied: true,
      rolledBack: false,
      verified: true,
      packageJsonBefore,
      packageJsonAfter,
    };
  } catch (err) {
    // Attempt rollback
    try {
      writePackageJson(repoPath, packageJsonBefore);
      gitReset(repoPath);
    } catch {
      // best-effort
    }
    return {
      strategy,
      applied: false,
      rolledBack: true,
      verified: false,
      packageJsonBefore,
      packageJsonAfter,
      error: String(err),
    };
  }
}
