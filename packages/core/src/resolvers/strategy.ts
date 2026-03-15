import semver from 'semver';
import type { Octokit } from '@octokit/rest';
import type {
  AnalysedAlert,
  FixStrategy,
  VersionChangeType,
  TransitivePath,
  DepGraph,
} from '../types.js';
import { isCoreDep } from '../config.js';
import { findTransitivePaths } from './transitive-tracer.js';
import { fetchChangelog } from '../github/client.js';

// ─── npm registry ─────────────────────────────────────────────────────────────

interface PackumentVersion {
  version: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface Packument {
  name: string;
  'dist-tags': { latest: string };
  versions: Record<string, PackumentVersion>;
}

async function fetchPackument(name: string): Promise<Packument | null> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (!res.ok) return null;
    return await res.json() as Packument;
  } catch {
    return null;
  }
}

function sortedVersions(packument: Packument): string[] {
  return Object.keys(packument.versions)
    .filter((v) => semver.valid(v) !== null)
    .sort((a, b) => semver.compare(a, b));
}

// ─── Version change classification ───────────────────────────────────────────

export function classifyVersionChange(from: string, to: string): VersionChangeType {
  const fromClean = semver.coerce(from)?.version;
  const toClean = semver.coerce(to)?.version;
  if (!fromClean || !toClean) return 'unknown';
  if (semver.major(toClean) > semver.major(fromClean)) return 'major';
  if (semver.minor(toClean) > semver.minor(fromClean)) return 'minor';
  return 'patch';
}

// ─── Specifier building ───────────────────────────────────────────────────────

export function buildProposedSpecifier(currentSpecifier: string, newVersion: string): string {
  const trimmed = currentSpecifier.trim();
  // Preserve range prefix: ^, ~, >=, >, exact
  if (trimmed.startsWith('>=')) return `>=${newVersion}`;
  if (trimmed.startsWith('^')) return `^${newVersion}`;
  if (trimmed.startsWith('~')) return `~${newVersion}`;
  if (trimmed === '*' || trimmed === 'latest' || trimmed === 'x') return trimmed;
  // Exact version
  return newVersion;
}

// ─── Find safe version of a direct dep that ships a safe transitive ───────────

async function findSafeOwnerVersion(
  ownerName: string,
  currentOwnerVersion: string,
  transitiveName: string,
  minSafeTransitiveVersion: string
): Promise<{ version: string; confidence: 'certain' | 'high' | 'low' } | null> {
  const packument = await fetchPackument(ownerName);
  if (!packument) return null;

  const candidates = sortedVersions(packument).filter(
    (v) => semver.gte(v, semver.coerce(currentOwnerVersion)?.version ?? currentOwnerVersion)
  );

  for (const candidateVersion of candidates) {
    const candidatePkg = packument.versions[candidateVersion];
    if (!candidatePkg) continue;

    const transitiveSpecifier =
      candidatePkg.dependencies?.[transitiveName] ??
      candidatePkg.devDependencies?.[transitiveName];

    if (!transitiveSpecifier) continue;

    // Check if the specifier's minimum satisfies the required safe version
    const minSatisfying = semver.minVersion(transitiveSpecifier);
    if (!minSatisfying) continue;

    const minSafe = semver.coerce(minSafeTransitiveVersion)?.version ?? minSafeTransitiveVersion;

    if (semver.gte(minSatisfying.version, minSafe)) {
      return { version: candidateVersion, confidence: 'certain' };
    }

    // Specifier lower bound is below safe but upper bound might be ok
    // e.g. ">=6.0.0 <7.0.0" with minSafe=6.5.0 — the range CAN resolve to safe
    const maxSatisfying = semver.maxSatisfying(
      // We'd need all transitive versions to check this; use heuristic
      [minSafe, minSatisfying.version],
      transitiveSpecifier
    );
    if (maxSatisfying && semver.gte(maxSatisfying, minSafe)) {
      return { version: candidateVersion, confidence: 'high' };
    }
  }

  return null;
}

// ─── Strategy builder ─────────────────────────────────────────────────────────

export async function buildFixStrategies(
  alerts: AnalysedAlert[],
  graph: DepGraph,
  repo: string,
  octokit: Octokit
): Promise<FixStrategy[]> {
  const strategies: FixStrategy[] = [];

  for (const alert of alerts) {
    // CodeQL findings → manual review
    if (alert.codeqlFindings && alert.codeqlFindings.length > 0 && !alert.packageName) {
      strategies.push({
        kind: 'manual-review',
        alert,
        confidence: 'certain',
        skipReason: 'CodeQL structural finding — requires manual code review',
      });
      continue;
    }

    // Secret scanning → manual review
    if (alert.secretFindings && alert.secretFindings.length > 0 && !alert.packageName) {
      strategies.push({
        kind: 'manual-review',
        alert,
        confidence: 'certain',
        skipReason: 'Secret scanning finding — requires immediate manual remediation',
      });
      continue;
    }

    const { packageName, patchedVersion } = alert;
    if (!packageName) continue;

    // No fix available upstream
    if (patchedVersion === null) {
      strategies.push({
        kind: 'no-fix-available',
        alert,
        confidence: 'certain',
        skipReason: 'No patched version published yet',
      });
      continue;
    }

    // Find the package in the dep graph
    const instances = graph.all.get(packageName) ?? [];
    if (instances.length === 0) {
      // Package not installed — alert might be stale
      strategies.push({
        kind: 'no-fix-available',
        alert,
        confidence: 'low',
        skipReason: `Package ${packageName} not found in dependency graph — alert may be stale`,
      });
      continue;
    }

    // Determine if any instance is a direct dep
    const directInstance = graph.direct.get(packageName);

    if (directInstance) {
      // It's a direct dep — bump it directly
      const currentVersion = directInstance.version;
      const targetVersion = (semver.coerce(patchedVersion)?.version ?? patchedVersion) as string;
      const changeType = classifyVersionChange(currentVersion, targetVersion);
      const proposedSpecifier = buildProposedSpecifier(directInstance.specifier, targetVersion);
      const isCore = isCoreDep(packageName);

      if (changeType === 'major' || isCore) {
        const changelog = await fetchChangelog(octokit, repo, packageName, currentVersion, targetVersion).catch(() => null);
        strategies.push({
          kind: 'alert-major-change',
          alert,
          location: {
            packageName,
            currentSpecifier: directInstance.specifier,
            section: directInstance.section,
            kind: 'direct',
          },
          targetPackage: packageName,
          currentSpecifier: directInstance.specifier,
          proposedSpecifier,
          proposedVersion: targetVersion,
          versionChangeType: changeType,
          confidence: 'certain',
          changelogExcerpt: changelog?.excerpt,
          migrationGuideUrl: changelog?.url,
        });
      } else {
        strategies.push({
          kind: 'bump-direct',
          alert,
          location: {
            packageName,
            currentSpecifier: directInstance.specifier,
            section: directInstance.section,
            kind: 'direct',
          },
          targetPackage: packageName,
          currentSpecifier: directInstance.specifier,
          proposedSpecifier,
          proposedVersion: targetVersion,
          versionChangeType: changeType,
          confidence: 'certain',
        });
      }
    } else {
      // It's a transitive dep — find the direct ancestor(s)
      const paths = findTransitivePaths(graph, packageName);

      if (paths.length === 0) {
        strategies.push({
          kind: 'no-fix-available',
          alert,
          confidence: 'low',
          skipReason: `Could not trace ${packageName} to any direct dependency`,
        });
        continue;
      }

      // Deduplicate paths by directAncestor
      const uniqueOwners = new Map<string, TransitivePath>();
      for (const path of paths) {
        uniqueOwners.set(path.directAncestor.name, path);
      }

      for (const [ownerName, transPath] of uniqueOwners) {
        const ownerNode = transPath.directAncestor;

        // isPeer — skip, not ours to fix
        if (ownerNode.isPeer) {
          strategies.push({
            kind: 'skip-peer',
            alert,
            confidence: 'certain',
            skipReason: `${ownerName} is a peer dependency — cannot be updated automatically`,
            transitiveChain: transPath,
          });
          continue;
        }

        const minSafe = semver.coerce(patchedVersion ?? '0.0.0')?.version ?? patchedVersion ?? '0.0.0';
        const safeOwner = await findSafeOwnerVersion(
          ownerName,
          ownerNode.version,
          packageName,
          minSafe
        );

        if (!safeOwner) {
          strategies.push({
            kind: 'no-fix-available',
            alert,
            confidence: 'low',
            skipReason: `No published version of ${ownerName} ships ${packageName} >= ${minSafe}`,
            transitiveChain: transPath,
          });
          continue;
        }

        const currentOwnerVersion = ownerNode.version;
        const changeType = classifyVersionChange(currentOwnerVersion, safeOwner.version);
        const proposedSpecifier = buildProposedSpecifier(ownerNode.specifier, safeOwner.version);
        const isCore = isCoreDep(ownerName);

        if (changeType === 'major' || isCore) {
          const changelog = await fetchChangelog(octokit, repo, ownerName, currentOwnerVersion, safeOwner.version).catch(() => null);
          strategies.push({
            kind: 'alert-major-change',
            alert,
            location: {
              packageName: ownerName,
              currentSpecifier: ownerNode.specifier,
              section: ownerNode.section,
              kind: 'direct',
            },
            targetPackage: ownerName,
            currentSpecifier: ownerNode.specifier,
            proposedSpecifier,
            proposedVersion: safeOwner.version,
            safeOwnerVersion: safeOwner.version,
            versionChangeType: changeType,
            transitiveChain: transPath,
            confidence: safeOwner.confidence,
            changelogExcerpt: changelog?.excerpt,
            migrationGuideUrl: changelog?.url,
          });
        } else {
          strategies.push({
            kind: 'bump-owner',
            alert,
            location: {
              packageName: ownerName,
              currentSpecifier: ownerNode.specifier,
              section: ownerNode.section,
              kind: 'direct',
            },
            targetPackage: ownerName,
            currentSpecifier: ownerNode.specifier,
            proposedSpecifier,
            proposedVersion: safeOwner.version,
            safeOwnerVersion: safeOwner.version,
            versionChangeType: changeType,
            transitiveChain: transPath,
            confidence: safeOwner.confidence,
          });
        }
      }
    }
  }

  return strategies;
}

// ─── Alert deduplication ──────────────────────────────────────────────────────

export function deduplicateAlerts(raw: import('../types.js').RawAlert[]): AnalysedAlert[] {
  const map = new Map<string, AnalysedAlert>();

  for (const alert of raw) {
    if (!alert.packageName && !alert.ruleId && !alert.secretType) continue;

    const key = alert.packageName
      ? `${alert.packageName}:${alert.ghsaId ?? alert.cve ?? alert.summary.slice(0, 40)}`
      : alert.ruleId
        ? `codeql:${alert.ruleId}:${alert.location?.path ?? ''}`
        : `secret:${alert.secretType ?? alert.id}`;

    const existing = map.get(key);
    if (existing) {
      if (!existing.sources.includes(alert.source)) existing.sources.push(alert.source);
      if (alert.githubAlertNumber !== undefined) {
        const nums = existing.githubAlertNumbers[alert.source] ?? [];
        nums.push(alert.githubAlertNumber);
        existing.githubAlertNumbers[alert.source] = nums;
      }
      // Take the most conservative (highest) patched version
      if (
        alert.patchedVersion &&
        existing.patchedVersion &&
        semver.gt(
          semver.coerce(alert.patchedVersion)?.version ?? '0.0.0',
          semver.coerce(existing.patchedVersion)?.version ?? '0.0.0'
        )
      ) {
        existing.patchedVersion = alert.patchedVersion;
      } else if (alert.patchedVersion && !existing.patchedVersion) {
        existing.patchedVersion = alert.patchedVersion;
      }
    } else {
      const analysed: AnalysedAlert = {
        key,
        sources: [alert.source],
        githubAlertNumbers: alert.githubAlertNumber !== undefined
          ? { [alert.source]: [alert.githubAlertNumber] }
          : {},
        severity: alert.severity,
        summary: alert.summary,
        references: alert.url ? [alert.url] : [],
        packageName: alert.packageName,
        vulnerableRange: alert.vulnerableRange,
        patchedVersion: alert.patchedVersion,
        ghsaId: alert.ghsaId,
        cve: alert.cve,
      };

      if (alert.source === 'codeql' && alert.location) {
        analysed.codeqlFindings = [{
          ruleId: alert.ruleId ?? '',
          ruleName: alert.ruleName ?? '',
          severity: alert.severity,
          location: alert.location,
          url: alert.url,
          alertNumber: alert.githubAlertNumber ?? 0,
        }];
      }

      if (alert.source === 'secret-scanning') {
        analysed.secretFindings = [{
          secretType: alert.secretType ?? '',
          secretTypeDisplay: alert.secretTypeDisplay ?? alert.secretType ?? '',
          alertNumber: alert.githubAlertNumber ?? 0,
          url: alert.url,
        }];
      }

      map.set(key, analysed);
    }
  }

  return Array.from(map.values());
}
