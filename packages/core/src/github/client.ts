import { Octokit } from '@octokit/rest';
import { retry } from '@octokit/plugin-retry';
import { throttling } from '@octokit/plugin-throttling';
import type {
  RawAlert,
  AlertSeverity,
  AlertState,
  CodeQLLocation,
} from '../types.js';

const OctokitWithPlugins = Octokit.plugin(retry, throttling);

export function createOctokit(token: string): Octokit {
  return new OctokitWithPlugins({
    auth: token,
    throttle: {
      onRateLimit: (retryAfter: number, options: { method: string; url: string }, _octokit: unknown, retryCount: number) => {
        console.warn(`Rate limited on ${options.method} ${options.url}. Retrying after ${retryAfter}s (attempt ${retryCount + 1})`);
        return retryCount < 3;
      },
      onSecondaryRateLimit: (retryAfter: number, options: { method: string; url: string }, _octokit: unknown) => {
        console.warn(`Secondary rate limit on ${options.method} ${options.url}`);
        return false;
      },
    },
    retry: { doNotRetry: ['429'] },
  }) as Octokit;
}

function parseOwnerRepo(repo: string): { owner: string; repoName: string } {
  const parts = repo.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Invalid repo format "${repo}" — expected "owner/repo"`);
  }
  return { owner: parts[0], repoName: parts[1] };
}

function normalizeSeverity(s: string | null | undefined): AlertSeverity {
  const map: Record<string, AlertSeverity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    moderate: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info',
    warning: 'low',
  };
  return map[s?.toLowerCase() ?? ''] ?? 'low';
}

// ─── Dependabot ───────────────────────────────────────────────────────────────

export async function fetchDependabotAlerts(
  octokit: Octokit,
  repo: string
): Promise<RawAlert[]> {
  const { owner, repoName } = parseOwnerRepo(repo);
  const results: RawAlert[] = [];

  const iter = octokit.paginate.iterator(octokit.rest.dependabot.listAlertsForRepo, {
    owner,
    repo: repoName,
    state: 'open',
    ecosystem: 'npm',
    per_page: 100,
  });

  for await (const { data } of iter) {
    for (const alert of data) {
      const vuln = alert.security_vulnerability;
      const advisory = alert.security_advisory;
      results.push({
        id: `dependabot:${alert.number}`,
        source: 'dependabot',
        githubAlertNumber: alert.number,
        severity: normalizeSeverity(vuln?.severity),
        state: alert.state === 'open' ? 'open' : 'fixed',
        summary: advisory?.summary ?? 'Dependabot security alert',
        url: alert.html_url,
        packageName: vuln?.package?.name,
        ecosystem: vuln?.package?.ecosystem,
        vulnerableRange: vuln?.vulnerable_version_range ?? undefined,
        patchedVersion: vuln?.first_patched_version?.identifier ?? null,
        ghsaId: advisory?.ghsa_id,
        cve: advisory?.cve_id ?? undefined,
      });
    }
  }

  return results;
}

// ─── CodeQL ───────────────────────────────────────────────────────────────────

export async function fetchCodeQLAlerts(
  octokit: Octokit,
  repo: string
): Promise<RawAlert[]> {
  const { owner, repoName } = parseOwnerRepo(repo);
  const results: RawAlert[] = [];

  try {
    const iter = octokit.paginate.iterator(octokit.rest.codeScanning.listAlertsForRepo, {
      owner,
      repo: repoName,
      state: 'open' as AlertState,
      per_page: 100,
    });

    for await (const { data } of iter) {
      for (const alert of data) {
        const loc = alert.most_recent_instance?.location;
        const location: CodeQLLocation | undefined = loc
          ? {
              path: loc.path ?? '',
              startLine: loc.start_line ?? 0,
              endLine: loc.end_line ?? 0,
              startColumn: loc.start_column ?? 0,
              endColumn: loc.end_column ?? 0,
            }
          : undefined;

        results.push({
          id: `codeql:${alert.number}`,
          source: 'codeql',
          githubAlertNumber: alert.number,
          severity: normalizeSeverity(alert.rule?.severity),
          state: 'open',
          summary: alert.rule?.description ?? alert.rule?.name ?? 'CodeQL finding',
          url: alert.html_url,
          ruleId: alert.rule?.id ?? undefined,
          ruleName: alert.rule?.name ?? undefined,
          location,
        });
      }
    }
  } catch (err: unknown) {
    // Code scanning might not be enabled on the repo
    if ((err as { status?: number }).status === 404) {
      return [];
    }
    throw err;
  }

  return results;
}

// ─── Secret Scanning ──────────────────────────────────────────────────────────

export async function fetchSecretScanningAlerts(
  octokit: Octokit,
  repo: string
): Promise<RawAlert[]> {
  const { owner, repoName } = parseOwnerRepo(repo);
  const results: RawAlert[] = [];

  try {
    const iter = octokit.paginate.iterator(octokit.rest.secretScanning.listAlertsForRepo, {
      owner,
      repo: repoName,
      state: 'open',
      per_page: 100,
    });

    for await (const { data } of iter) {
      for (const alert of data) {
        results.push({
          id: `secret:${alert.number}`,
          source: 'secret-scanning',
          githubAlertNumber: alert.number,
          severity: 'critical',
          state: 'open',
          summary: `Exposed secret: ${alert.secret_type_display_name ?? alert.secret_type ?? 'unknown'}`,
          url: alert.html_url ?? `https://github.com/${repo}/security/secret-scanning`,
          secretType: alert.secret_type ?? 'unknown',
          secretTypeDisplay: alert.secret_type_display_name ?? alert.secret_type ?? 'Unknown Secret',
        });
      }
    }
  } catch (err: unknown) {
    if ((err as { status?: number }).status === 404) {
      return [];
    }
    throw err;
  }

  return results;
}

// ─── Issues ───────────────────────────────────────────────────────────────────

export interface CreateIssueParams {
  repo: string;
  title: string;
  body: string;
  labels?: string[];
}

export async function createIssue(
  octokit: Octokit,
  params: CreateIssueParams
): Promise<{ number: number; url: string }> {
  const { owner, repoName } = parseOwnerRepo(params.repo);
  const response = await octokit.rest.issues.create({
    owner,
    repo: repoName,
    title: params.title,
    body: params.body,
    labels: params.labels ?? ['dep-guardian', 'security'],
  });
  return { number: response.data.number, url: response.data.html_url };
}

// ─── PR ───────────────────────────────────────────────────────────────────────

export interface CreatePrParams {
  repo: string;
  title: string;
  body: string;
  head: string;
  base: string;
  draft?: boolean;
}

export async function createPr(
  octokit: Octokit,
  params: CreatePrParams
): Promise<{ number: number; url: string }> {
  const { owner, repoName } = parseOwnerRepo(params.repo);
  const response = await octokit.rest.pulls.create({
    owner,
    repo: repoName,
    title: params.title,
    body: params.body,
    head: params.head,
    base: params.base,
    draft: params.draft ?? false,
  });
  return { number: response.data.number, url: response.data.html_url };
}

export async function findOpenPr(
  octokit: Octokit,
  repo: string,
  head: string
): Promise<number | null> {
  const { owner, repoName } = parseOwnerRepo(repo);
  const { data } = await octokit.rest.pulls.list({
    owner,
    repo: repoName,
    head: `${owner}:${head}`,
    state: 'open',
  });
  return data[0]?.number ?? null;
}

// ─── Repository info ──────────────────────────────────────────────────────────

export async function getDefaultBranch(octokit: Octokit, repo: string): Promise<string> {
  const { owner, repoName } = parseOwnerRepo(repo);
  const { data } = await octokit.rest.repos.get({ owner, repo: repoName });
  return data.default_branch;
}

export async function fetchChangelog(
  octokit: Octokit,
  repo: string,
  packageName: string,
  fromVersion: string,
  toVersion: string
): Promise<{ excerpt: string; url: string } | null> {
  // Try to find the package's GitHub repo from npm registry
  try {
    const registryResponse = await fetch(`https://registry.npmjs.org/${packageName}`);
    if (!registryResponse.ok) return null;
    const data = await registryResponse.json() as {
      repository?: { url?: string };
      versions?: Record<string, { repository?: { url?: string } }>;
    };

    const repoUrl = data.repository?.url ?? '';
    const ghMatch = repoUrl.match(/github\.com\/([^/]+\/[^/]+?)(?:\.git)?(?:\/|$)/);
    if (!ghMatch?.[1]) return null;

    const pkgRepo = ghMatch[1];
    const { owner: pkgOwner, repoName: pkgRepoName } = parseOwnerRepo(pkgRepo);

    // Fetch latest releases
    const { data: releases } = await octokit.rest.repos.listReleases({
      owner: pkgOwner,
      repo: pkgRepoName,
      per_page: 10,
    });

    const releaseUrl = `https://github.com/${pkgRepo}/releases`;
    const relevant = releases.filter((r) => {
      const tag = r.tag_name.replace(/^v/, '');
      return tag === toVersion || tag.startsWith(toVersion.split('.')[0] ?? '');
    });

    if (relevant.length > 0 && relevant[0]) {
      const body = relevant[0].body ?? '';
      const excerpt = body.length > 500 ? body.slice(0, 500) + '...' : body;
      return { excerpt, url: relevant[0].html_url };
    }

    return { excerpt: '', url: releaseUrl };
  } catch {
    return null;
  }
}
