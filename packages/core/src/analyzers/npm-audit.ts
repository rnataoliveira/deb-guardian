import { execFileSync } from 'node:child_process';
import type { RawAlert, AlertSeverity, PackageManager } from '../types.js';

// ─── npm audit --json shape (v7+) ─────────────────────────────────────────────

interface NpmAuditVia {
  source?: number;
  name?: string;
  dependency?: string;
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
  cvss?: { score: number };
}

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<NpmAuditVia | string>;
  range: string;
  nodes: string[];
  fixAvailable:
    | boolean
    | { name: string; version: string; isSemVerMajor: boolean };
}

interface NpmAuditReport {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities: Record<string, number>;
  };
}

// ─── yarn audit --json shape ──────────────────────────────────────────────────

interface YarnAuditAdvisory {
  type: 'auditAdvisory';
  data: {
    resolution: { id: number; path: string; dev: boolean };
    advisory: {
      module_name: string;
      severity: string;
      title: string;
      url: string;
      vulnerable_versions: string;
      patched_versions: string;
      cves: string[];
    };
  };
}

// ─── pnpm audit --json shape ──────────────────────────────────────────────────

interface PnpmAuditReport {
  advisories: Record<string, {
    module_name: string;
    severity: string;
    title: string;
    url: string;
    vulnerable_versions: string;
    patched_versions: string;
    cves: string[];
    findings: Array<{ version: string; paths: string[] }>;
  }>;
}

function normalizeSeverity(s: string): AlertSeverity {
  const map: Record<string, AlertSeverity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    moderate: 'medium',
    low: 'low',
    info: 'info',
  };
  return map[s.toLowerCase()] ?? 'low';
}

function runAudit(repoPath: string, pm: PackageManager): string {
  const commands: Record<PackageManager, [string, string[]]> = {
    npm: ['npm', ['audit', '--json']],
    yarn: ['yarn', ['audit', '--json']],
    pnpm: ['pnpm', ['audit', '--json']],
  };

  const [cmd, args] = commands[pm];
  try {
    return execFileSync(cmd, args, {
      cwd: repoPath,
      stdio: ['pipe', 'pipe', 'pipe'],
      encoding: 'utf8',
      // npm audit exits with non-zero if vulnerabilities found — that's expected
    });
  } catch (err: unknown) {
    const error = err as { stdout?: string; status?: number };
    // npm audit returns exit code 1 when vulnerabilities exist — stdout still has JSON
    if (error.stdout) return error.stdout;
    throw new Error(`${pm} audit failed: ${String(err)}`);
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

function parseNpmAudit(raw: string): RawAlert[] {
  const report = JSON.parse(raw) as NpmAuditReport;
  const alerts: RawAlert[] = [];
  let idx = 0;

  for (const [, vuln] of Object.entries(report.vulnerabilities)) {
    // Only emit one alert per vulnerable package, using the deepest `via` advisory
    const advisory = vuln.via.find((v): v is NpmAuditVia => typeof v === 'object');
    if (!advisory) continue;

    const fixAvailable = vuln.fixAvailable;
    let patchedVersion: string | null = null;
    if (typeof fixAvailable === 'object') {
      patchedVersion = fixAvailable.version;
    } else if (fixAvailable === false) {
      patchedVersion = null;
    }

    alerts.push({
      id: `npm-audit:${idx++}`,
      source: 'npm-audit',
      severity: normalizeSeverity(vuln.severity),
      state: 'open',
      summary: advisory.title ?? `Vulnerability in ${vuln.name}`,
      url: advisory.url ?? `https://www.npmjs.com/advisories`,
      packageName: vuln.name,
      ecosystem: 'npm',
      vulnerableRange: vuln.range,
      patchedVersion,
    });
  }

  return alerts;
}

function parseYarnAudit(raw: string): RawAlert[] {
  const alerts: RawAlert[] = [];
  // yarn audit --json outputs one JSON object per line (NDJSON)
  const lines = raw.split('\n').filter(Boolean);
  let idx = 0;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line) as YarnAuditAdvisory;
      if (entry.type !== 'auditAdvisory') continue;
      const { advisory } = entry.data;

      alerts.push({
        id: `npm-audit:${idx++}`,
        source: 'npm-audit',
        severity: normalizeSeverity(advisory.severity),
        state: 'open',
        summary: advisory.title,
        url: advisory.url,
        packageName: advisory.module_name,
        ecosystem: 'npm',
        vulnerableRange: advisory.vulnerable_versions,
        patchedVersion: advisory.patched_versions === '<0.0.0' ? null : advisory.patched_versions,
        cve: advisory.cves[0],
      });
    } catch {
      // skip malformed lines
    }
  }

  return alerts;
}

function parsePnpmAudit(raw: string): RawAlert[] {
  const report = JSON.parse(raw) as PnpmAuditReport;
  const alerts: RawAlert[] = [];
  let idx = 0;

  for (const [, adv] of Object.entries(report.advisories)) {
    alerts.push({
      id: `npm-audit:${idx++}`,
      source: 'npm-audit',
      severity: normalizeSeverity(adv.severity),
      state: 'open',
      summary: adv.title,
      url: adv.url,
      packageName: adv.module_name,
      ecosystem: 'npm',
      vulnerableRange: adv.vulnerable_versions,
      patchedVersion: adv.patched_versions === '<0.0.0' ? null : adv.patched_versions,
      cve: adv.cves[0],
    });
  }

  return alerts;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function runNpmAudit(repoPath: string, pm: PackageManager): RawAlert[] {
  const raw = runAudit(repoPath, pm);

  try {
    if (pm === 'npm') return parseNpmAudit(raw);
    if (pm === 'yarn') return parseYarnAudit(raw);
    if (pm === 'pnpm') return parsePnpmAudit(raw);
  } catch (err) {
    throw new Error(`Failed to parse ${pm} audit output: ${String(err)}`);
  }

  return [];
}
