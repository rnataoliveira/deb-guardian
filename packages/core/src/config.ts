import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execSync } from 'node:child_process';
import type { GuardianConfig, PackageManager, AlertSource, ValidationStepName } from './types.js';

// ─── Core dep classification ──────────────────────────────────────────────────
// These packages require explicit user approval for major bumps.

export const CORE_PACKAGES = new Set([
  // Frameworks
  'react', 'react-dom', 'react-router', 'react-router-dom',
  'next', 'nuxt', 'vue', '@vue/core',
  'angular', '@angular/core', '@angular/common', '@angular/router', '@angular/cli',
  'svelte', '@sveltejs/kit',
  'remix', '@remix-run/react', '@remix-run/node',
  'gatsby', 'astro',
  // Backend frameworks
  'express', 'fastify', 'koa', 'hapi', '@hapi/hapi',
  '@nestjs/core', '@nestjs/common', '@nestjs/platform-express',
  'elysia', 'hono',
  // Build tools
  'vite', 'webpack', 'webpack-cli', 'rollup', 'esbuild',
  'parcel', '@rspack/core', 'turbopack',
  // Language
  'typescript',
  // Test frameworks
  'jest', 'vitest', 'mocha', 'jasmine', '@jest/core',
  // CSS
  'tailwindcss', 'styled-components', '@emotion/react',
  // Database / ORM
  'prisma', '@prisma/client', 'typeorm', 'drizzle-orm', 'sequelize', 'mongoose',
]);

export const CORE_PREFIXES = [
  '@angular/', '@nestjs/', '@sveltejs/', '@remix-run/', '@vue/',
];

export function isCoreDep(name: string): boolean {
  if (CORE_PACKAGES.has(name)) return true;
  return CORE_PREFIXES.some((p) => name.startsWith(p));
}

// ─── Package manager detection ────────────────────────────────────────────────

export function detectPackageManager(repoPath: string): PackageManager {
  if (existsSync(join(repoPath, 'pnpm-lock.yaml'))) return 'pnpm';
  if (existsSync(join(repoPath, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

// ─── GitHub token resolution ──────────────────────────────────────────────────

export function resolveGithubToken(explicit?: string): string {
  if (explicit) return explicit;
  if (process.env['GH_TOKEN']) return process.env['GH_TOKEN'];
  if (process.env['GITHUB_TOKEN']) return process.env['GITHUB_TOKEN'];
  // Last resort: gh CLI
  try {
    const token = execSync('gh auth token', { stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim();
    if (token) return token;
  } catch {
    // gh not installed or not logged in
  }
  throw new Error(
    'No GitHub token found. Set GH_TOKEN or GITHUB_TOKEN, pass --token, or run `gh auth login`.'
  );
}

// ─── Config file loading ──────────────────────────────────────────────────────

interface ConfigFile {
  repo?: string;
  sources?: AlertSource[];
  majorBumpMode?: 'issue' | 'pr' | 'skip';
  validate?: ValidationStepName[];
  scripts?: Partial<Record<ValidationStepName, string>>;
  protected?: string[];
  maxAlerts?: number;
  baseBranch?: string;
}

function loadConfigFile(repoPath: string): ConfigFile {
  const candidates = [
    join(repoPath, 'dep-guardian.config.json'),
    join(repoPath, '.dep-guardian.json'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, 'utf8')) as ConfigFile;
      } catch {
        throw new Error(`Failed to parse config file at ${p}`);
      }
    }
  }
  return {};
}

// ─── Config builder ───────────────────────────────────────────────────────────

export interface BuildConfigOptions {
  repo?: string;
  repoPath?: string;
  token?: string;
  dryRun?: boolean;
  validate?: boolean;
  sources?: AlertSource[];
}

export function buildConfig(opts: BuildConfigOptions): GuardianConfig {
  const repoPath = resolve(opts.repoPath ?? process.cwd());
  const fileConfig = loadConfigFile(repoPath);

  const repo = opts.repo ?? fileConfig.repo ?? inferRepoFromGit(repoPath);
  if (!repo) {
    throw new Error(
      'Cannot determine repository. Pass --repo owner/repo or add "repo" to dep-guardian.config.json'
    );
  }

  return {
    repo,
    repoPath,
    githubToken: resolveGithubToken(opts.token),
    packageManager: detectPackageManager(repoPath),
    baseBranch: fileConfig.baseBranch ?? 'main',
    sources: opts.sources ?? fileConfig.sources ?? ['dependabot', 'codeql', 'npm-audit', 'secret-scanning'],
    autoFixMinorPatch: true,
    majorBumpMode: fileConfig.majorBumpMode ?? 'issue',
    validate: opts.validate === false
      ? []
      : (fileConfig.validate ?? (['lint', 'typecheck', 'build', 'test'] as ValidationStepName[])),
    scripts: fileConfig.scripts,
    dryRun: opts.dryRun ?? false,
    protected: fileConfig.protected ?? [],
    maxAlerts: fileConfig.maxAlerts,
  };
}

function inferRepoFromGit(repoPath: string): string | undefined {
  try {
    const remote = execSync('git remote get-url origin', {
      cwd: repoPath,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).toString().trim();

    // SSH: git@github.com:owner/repo.git
    const sshMatch = remote.match(/github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/);
    if (sshMatch?.[1]) return sshMatch[1];

    // HTTPS: https://github.com/owner/repo.git
    const httpsMatch = remote.match(/github\.com\/([^/]+\/[^/]+?)(?:\.git)?$/);
    if (httpsMatch?.[1]) return httpsMatch[1];
  } catch {
    // not a git repo or no remote
  }
  return undefined;
}
