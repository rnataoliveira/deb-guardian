import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type {
  DepGraph,
  DepNode,
  DepSection,
  TransitivePath,
  PackageManager,
} from '../types.js';

// ─── Lockfile v3 shape ────────────────────────────────────────────────────────

interface LockfilePackage {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  peer?: boolean;
  optional?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PackageLockV3 {
  lockfileVersion: number;
  packages: Record<string, LockfilePackage>;
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

// ─── Graph builder ────────────────────────────────────────────────────────────

function sectionForDep(name: string, pkg: PackageJson): DepSection {
  if (pkg.devDependencies?.[name]) return 'devDependencies';
  if (pkg.peerDependencies?.[name]) return 'peerDependencies';
  if (pkg.optionalDependencies?.[name]) return 'optionalDependencies';
  return 'dependencies';
}

function nameFromPath(lockfilePath: string): string {
  // "node_modules/foo" → "foo"
  // "node_modules/foo/node_modules/bar" → "bar"
  // "node_modules/@scope/foo" → "@scope/foo"
  const parts = lockfilePath.split('node_modules/');
  const last = parts[parts.length - 1];
  return last?.replace(/\/$/, '') ?? lockfilePath;
}

function parentPath(lockfilePath: string): string | null {
  // "node_modules/express/node_modules/qs" → "node_modules/express"
  const idx = lockfilePath.lastIndexOf('/node_modules/');
  if (idx === -1) return null;
  return lockfilePath.slice(0, idx);
}

export function buildDepGraph(repoPath: string): DepGraph {
  const pkgPath = join(repoPath, 'package.json');
  const lockPath = join(repoPath, 'package-lock.json');

  if (!existsSync(pkgPath)) {
    throw new Error(`package.json not found at ${pkgPath}`);
  }
  if (!existsSync(lockPath)) {
    throw new Error(`package-lock.json not found at ${lockPath}. Run npm install first.`);
  }

  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJson;
  const lock = JSON.parse(readFileSync(lockPath, 'utf8')) as PackageLockV3;

  if (lock.lockfileVersion < 2) {
    throw new Error(
      `package-lock.json lockfileVersion ${lock.lockfileVersion} is not supported. ` +
      'Re-run npm install with npm >= 7 to generate a v2/v3 lockfile.'
    );
  }

  const allDirectNames = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
  ]);

  const direct = new Map<string, DepNode>();
  const all = new Map<string, DepNode[]>();
  const byPath = new Map<string, DepNode>();

  for (const [lockfilePath, lockPkg] of Object.entries(lock.packages)) {
    if (lockfilePath === '') continue; // root package
    if (!lockfilePath.includes('node_modules/')) continue;

    const name = nameFromPath(lockfilePath);
    const version = lockPkg.version ?? '0.0.0';
    const isTopLevel = lockfilePath === `node_modules/${name}`;
    const isDirect = isTopLevel && allDirectNames.has(name);
    const section = isDirect ? sectionForDep(name, pkg) : 'dependencies';

    // Determine specifier from parent's dep list
    let specifier = '*';
    if (isDirect) {
      specifier = (
        pkg.dependencies?.[name] ??
        pkg.devDependencies?.[name] ??
        pkg.peerDependencies?.[name] ??
        pkg.optionalDependencies?.[name] ??
        '*'
      );
    } else {
      const pPath = parentPath(lockfilePath);
      if (pPath) {
        const parentPkg = lock.packages[pPath];
        specifier = (
          parentPkg?.dependencies?.[name] ??
          parentPkg?.devDependencies?.[name] ??
          parentPkg?.peerDependencies?.[name] ??
          parentPkg?.optionalDependencies?.[name] ??
          '*'
        );
      }
    }

    const node: DepNode = {
      name,
      version,
      specifier,
      kind: isDirect ? 'direct' : 'transitive',
      section,
      lockfilePath,
      parents: [],
      isDev: lockPkg.dev ?? false,
      isPeer: lockPkg.peer ?? false,
      isOptional: lockPkg.optional ?? false,
    };

    byPath.set(lockfilePath, node);
    if (isDirect) direct.set(name, node);

    const existing = all.get(name);
    if (existing) {
      existing.push(node);
    } else {
      all.set(name, [node]);
    }
  }

  // Build parent references
  for (const [lockfilePath, node] of byPath) {
    const pPath = parentPath(lockfilePath);
    if (pPath) {
      node.parents.push(pPath);
    }
  }

  return { direct, all, byPath };
}

// ─── Transitive tracer ────────────────────────────────────────────────────────

export function findTransitivePaths(
  graph: DepGraph,
  vulnerablePackageName: string
): TransitivePath[] {
  const instances = graph.all.get(vulnerablePackageName) ?? [];
  const results: TransitivePath[] = [];

  for (const vulnNode of instances) {
    // Walk up parent chain until we hit a direct dep
    const chains = walkToDirectAncestors(vulnNode, graph, [vulnNode]);
    results.push(...chains);
  }

  return results;
}

function walkToDirectAncestors(
  node: DepNode,
  graph: DepGraph,
  currentChain: DepNode[],
  visited: Set<string> = new Set()
): TransitivePath[] {
  if (visited.has(node.lockfilePath)) return []; // cycle guard
  visited.add(node.lockfilePath);

  if (node.kind === 'direct') {
    // The vulnerable node itself is a direct dep — degenerate case
    return [{
      vulnerable: currentChain[currentChain.length - 1] as DepNode,
      chain: [...currentChain],
      directAncestor: node,
    }];
  }

  const results: TransitivePath[] = [];

  for (const parentPath of node.parents) {
    const parentNode = graph.byPath.get(parentPath);
    if (!parentNode) continue;

    if (parentNode.kind === 'direct') {
      results.push({
        vulnerable: currentChain[currentChain.length - 1] as DepNode,
        chain: [...currentChain, parentNode],
        directAncestor: parentNode,
      });
    } else {
      const deeper = walkToDirectAncestors(
        parentNode,
        graph,
        [...currentChain, parentNode],
        new Set(visited)
      );
      results.push(...deeper);
    }
  }

  return results;
}

// ─── npm ls fallback ──────────────────────────────────────────────────────────
// Used when package-lock.json is not available (e.g. yarn/pnpm).

interface NpmLsDep {
  version?: string;
  resolved?: string;
  dependencies?: Record<string, NpmLsDep>;
  deduped?: boolean;
  peer?: boolean;
  dev?: boolean;
  optional?: boolean;
}

interface NpmLsOutput {
  name: string;
  version: string;
  dependencies?: Record<string, NpmLsDep>;
}

export function buildDepGraphFromNpmLs(repoPath: string, pm: PackageManager): DepGraph {
  const pkgPath = join(repoPath, 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJson;

  let raw: string;
  try {
    const cmd = pm === 'pnpm' ? 'pnpm' : pm === 'yarn' ? 'yarn' : 'npm';
    const args = pm === 'npm' ? ['ls', '--json', '--all'] : ['list', '--json', '--depth=Infinity'];
    raw = execFileSync(cmd, args, {
      cwd: repoPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err: unknown) {
    const error = err as { stdout?: string };
    if (error.stdout) {
      raw = error.stdout;
    } else {
      throw new Error(`Failed to run npm ls: ${String(err)}`);
    }
  }

  const lsOutput = JSON.parse(raw) as NpmLsOutput;
  const direct = new Map<string, DepNode>();
  const all = new Map<string, DepNode[]>();
  const byPath = new Map<string, DepNode>();

  const allDirectNames = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
  ]);

  function traverse(
    deps: Record<string, NpmLsDep>,
    parentPath: string,
    depth: number
  ): void {
    for (const [name, dep] of Object.entries(deps)) {
      const lp = depth === 0 ? `node_modules/${name}` : `${parentPath}/node_modules/${name}`;
      const isDirect = depth === 0 && allDirectNames.has(name);

      const node: DepNode = {
        name,
        version: dep.version ?? '0.0.0',
        specifier: isDirect
          ? (pkg.dependencies?.[name] ?? pkg.devDependencies?.[name] ?? '*')
          : '*',
        kind: isDirect ? 'direct' : 'transitive',
        section: isDirect ? sectionForDep(name, pkg) : 'dependencies',
        lockfilePath: lp,
        parents: parentPath ? [parentPath] : [],
        isDev: dep.dev ?? false,
        isPeer: dep.peer ?? false,
        isOptional: dep.optional ?? false,
      };

      byPath.set(lp, node);
      if (isDirect) direct.set(name, node);
      const existing = all.get(name);
      if (existing) existing.push(node);
      else all.set(name, [node]);

      if (dep.dependencies && !dep.deduped) {
        traverse(dep.dependencies, lp, depth + 1);
      }
    }
  }

  if (lsOutput.dependencies) {
    traverse(lsOutput.dependencies, '', 0);
  }

  return { direct, all, byPath };
}
