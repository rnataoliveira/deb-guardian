# @rntpkgs/dep-guardian-core

The engine behind `@rntpkgs/dep-guardian`. Use this package if you want to integrate dep-guardian into your own tooling, scripts, or CI pipelines programmatically.

## Install

```bash
npm install @rntpkgs/dep-guardian-core
```

## Quick start

```ts
import { run, buildConfig } from '@rntpkgs/dep-guardian-core';

const summary = await run(
  buildConfig({
    repo: 'owner/repo',
    token: process.env.GITHUB_TOKEN,
    repoPath: '/path/to/local/clone',
  }),
  (event) => console.log(event.type)   // optional progress handler
);

console.log(`Fixed: ${summary.fixesApplied}`);
console.log(`PRs:   ${summary.createdPrs.map(p => p.url).join(', ')}`);
```

## API

### `buildConfig(options)`

Resolves configuration from options, environment variables, and `dep-guardian.config.json` if present.

```ts
import { buildConfig } from '@rntpkgs/dep-guardian-core';

const config = buildConfig({
  repo: 'owner/repo',           // defaults to git remote origin
  repoPath: process.cwd(),      // local checkout path
  token: process.env.GH_TOKEN,  // falls back to GITHUB_TOKEN, then `gh auth token`
  dryRun: false,
  sources: ['dependabot', 'npm-audit'],
  validate: true,               // false = skip lint/build/test
});
```

### `run(config, onProgress?)`

Runs the full fix pipeline and returns a `RunSummary`.

```ts
import { run } from '@rntpkgs/dep-guardian-core';
import type { ProgressEvent, RunSummary } from '@rntpkgs/dep-guardian-core';

const summary: RunSummary = await run(config, (event: ProgressEvent) => {
  if (event.type === 'fix-applied') {
    console.log(`Fixed ${event.strategy.targetPackage}`);
  }
  if (event.type === 'pr-created') {
    console.log(`PR: ${event.url}`);
  }
});
```

#### Progress events

| Event type | Properties |
|---|---|
| `fetching-alerts` | `source` |
| `alerts-fetched` | `source`, `count` |
| `building-graph` | — |
| `graph-built` | `directCount`, `transitiveCount` |
| `planning-strategies` | `alertCount` |
| `strategy-planned` | `strategy` |
| `applying-fix` | `strategy` |
| `fix-applied` | `strategy`, `verified` |
| `fix-rolled-back` | `strategy`, `error` |
| `validating` | `step` |
| `validation-done` | `passed` |
| `creating-pr` | — |
| `pr-created` | `number`, `url` |
| `creating-issue` | `title` |
| `issue-created` | `number`, `url` |
| `done` | `summary` |

### `RunSummary`

```ts
interface RunSummary {
  repo: string;
  startedAt: Date;
  finishedAt: Date;
  totalAlerts: number;
  alertsBySource: Record<AlertSource, number>;
  alertsBySeverity: Record<AlertSeverity, number>;
  fixesApplied: number;
  fixesVerified: number;
  fixesRolledBack: number;
  fixesSkipped: number;
  validation?: ValidationResult;
  createdPrs: CreatedPr[];
  createdIssues: CreatedIssue[];
  manualReviewRequired: AnalysedAlert[];
  secretsFound: SecretFinding[];
  errors: string[];
}
```

### Individual utilities

```ts
import {
  createOctokit,
  fetchDependabotAlerts,
  fetchCodeQLAlerts,
  fetchSecretScanningAlerts,
  runNpmAudit,
  deduplicateAlerts,
  buildDepGraph,
  buildFixStrategies,
  isCoreDep,
} from '@rntpkgs/dep-guardian-core';

// Use individual pieces in your own pipeline
const octokit = createOctokit(token);
const alerts = await fetchDependabotAlerts(octokit, 'owner/repo');
const graph = buildDepGraph('/path/to/repo');
const strategies = await buildFixStrategies(
  deduplicateAlerts(alerts),
  graph,
  'owner/repo',
  octokit
);
```

### `isCoreDep(name)`

Returns `true` for packages classified as core dependencies (react, next, express, typescript, etc.) — these always require explicit human approval before updating.

```ts
import { isCoreDep } from '@rntpkgs/dep-guardian-core';

isCoreDep('react')      // true
isCoreDep('express')    // true
isCoreDep('lodash')     // false
```

## Types

All types are exported from the main entry point:

```ts
import type {
  GuardianConfig,
  RunSummary,
  RawAlert,
  AnalysedAlert,
  FixStrategy,
  FixResult,
  DepGraph,
  DepNode,
  TransitivePath,
  ValidationResult,
  AlertSource,
  AlertSeverity,
  VersionChangeType,
} from '@rntpkgs/dep-guardian-core';
```

## License

MIT
