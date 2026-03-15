# dep-guardian

Automated security fixer for npm projects. Reads Dependabot, CodeQL, Secret Scanning, and `npm audit` alerts from a GitHub repository and applies real dependency fixes — no `overrides`, no workarounds.

## How it works

| Alert type | What dep-guardian does |
|---|---|
| Minor / patch vulnerability | Updates `package.json`, runs install, validates, opens a PR |
| Major version bump required | Opens a GitHub Issue with changelog and migration notes — never auto-applies |
| Transitive dependency | Finds the direct dep that owns it, updates that to a version shipping a safe transitive |
| CodeQL finding | Surfaces it in the PR body — requires manual code review |
| Exposed secret | Fails loudly, lists all findings — requires immediate manual action |

## Packages

| Package | Description |
|---|---|
| [`@rntpkgs/dep-guardian`](packages/cli) | Global CLI — `dg scan`, `dg fix`, `dg status`, `dg init` |
| [`@rntpkgs/dep-guardian-core`](packages/core) | Engine — programmatic API, importable in your own tooling |
| [`@rntpkgs/dep-guardian-action`](packages/action) | GitHub Action — drop into any workflow |

## Quick start

```bash
npm install -g @rntpkgs/dep-guardian
export GITHUB_TOKEN=ghp_...

dg scan owner/repo     # see what would be fixed
dg fix owner/repo      # fix it and open a PR
```

## Repository structure

```
packages/
  core/     Engine: alert fetching, dep graph, fix strategies, validation
  cli/      CLI wrapper: Commander-based interface
  action/   GitHub Action wrapper: reads action inputs, calls core
.github/
  workflows/
    dep-guardian.yml   Scheduled security run (every Monday)
    release.yml        Publishes to npm on git tag push
```

## Contributing

```bash
npm install
npm run build      # core → cli → action (order matters)
npm run clean      # removes dist/ and .tsbuildinfo
```

## License

MIT
