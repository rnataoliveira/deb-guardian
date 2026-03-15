# @rntpkgs/dep-guardian

Automated security fixer for npm projects. Reads Dependabot, CodeQL, Secret Scanning, and `npm audit` alerts from GitHub and applies real dependency fixes — updating `package.json` properly, validating the result, and opening a pull request.

## Why

Most security tools tell you what is wrong. This one fixes it.

The key difference from tools that add `overrides` or `resolutions` to `package.json`: dep-guardian traces each vulnerable package to the direct dependency that pulls it in and updates that dependency to a version that ships a safe transitive. If no such version exists, it tells you. If the fix requires a major version bump, it opens a GitHub Issue with the changelog and migration guide instead of silently breaking your app.

## Install

```bash
npm install -g @rntpkgs/dep-guardian
```

Requires Node.js >= 20 and a GitHub token with the following permissions:
- `security_events: read` (Dependabot, CodeQL, Secret Scanning)
- `contents: write` (push fix branch)
- `pull_requests: write` (open PR)
- `issues: write` (open major bump issues)

```bash
export GITHUB_TOKEN=ghp_...
# or
export GH_TOKEN=ghp_...
# or: install the GitHub CLI and run `gh auth login`
```

## Commands

### `dg scan`

Read-only audit. Shows every open vulnerability and what dep-guardian would do about it.

```bash
dg scan owner/repo
dg scan owner/repo --source dependabot,npm-audit
dg scan owner/repo --json > report.json
```

Output:
```
dep-guardian scan — owner/repo

Vulnerability Summary
   HIGH    3
   MEDIUM  1

   HIGH  qs
    Prototype Pollution in qs
    fix: ^6.5.2 → ^6.11.0 (transitive via express)
    ✔ auto-fixable

   HIGH  semver
    Regular Expression Denial of Service in semver
    fix: ^7.3.5 → ^7.5.2
    ✔ auto-fixable

   HIGH  next
    Next.js authorization bypass
    fix: ^13.0.0 → ^14.2.30
    ⚠ major bump (issue)

Run dep-guardian fix to auto-fix 2 vulnerabilities (1 major bump will create a GitHub issue)
```

### `dg fix`

Applies minor/patch fixes, validates with lint/typecheck/build/test, and opens a pull request. Creates GitHub Issues for major bumps.

```bash
dg fix owner/repo

# Options
dg fix owner/repo --dry-run               # plan only, no file changes or PRs
dg fix owner/repo --path ./local-checkout # use a local clone instead of cloning fresh
dg fix owner/repo --no-validate           # skip lint/build/test after fix
dg fix owner/repo --major-mode skip       # ignore major bumps entirely
dg fix owner/repo --major-mode pr         # open a PR for major bumps instead of an issue
dg fix owner/repo --protected react,next  # never auto-fix these packages
dg fix owner/repo --base develop          # target branch for PRs
```

The fix process:
1. Fetches all open alerts (Dependabot + CodeQL + Secret Scanning + npm audit)
2. Deduplicates across sources — takes the most conservative patched version
3. Builds the full dependency graph from `package-lock.json`
4. For each vulnerable package:
   - If it is a direct dependency → bumps it in `package.json`
   - If it is transitive → finds the direct ancestor and bumps that to a version shipping a safe transitive
   - If the fix requires a major bump → creates a GitHub Issue instead
5. Runs `npm install`
6. Verifies the vulnerable version is no longer present
7. Rolls back `package.json` if verification fails
8. Runs lint → typecheck → build → test (auto-detected from your `package.json` scripts)
9. Commits, pushes a branch, opens a PR

### `dg status`

Security health dashboard for a repository.

```bash
dg status owner/repo
dg status owner/repo --json
```

Output:
```
Security Status — owner/repo
Overall: AT RISK

Dependabot Alerts
  critical ░░░░░░░░░░░░░░░░░░░░ 0
  high     ████████████░░░░░░░░ 3
  medium   ████░░░░░░░░░░░░░░░░ 1
  low      ░░░░░░░░░░░░░░░░░░░░ 0

Other Findings
  CodeQL findings:  2
  Exposed secrets:  0
```

### `dg init`

Scaffolds a config file and a GitHub Actions workflow into the current project.

```bash
cd my-project
dg init
```

Creates:
- `dep-guardian.config.json` — config file, edit the `repo` field
- `.github/workflows/dep-guardian.yml` — runs every Monday, also manually triggerable

## Configuration

Drop a `dep-guardian.config.json` in your project root to avoid passing flags every time:

```json
{
  "repo": "owner/repo",
  "baseBranch": "main",
  "sources": ["dependabot", "codeql", "npm-audit", "secret-scanning"],
  "majorBumpMode": "issue",
  "validate": ["lint", "typecheck", "build", "test"],
  "scripts": {
    "lint": "npm run lint:ci",
    "test": "npm run test:unit"
  },
  "protected": ["react", "react-dom", "next"],
  "maxAlerts": 50
}
```

| Field | Default | Description |
|---|---|---|
| `repo` | inferred from git remote | `owner/repo` |
| `baseBranch` | `main` | Base branch for PRs |
| `sources` | all four | Alert sources to check |
| `majorBumpMode` | `issue` | `issue`, `pr`, or `skip` |
| `validate` | all four | Steps to run after fixing |
| `scripts` | auto-detected | Override auto-detected npm scripts |
| `protected` | `[]` | Packages to never auto-fix |
| `maxAlerts` | unlimited | Cap alerts processed per run |

## GitHub Action

Use dep-guardian as a GitHub Action in any repository:

```yaml
name: dep-guardian

on:
  schedule:
    - cron: '0 9 * * 1'   # every Monday at 09:00 UTC
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  issues: write
  security-events: read

jobs:
  dep-guardian:
    runs-on: ubuntu-latest
    env:
      FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: 'npm'

      - run: npm ci

      - name: Configure git
        run: |
          git config user.name "dep-guardian[bot]"
          git config user.email "dep-guardian[bot]@users.noreply.github.com"

      - uses: rnataoliveira/deb-guardian@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          major-bump-mode: issue
```

Or run `dg init` to generate this automatically.

### Action inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | required | GitHub token |
| `dry-run` | `false` | Plan only, no changes |
| `major-bump-mode` | `issue` | `issue`, `pr`, or `skip` |
| `sources` | all four | Comma-separated alert sources |
| `validate` | all four | Comma-separated validation steps |
| `protected` | `` | Comma-separated packages to never auto-fix |
| `base-branch` | repo default | Base branch for PRs |

### Action outputs

| Output | Description |
|---|---|
| `fixes-applied` | Number of vulnerabilities fixed |
| `pr-url` | URL of the created pull request |
| `issues-created` | Comma-separated URLs of issues created for major bumps |

## License

MIT
