// ─── Alert Sources ─────────────────────────────────────────────────────────────

export type AlertSource = 'dependabot' | 'codeql' | 'npm-audit' | 'secret-scanning';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertState = 'open' | 'fixed' | 'dismissed';

/** Raw alert as returned by GitHub API or npm audit, before any analysis */
export interface RawAlert {
  id: string;
  source: AlertSource;
  githubAlertNumber?: number;
  severity: AlertSeverity;
  state: AlertState;
  summary: string;
  url: string;
  // Dependency-specific fields (Dependabot + npm audit)
  packageName?: string;
  ecosystem?: string;
  vulnerableRange?: string;       // e.g. "< 1.2.3"
  patchedVersion?: string | null; // null = no fix available yet
  ghsaId?: string;
  cve?: string;
  // CodeQL-specific
  ruleId?: string;
  ruleName?: string;
  location?: CodeQLLocation;
  // Secret scanning-specific
  secretType?: string;
  secretTypeDisplay?: string;
  resolvedAt?: string;
}

export interface CodeQLLocation {
  path: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

/** Alert after deduplication and cross-source merging */
export interface AnalysedAlert {
  /** Dedup key: `${packageName}:${ghsaId ?? cve ?? ruleId}` */
  key: string;
  sources: AlertSource[];
  githubAlertNumbers: Partial<Record<AlertSource, number[]>>;
  severity: AlertSeverity;
  summary: string;
  references: string[];
  // Dependency-specific
  packageName?: string;
  vulnerableRange?: string;
  patchedVersion?: string | null;
  ghsaId?: string;
  cve?: string;
  // CodeQL-specific
  codeqlFindings?: CodeQLFinding[];
  // Secret scanning
  secretFindings?: SecretFinding[];
}

export interface CodeQLFinding {
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  location: CodeQLLocation;
  url: string;
  alertNumber: number;
}

export interface SecretFinding {
  secretType: string;
  secretTypeDisplay: string;
  alertNumber: number;
  url: string;
  resolvedAt?: string;
}

// ─── Dependency Graph ─────────────────────────────────────────────────────────

export type DepKind = 'direct' | 'transitive';
export type DepSection = 'dependencies' | 'devDependencies' | 'peerDependencies' | 'optionalDependencies';

export interface DepNode {
  name: string;
  /** Resolved installed version */
  version: string;
  /** Specifier from parent's package.json, e.g. "^4.17.1" */
  specifier: string;
  kind: DepKind;
  section: DepSection;
  /** node_modules path key, e.g. "node_modules/express/node_modules/qs" */
  lockfilePath: string;
  parents: string[];
  isDev: boolean;
  isPeer: boolean;
  isOptional: boolean;
}

export interface DepGraph {
  /** Direct deps from package.json */
  direct: Map<string, DepNode>;
  /** All nodes indexed by name → all installed instances */
  all: Map<string, DepNode[]>;
  /** lockfilePath → DepNode */
  byPath: Map<string, DepNode>;
}

/** Describes the chain from a direct dep to a vulnerable transitive dep */
export interface TransitivePath {
  /** The vulnerable transitive package */
  vulnerable: DepNode;
  /** Ordered ancestor chain: [directDep, intermediate?, ..., vulnerable] */
  chain: DepNode[];
  /** chain[0] — always a direct dep in package.json */
  directAncestor: DepNode;
}

// ─── Dependency Location ──────────────────────────────────────────────────────

export interface DependencyLocation {
  packageName: string;
  currentSpecifier: string;
  section: DepSection;
  kind: DepKind;
}

// ─── Fix Strategies ───────────────────────────────────────────────────────────

export type VersionChangeType = 'major' | 'minor' | 'patch' | 'unknown';

export type FixStrategyKind =
  | 'bump-direct'              // Vulnerable pkg IS a direct dep — bump it
  | 'bump-owner'               // Update the direct dep that owns the transitive
  | 'alert-major-change'       // Fix requires a major bump → open issue/PR asking user
  | 'no-fix-available'         // No published version fixes it yet
  | 'manual-review'            // CodeQL/Secret — code-level change required
  | 'skip-peer';               // Peer dep, not ours to fix

export interface FixStrategy {
  kind: FixStrategyKind;
  alert: AnalysedAlert;
  location?: DependencyLocation;
  /** The package.json entry to modify (always a direct dep) */
  targetPackage?: string;
  currentSpecifier?: string;
  proposedSpecifier?: string;
  proposedVersion?: string;     // resolved concrete version
  versionChangeType?: VersionChangeType;
  transitiveChain?: TransitivePath;
  /** For bump-owner: minimum version of direct dep that ships safe transitive */
  safeOwnerVersion?: string;
  confidence: 'certain' | 'high' | 'low';
  skipReason?: string;
  /** Fetched changelog excerpt for major bumps */
  changelogExcerpt?: string;
  migrationGuideUrl?: string;
}

// ─── Fix Result ───────────────────────────────────────────────────────────────

export interface FixResult {
  strategy: FixStrategy;
  applied: boolean;
  rolledBack: boolean;
  error?: string;
  /** Verified the vulnerable package version is no longer present post-fix */
  verified: boolean;
  packageJsonBefore: string;
  packageJsonAfter: string | undefined;
}

// ─── Validation ───────────────────────────────────────────────────────────────

export type ValidationStepName = 'lint' | 'typecheck' | 'build' | 'test';

export interface ValidationStep {
  name: ValidationStepName;
  command: string;
  passed: boolean;
  durationMs: number;
  output: string;
  exitCode: number;
}

export interface ValidationResult {
  passed: boolean;
  steps: ValidationStep[];
  totalDurationMs: number;
}

// ─── PR / Issue ───────────────────────────────────────────────────────────────

export type PrOrIssueKind = 'fix-pr' | 'major-bump-issue';

export interface CreatedPr {
  kind: 'fix-pr';
  number: number;
  url: string;
  branchName: string;
  title: string;
}

export interface CreatedIssue {
  kind: 'major-bump-issue';
  number: number;
  url: string;
  title: string;
}

// ─── Run Summary ──────────────────────────────────────────────────────────────

export interface RunSummary {
  repo: string;
  startedAt: Date;
  finishedAt: Date;
  totalAlerts: number;
  alertsBySource: Record<AlertSource, number>;
  alertsBySeverity: Record<AlertSeverity, number>;
  strategiesPlanned: number;
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

// ─── Config ───────────────────────────────────────────────────────────────────

export type PackageManager = 'npm' | 'yarn' | 'pnpm';

export interface GuardianConfig {
  /** owner/repo */
  repo: string;
  /** Local path to the repository checkout */
  repoPath: string;
  githubToken: string;
  packageManager: PackageManager;
  /** Default branch to target for PRs */
  baseBranch: string;
  /** Which alert sources to check */
  sources: AlertSource[];
  /** Auto-approve minor/patch; prompt or skip for major */
  autoFixMinorPatch: boolean;
  /** Create PR/Issue for major bumps instead of prompting interactively */
  majorBumpMode: 'issue' | 'pr' | 'skip';
  /** Validation steps to run after fix */
  validate: ValidationStepName[];
  /** Custom commands override (e.g. { lint: "eslint src" }) */
  scripts?: Partial<Record<ValidationStepName, string>>;
  dryRun: boolean;
  /** Packages to never auto-fix (always requires human approval) */
  protected?: string[];
  /** Max alerts to process per run */
  maxAlerts?: number;
}
