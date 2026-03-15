import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ValidationResult, ValidationStep, ValidationStepName } from '../types.js';

interface PackageJsonScripts {
  scripts?: Record<string, string>;
}

// ─── Script detection ─────────────────────────────────────────────────────────

const SCRIPT_CANDIDATES: Record<ValidationStepName, string[]> = {
  lint: ['lint', 'eslint', 'lint:check', 'lint:ci', 'check:lint'],
  typecheck: ['typecheck', 'type-check', 'tsc', 'check:types', 'types'],
  build: ['build', 'build:prod', 'compile'],
  test: ['test', 'test:ci', 'vitest run', 'jest --ci'],
};

export function detectScripts(
  repoPath: string,
  overrides?: Partial<Record<ValidationStepName, string>>
): Partial<Record<ValidationStepName, string>> {
  const pkgPath = join(repoPath, 'package.json');
  if (!existsSync(pkgPath)) return {};

  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJsonScripts;
  const scripts = pkg.scripts ?? {};
  const result: Partial<Record<ValidationStepName, string>> = {};

  for (const [step, candidates] of Object.entries(SCRIPT_CANDIDATES) as [ValidationStepName, string[]][]) {
    if (overrides?.[step]) {
      result[step] = overrides[step];
      continue;
    }
    for (const candidate of candidates) {
      if (scripts[candidate]) {
        result[step] = `npm run ${candidate}`;
        break;
      }
    }
  }

  return result;
}

// ─── Runner ───────────────────────────────────────────────────────────────────

function runStep(
  name: ValidationStepName,
  command: string,
  repoPath: string
): ValidationStep {
  const start = Date.now();
  const [cmd, ...args] = command.split(' ');

  try {
    const output = execFileSync(cmd ?? 'npm', args, {
      cwd: repoPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    return {
      name,
      command,
      passed: true,
      durationMs: Date.now() - start,
      output: output.slice(-2000), // last 2kb
      exitCode: 0,
    };
  } catch (err: unknown) {
    const error = err as { stdout?: string; stderr?: string; status?: number };
    const output = [(error.stdout ?? ''), (error.stderr ?? '')].join('\n').trim().slice(-2000);

    return {
      name,
      command,
      passed: false,
      durationMs: Date.now() - start,
      output,
      exitCode: error.status ?? 1,
    };
  }
}

// ─── Pipeline ─────────────────────────────────────────────────────────────────

export function runValidationPipeline(
  repoPath: string,
  stepsToRun: ValidationStepName[],
  scriptOverrides?: Partial<Record<ValidationStepName, string>>
): ValidationResult {
  const detected = detectScripts(repoPath, scriptOverrides);
  const start = Date.now();
  const steps: ValidationStep[] = [];

  for (const stepName of stepsToRun) {
    const command = detected[stepName];
    if (!command) {
      // Step not found — skip silently
      continue;
    }

    const result = runStep(stepName, command, repoPath);
    steps.push(result);

    // Fail fast: stop pipeline if build fails (can't run tests without build)
    if (!result.passed && (stepName === 'build' || stepName === 'typecheck')) {
      break;
    }
  }

  return {
    passed: steps.every((s) => s.passed),
    steps,
    totalDurationMs: Date.now() - start,
  };
}
