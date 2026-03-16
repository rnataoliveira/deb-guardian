"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core = require("@actions/core");
const dep_guardian_core_1 = require("@rntpkgs/dep-guardian-core");
function parseValidationSteps(input) {
    const valid = ['lint', 'typecheck', 'build', 'test'];
    return input
        .split(',')
        .map((s) => s.trim())
        .filter((s) => valid.includes(s));
}
function parseSources(input) {
    const valid = ['dependabot', 'codeql', 'npm-audit', 'secret-scanning'];
    return input
        .split(',')
        .map((s) => s.trim())
        .filter((s) => valid.includes(s));
}
function handleProgress(event) {
    switch (event.type) {
        case 'fetching-alerts':
            core.info(`Fetching ${event.source} alerts...`);
            break;
        case 'alerts-fetched':
            core.info(`${event.source}: ${event.count} alerts found`);
            break;
        case 'building-graph':
            core.info('Building dependency graph...');
            break;
        case 'graph-built':
            core.info(`Graph built: ${event.directCount} direct, ${event.transitiveCount} transitive deps`);
            break;
        case 'planning-strategies':
            core.info(`Planning fix strategies for ${event.alertCount} alerts...`);
            break;
        case 'strategy-planned':
            core.debug(`Strategy: ${event.strategy.kind} for ${event.strategy.targetPackage ?? event.strategy.alert.key}`);
            break;
        case 'applying-fix': {
            const s = event.strategy;
            core.info(`Applying fix: ${s.targetPackage} ${s.currentSpecifier} → ${s.proposedSpecifier}`);
            break;
        }
        case 'fix-applied':
            core.info(`Fixed: ${event.strategy.targetPackage} (verified: ${event.verified})`);
            break;
        case 'fix-rolled-back':
            core.warning(`Rolled back ${event.strategy.targetPackage}: ${event.error}`);
            break;
        case 'validating':
            core.info(`Validating: ${event.step}...`);
            break;
        case 'validation-done':
            core.info(`Validation ${event.passed ? 'passed' : 'failed'}`);
            break;
        case 'creating-pr':
            core.info('Creating pull request...');
            break;
        case 'pr-created':
            core.info(`PR created: ${event.url}`);
            break;
        case 'creating-issue':
            core.info(`Creating issue: ${event.title}`);
            break;
        case 'issue-created':
            core.info(`Issue created: ${event.url}`);
            break;
        case 'done':
            // handled below
            break;
    }
}
async function main() {
    try {
        const token = core.getInput('github-token', { required: true });
        const repo = core.getInput('repo');
        const repoPath = core.getInput('path') || process.cwd();
        const dryRun = core.getInput('dry-run') === 'true';
        const majorBumpMode = (core.getInput('major-bump-mode') || 'issue');
        const sourcesInput = core.getInput('sources') || 'dependabot,codeql,npm-audit,secret-scanning';
        const validateInput = core.getInput('validate') || 'lint,typecheck,build,test';
        const protectedInput = core.getInput('protected');
        const baseBranch = core.getInput('base-branch');
        const config = (0, dep_guardian_core_1.buildConfig)({
            repo: repo || undefined,
            repoPath,
            token,
            dryRun,
            sources: parseSources(sourcesInput),
            validate: true,
        });
        config.majorBumpMode = majorBumpMode;
        config.validate = parseValidationSteps(validateInput);
        if (protectedInput)
            config.protected = protectedInput.split(',').map((s) => s.trim());
        if (baseBranch)
            config.baseBranch = baseBranch;
        core.startGroup('dep-guardian run');
        const summary = await (0, dep_guardian_core_1.run)(config, handleProgress);
        core.endGroup();
        // Set outputs
        core.setOutput('fixes-applied', String(summary.fixesApplied));
        if (summary.createdPrs.length > 0) {
            core.setOutput('pr-url', summary.createdPrs[0]?.url ?? '');
        }
        if (summary.createdIssues.length > 0) {
            core.setOutput('issues-created', summary.createdIssues.map((i) => i.url).join(','));
        }
        // Secrets are always a hard failure
        if (summary.secretsFound.length > 0) {
            core.setFailed(`${summary.secretsFound.length} exposed secret(s) detected. Revoke and rotate them immediately.`);
            return;
        }
        // Report errors but don't fail the action if fixes were made
        for (const err of summary.errors) {
            core.warning(err);
        }
        if (summary.fixesApplied === 0 && summary.totalAlerts > 0) {
            core.warning(`${summary.totalAlerts} open vulnerabilities found but none could be auto-fixed. ` +
                'Check created issues for major bumps that require manual review.');
        }
        core.info(`Done. Fixed: ${summary.fixesApplied}, Skipped: ${summary.fixesSkipped}`);
    }
    catch (err) {
        core.setFailed(err instanceof Error ? err.message : String(err));
    }
}
main();
//# sourceMappingURL=main.js.map