# Project Status: MCP Inspector

## Current Version

- **Version**: 1.22.14 (published to npm as "@bryan-thompson/inspector-assessment")

**Technical Details:**
- Root cause: Workspace packages incorrectly listed as npm dependencies caused ETARGET errors when versions mismatched
- The `files` array physically bundles workspace builds in the tarball - no npm resolution needed
- Validation script checks: no workspace deps, version consistency, files array, build directories

**Commits:**
- b4bb5aa fix: add safeguards against workspace dependency bug

**Next Steps:**
- Consider adding the verify-publish workflow to CI pipeline
- Monitor for any other publishing issues

**Notes:**
- All 1468 tests passing
- Validation script passes all 4 checks
- Changes pushed to origin/main

---

## 2026-01-03: Published v1.22.8 - Annotation Inference Fix

**Summary:** Published v1.22.8 with the annotation inference fix to npm.

**Session Focus:** npm release v1.22.8 - Publishing the annotation inference confidence guard fix

**Changes Made:**
- Modified: package.json, client/package.json, server/package.json, cli/package.json (version 1.22.7 -> 1.22.8)
- Tag created: v1.22.8

**Key Decisions:**
- Patch release (1.22.8) since this is a bug fix with no breaking changes
- Published all 4 workspace packages to maintain version consistency

**Technical Details:**
- Pushed fix commit 6627915 to origin/main
- Bumped version using `npm version patch` (auto-syncs workspaces)
- Built all packages
- Published via `npm run publish-all`
- Pushed v1.22.8 tag to origin

**Results:**
- All 4 packages published successfully:
  - @bryan-thompson/inspector-assessment@1.22.8
  - @bryan-thompson/inspector-assessment-client@1.22.8
  - @bryan-thompson/inspector-assessment-server@1.22.8
  - @bryan-thompson/inspector-assessment-cli@1.22.8

**Next Steps:**
- Monitor for any edge cases in production usage
- Update CHANGELOG.md with v1.22.8 release notes

**Notes:**
- This release includes the confidence guard fix from commit 6627915
- Eliminates false positive misalignments when inference confidence is low
- hardened-mcp misalignment count: 23 -> 0 after this fix

---

## 2026-01-04: Fixed Issue #16 - skip-modules Flag JSON Output

**Summary:** Fixed Issue #16 - skip-modules flag now properly omits skipped modules from JSON output and JSONL events

**Session Focus:** Bug fix for --skip-modules flag not properly excluding modules from assessment output

**Changes Made:**
- Modified: `client/src/lib/moduleScoring.ts` - Changed `calculateModuleScore()` to return `null` instead of `50` for undefined/missing results
- Modified: `client/src/services/assessment/AssessmentOrchestrator.ts` - Added guard in `emitModuleProgress()` to skip emission when score is null
- Modified: `cli/src/assess-full.ts` - Added filter in `saveResults()` to exclude undefined module keys from JSON output
- Modified: `scripts/run-full-assessment.ts` - Applied same filter to keep in sync with CLI per CLAUDE.md requirements
- Modified: `client/src/lib/__tests__/moduleScoring.test.ts` - Updated test expectations for null return value on undefined inputs

**Key Decisions:**
- Return `null` instead of `50` for undefined results - clearer semantics for "not run"
- Completely omit skipped modules from JSON (user preference) rather than including with SKIPPED status
- Filter at both event emission and JSON output levels for comprehensive fix

**Technical Details:**
- Issue: --skip-modules functionality flag was implemented but skipped modules still appeared in JSON output with default scores
- Root cause: `calculateModuleScore()` returned 50 for undefined inputs, and no filtering existed at output level
- Fix applied at three levels: scoring returns null, events not emitted for null scores, JSON excludes undefined keys

**Results:**
- Published as npm v1.22.9 (issue fix) and v1.22.10 (added missing commander dependency)
- All 1468 tests passing
- Issue #16 commented with fix details

**Next Steps:**
- Monitor for any downstream issues with mcp-auditor consuming the new format
- Consider adding integration test for --skip-modules behavior

**Notes:**
- Fix maintains backwards compatibility for consumers expecting module data
- Users explicitly opting out of modules via --skip-modules now get clean JSON without those module keys
- Both CLI binary and local development script updated to stay in sync per project requirements

---

## 2026-01-04: Fixed Critical Gap in Issue #16 Skip-Modules Fix

**Summary:** Fixed critical gap in Issue #16 skip-modules fix found by dual-agent code review - added missing null guard in run-security-assessment.ts, published v1.22.13

**Session Focus:** Code review of Issue #16 fix and addressing critical gap discovered

**Changes Made:**
- Modified: `scripts/run-security-assessment.ts` - Added null guard before `emitModuleComplete()` call

**Key Decisions:**
- Used dual-agent code review (inspector-assessment-code-reviewer + code-reviewer-pro) for thorough analysis
- Fixed gap immediately rather than deferring to future release
- Published as v1.22.13 (patch version for bug fix)

**Technical Details:**
- Code review found that `scripts/run-security-assessment.ts` was not updated with the null guard that was added to `AssessmentOrchestrator.ts`
- This could have caused JSONL events to be emitted with `score: null` when using --skip-modules
- Dual-agent review methodology proved valuable for catching cross-file consistency issues

**Results:**
- All 1483 tests passed after fix
- Added comment to closed GitHub Issue #16 documenting the additional fix
- Published as v1.22.13

**Next Steps:**
- Monitor for any additional gaps in skip-modules handling
- Consider adding integration test for full --skip-modules workflow as suggested by reviewers

**Notes:**
- Demonstrates value of dual-agent code review for finding gaps that single-pass review might miss
- Cross-file consistency is critical when applying similar fixes to multiple locations
- The fix ensures parity between AssessmentOrchestrator.ts and run-security-assessment.ts

---

## 2026-01-04: Published v1.22.14 to npm

**Summary:** Published v1.22.14 to npm with all workspace packages synced and tests passing

**Session Focus:** Version bump, npm publish, and verification

**Changes Made:**
- Updated all package.json files to version 1.22.14 (root, client, server, cli)
- Published all 4 packages to npm registry
- Created git tag v1.22.14

**Key Decisions:**
- Used manual version sync after discovering npm version patch only bumped client
- Rebased to resolve branch divergence from earlier partial publish attempt

**Next Steps:**
- Continue with any pending feature work
- Monitor npm package downloads

**Notes:**
- All 1495 tests passing
- Package verified working via bunx command
- This was a continuation session completing the version bump that was interrupted

---

## 2026-01-04: Code Review Implementation - P1/P2 Fixes and securityTestTimeout

**Summary:** Completed comprehensive code review of inspector-assessment module, implemented all P1/P2 fixes, and documented new securityTestTimeout configuration

**Session Focus:** Code review response - implementing fixes for high and medium priority issues identified by code review agents

**Changes Made:**
- `cli/src/assess-full.ts` - Added EventEmitter configuration to prevent listener warnings during full security assessments
- `client/src/services/assessment/AssessmentOrchestrator.ts` - Added getToolCountForTesting() helper for accurate progress estimation, improved type safety
- `client/src/services/assessment/modules/BaseAssessor.ts` - Added generic type parameter `<T = unknown>` for type-safe assess() return types
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Pre-calculate exact payload counts for accurate progress, use configurable securityTestTimeout
- `client/src/lib/assessmentTypes.ts` - Added securityTestTimeout configuration option
- `docs/CLI_ASSESSMENT_GUIDE.md` - Added "Option: Security Test Timeout" section
- `docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md` - Updated BaseAssessor docs, added Pattern 6.5 (progress estimation) and Pattern 6.6 (security timeouts)
- `docs/ASSESSMENT_CATALOG.md` - Added Configuration Options section to Security Assessment

**Key Decisions:**
- Used Promise<unknown>[] instead of Promise<void>[] because assessment promises return results
- Default securityTestTimeout is 5000ms (lower than general testTimeout for faster security scans)
- Added type assertion on return statement since Partial<MCPDirectoryAssessment> doesn't guarantee required fields

**Commits:**
- fbf99ef: fix: address P1/P2 issues from code review
- 2c56f91: docs: document securityTestTimeout and progress estimation fixes

**GitHub Issues Created:**
- #19: Extract shared CLI logic to common module
- #20: Remove deprecated maxToolsToTestForErrors from config presets
- #21: Split assessmentTypes.ts into focused files
- #22: Add queue backpressure warning to concurrencyLimit
- #23: Add structured logging to AssessmentOrchestrator

**Next Steps:**
- Address P3 tech debt items as time permits (tracked in GitHub issues)
- Consider npm version bump and publish for new features

**Notes:**
- All 1495 tests passing after changes
- Build successful with no TypeScript errors

---

## 2026-01-04: Issue #19 - Deprecate Local Script in Favor of Unified CLI

**Summary:** Resolved Issue #19 by deprecating local script in favor of unified CLI, eliminating ~400 lines of duplicate code

**Session Focus:** GitHub Issue #19 - Tech Debt: Extract shared CLI logic to common module. Chose Option A (deprecate local script) instead of extraction.

**Changes Made:**
- `package.json`: Updated `assess:full` to use CLI binary with auto-build check, added `assess:full:legacy`
- `scripts/run-full-assessment.ts`: Added deprecation warning (v2.0.0 removal), TODO comment
- `CLAUDE.md`: Replaced "npm Binary / Local Script Parity" section with "Full Assessment CLI"
- `docs/CLI_ASSESSMENT_GUIDE.md`: Updated Mode 1 section, added migration note
- `CHANGELOG.md`: Added v1.22.14 release notes
- `docs/ARCHITECTURE_AND_VALUE.md`: Clarified CLI as primary component
- `docs/DVMCP_USAGE_GUIDE.md`: Updated development workflow
- `docs/REAL_TIME_PROGRESS_OUTPUT.md`: Organized Primary vs Legacy scripts

**Commits:**
- f230dc8: refactor: deprecate local script in favor of unified CLI (closes #19)
- bd18e8e: fix: address code review warnings for #19
- fe2ba53: docs: update documentation for unified CLI workflow (#19)

**Key Decisions:**
- Chose deprecation over extraction because CLI binary already has 9+ features the local script lacked
- Set removal timeline to v2.0.0 for clear migration path
- Added auto-build check so `npm run assess:full` works even if CLI not built

**Next Steps:**
- 4 remaining open issues: #20, #21, #22, #23
- Legacy script removal planned for v2.0.0

**Notes:**
- Code review by @agent-code-reviewer-pro identified 2 warnings, both fixed
- Documentation review by @agent-api-documenter found 5 files needing updates
- Issue #19 closed on GitHub with resolution comment

---
