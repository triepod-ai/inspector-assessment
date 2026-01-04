# Project Status: MCP Inspector

## Current Version

- **Version**: 1.22.14 (published to npm as "@bryan-thompson/inspector-assessment")

**Recent Changes:**
- v1.22.14: Issue #19 - Deprecate local script in favor of unified CLI
- v1.22.12: Issue #18 - Run+analysis tool exemption (runAccessibilityAudit, etc.)
- v1.22.11: Issue #17 - Annotation and portability false positives

---

## 2026-01-04: Issue #19 - Deprecate Local Script & Unify CLI Workflow (v1.22.14)

**Summary:** Consolidated full assessment workflow by deprecating duplicate local development script and making `npm run assess:full` use the single-source-of-truth CLI binary.

**Session Focus:** Code consolidation and workflow simplification - GitHub Issue #19 aimed to eliminate ~400 lines of duplicated CLI code that had been maintained in parallel since v1.17.0.

**Problem Solved:**
- **Before**: Two separate implementations of full assessment (`cli/src/assess-full.ts` and `scripts/run-full-assessment.ts`)
- **Required**: Maintaining CLI/script parity tests and synchronized changes across both files
- **Risk**: Divergence between implementations, accidental omissions in one file or the other
- **After**: Single source of truth - CLI binary is authoritative, local script is deprecated

**Changes Made:**
- Modified `package.json`:
  - `npm run assess:full` now builds and runs CLI binary: `test -f cli/build/assess-full.js || npm run build-cli --silent && node cli/build/assess-full.js`
  - Added `npm run assess:full:legacy` for transition period (runs local script via tsx)
- Modified `scripts/run-full-assessment.ts`:
  - Added deprecation warning: "This script is deprecated. Use 'npm run assess:full' instead."
  - Added timeline: "Will be removed in v2.0.0. Migrate to 'npm run assess:full'."
  - Added TODO comment for cleanup task
- Updated `CLAUDE.md`:
  - Removed "npm Binary / Local Script Parity" section (was heavily referencing parity maintenance)
  - Replaced with "Full Assessment CLI" section explaining unified workflow
  - Documents both local development and published package usage
  - Notes legacy script availability during transition
- Updated `docs/CLI_ASSESSMENT_GUIDE.md`:
  - Added migration note to Mode 1 (Full Assessment): "Primary workflow is now unified under single CLI binary"
  - Updated source code references from `scripts/run-full-assessment.ts` to `cli/src/assess-full.ts`
  - Clarified that legacy script is available via `npm run assess:full:legacy`

**Key Benefits:**
- Eliminates 400 lines of duplicate code
- Single source of truth for full assessment logic
- No more CLI/script parity maintenance burden
- Simpler development workflow - changes go in one place
- Seamless transition - local dev script still works via legacy command
- Auto-build convenience - `npm run assess:full` builds if needed

**Backwards Compatibility:**
- `npm run assess:full:legacy` continues to work during transition
- Removal scheduled for v2.0.0 (clear 6+ month timeline)
- Deprecation warning guides users to new workflow

**Testing & Validation:**
- Both commit history reviewed (f230dc8, bd18e8e)
- Code review addressed auto-build and deprecation timeline concerns
- No new tests needed (functionality unchanged, just consolidated)

**Commits:**
- `f230dc8` refactor: deprecate local script in favor of unified CLI (closes #19)
- `bd18e8e` fix: address code review warnings for #19 (auto-build check, deprecation timeline)

**Files Modified:**
- `/home/bryan/inspector/package.json` - Updated npm script and added legacy command
- `/home/bryan/inspector/scripts/run-full-assessment.ts` - Added deprecation warning
- `/home/bryan/inspector/CLAUDE.md` - Replaced parity section with unified CLI docs
- `/home/bryan/inspector/docs/CLI_ASSESSMENT_GUIDE.md` - Updated Mode 1 with migration note

**Next Steps:**
- Plan v2.0.0 release (v1.25.0 or later) for removal of legacy script
- Update migration guide in v2.0.0 release notes
- Monitor for user feedback on deprecation timeline
- Consider adding deprecation warning to npm package README

**Notes:**
- Issue #19 closed on GitHub
- Related to earlier work on CLI/script parity (Issue #13, v1.22.1-1.22.3)
- Removes 340 lines from scripts/run-full-assessment.ts responsibility (still ~400 lines as fallback)

---

## 2026-01-04: Issue #18 Fix - Run+Analysis Tool Exemption (v1.22.12)

**Summary:** Fixed false positive where `run*` prefix incorrectly flagged audit/analysis tools as deceptive when annotated with readOnlyHint=true.

**Session Focus:** Bug fix for GitHub Issue #18 - browser-tools-mcp uses tools like `runAccessibilityAudit`, `runSEOAudit`, `runPerformanceAudit` which are genuinely read-only (they fetch analysis data, don't modify state). The pattern-matching engine flagged "run" as a state-modification keyword, incorrectly detecting deception.

**Changes Made:**
- Modified `client/src/services/assessment/modules/ToolAnnotationAssessor.ts`:
  - Added `RUN_READONLY_EXEMPT_SUFFIXES` constant with 14 analysis-related suffixes
  - Added `isRunKeywordExempt()` helper function
  - Modified `detectAnnotationDeception()` to skip flagging for run+analysis tools
  - Modified `inferBehavior()` to infer readOnly=true for run+analysis tools BEFORE pattern matching
- Added 10 new tests in `ToolAnnotationAssessor.test.ts` for exemption logic

**Exempt Suffixes:** audit, check, scan, test, mode, analyze, report, status, validate, verify, inspect, lint, benchmark, diagnostic

**Key Decision:**
- Early check in `inferBehavior()` before pattern matching ensures exemption is applied BEFORE generic "run" pattern kicks in

**Notes:**
- Commit: 9e9742d "fix: resolve false positive for run*Audit tools with readOnlyHint=true (#18)"
- Version: 1.22.12 (published to npm)
- All 1483 tests passing
- Issue #18 closed on GitHub

---

## 2026-01-03: Fixed Issue #15 - Skip-Modules Flag Not Honored for Core Modules

**Summary:** Fixed Issue #15 where --skip-modules flag was parsed but core assessment modules still executed.

**Session Focus:** Bug fix for GitHub Issue #15 - the --skip-modules CLI flag was being parsed correctly but core modules (functionality, security, documentation, errorHandling, usability) still ran because they were unconditionally instantiated and executed in AssessmentOrchestrator.ts.

**Changes Made:**
- Modified `client/src/services/assessment/AssessmentOrchestrator.ts` - Made core assessor properties optional, added conditional instantiation in constructor, added guards in parallel and sequential execution modes (+173, -135 lines)

**Key Decisions:**
- Used same pattern as extended modules (which already had conditional logic)
- Check `assessmentCategories?.moduleName !== false` for core modules
- Added optional chaining in resetAllTestCounts() and collectTotalTestCount()

**Next Steps:**
- Monitor for any edge cases with skip-modules functionality
- Consider adding unit tests specifically for skip-modules behavior

**Notes:**
- Commit: 36c78d4 "fix: honor --skip-modules flag for core assessment modules"
- All 12 AssessmentOrchestrator tests pass
- Issue #15 closed

---

## 2026-01-03: Code Review Remediation and v1.22.2 Release

**Summary:** Fixed code and documentation issues identified by code-reviewer-pro and api-documenter agents, published version 1.22.2 to npm.

**Session Focus:** Code review remediation and npm release - addressed issues found by parallel agent review using code-reviewer-pro and api-documenter agents.

**Changes Made:**
- Modified `cli/src/assess-full.ts` - Added missing `authentication: true` module to allModules object
- Modified `scripts/run-full-assessment.ts` - Added authentication + externalAPIScanner modules, synced temporal logic with cli version
- Updated `docs/JSONL_EVENTS_ALGORITHMS.md` - Corrected event count from 12 to 13
- Updated `docs/JSONL_EVENTS_INTEGRATION.md` - Corrected event count from 12 to 13 (two locations)
- Updated `docs/ASSESSMENT_CATALOG.md` - Updated from 11 to 17 modules, added complete module reference table
- Updated `docs/CLI_ASSESSMENT_GUIDE.md` - Updated to 17 modules with Core/Compliance/Advanced categories

**Key Decisions:**
- Used parallel agent review (code-reviewer-pro + api-documenter) for comprehensive coverage
- Organized modules into three categories: Core (5), Compliance (6), Advanced (6)
- Published as patch version (1.22.1 to 1.22.2) since these are bug fixes, not new features

**Validation Results:**
- All 1444 tests passed (62 suites)
- npm package published successfully as @bryan-thompson/inspector-assessment@1.22.2

**Next Steps:**
- Consider adding unit tests for module filtering logic (suggestion from code review)
- Consider deriving allModules from ASSESSMENT_CATEGORY_METADATA (single source of truth)

**Notes:**
- Code review identified missing authentication module that could cause silent failures with --only-modules authentication
- Documentation had outdated event counts (12 vs actual 13) and module counts (11 vs actual 17)
- Binary/local script parity restored between cli/src/assess-full.ts and scripts/run-full-assessment.ts

---

## 2026-01-03: Code Review Remediation - CLI Parity and Test Coverage

**Summary:** Fixed v1.22.1 authentication module bug, synced CLI parity, updated documentation for 17 modules, and added buildConfig completeness tests.

**Session Focus:** Code review and bug fixes for v1.22.1 release, documentation accuracy, and test coverage improvements.

**Changes Made:**
- Modified `cli/src/assess-full.ts` - Added missing `authentication: true` to allModules
- Modified `scripts/run-full-assessment.ts` - Added `authentication`, `externalAPIScanner`, synced `temporal` logic
- Updated `docs/JSONL_EVENTS_ALGORITHMS.md` - Updated event count 12 to 13
- Updated `docs/JSONL_EVENTS_INTEGRATION.md` - Updated event counts 12 to 13 (two locations)
- Updated `docs/ASSESSMENT_CATALOG.md` - Updated to 17 modules with complete reference table
- Updated `docs/CLI_ASSESSMENT_GUIDE.md` - Updated to 17 modules, reorganized into Core/Compliance/Advanced
- Added `scripts/__tests__/cli-parity.test.ts` - Added 5 new buildConfig completeness tests using AST parsing

**Key Decisions:**
- Do not extract buildConfig() to shared module (TypeScript rootDir constraint makes it too complex)
- Use AST-based parity tests instead (matches existing cli-parity.test.ts pattern)
- 4-layer defense-in-depth for module configuration now in place

**Commits:**
- fix: add authentication module and sync CLI parity
- docs: update event counts and module counts
- test: add buildConfig completeness tests to catch missing modules (428dc36)

**Next Steps:**
- Consider publishing v1.22.2 with these fixes
- Monitor for any additional parity drift between CLI and scripts

**Notes:**
- Used 5 specialized agents: code-reviewer-pro, api-documenter, test-automator, test-generator for analysis
- All 1444 tests pass including 18 cli-parity tests (5 new)

---

## 2026-01-03: Published v1.22.3 to npm with Code Review Fixes

**Summary:** Published v1.22.3 to npm with code review fixes and updated CHANGELOG with release notes.

**Session Focus:** Publishing v1.22.3 release with fixes from code review session.

**Changes Made:**
- Modified `package.json` - Version bump to 1.22.3
- Modified `client/package.json` - Version sync to 1.22.3
- Modified `server/package.json` - Version sync to 1.22.3
- Modified `cli/package.json` - Version sync to 1.22.3
- Updated `CHANGELOG.md` - Added v1.22.3 release notes

**Key Decisions:**
- Version bumped to 1.22.3 (1.22.2 was already current version)
- Published all 4 workspace packages to npm
- Created GitHub tag v1.22.3

**Commits:**
- docs: update PROJECT_STATUS.md with session work (cebd531)
- v1.22.3 version bump
- docs: add v1.22.3 release notes to CHANGELOG (6ac8cc6)

**Next Steps:**
- Monitor npm downloads and user feedback
- Consider addressing remaining code review warnings (setTimeout anti-pattern, zero-modules validation)

**Notes:**
- All 4 packages published: root, client, server, cli
- Verified via `npm view @bryan-thompson/inspector-assessment version` showing 1.22.3
- CLI binary works: `npx -p @bryan-thompson/inspector-assessment@1.22.3 mcp-assess-full --help`

---

## 2026-01-03: Fixed Issue #15 - --skip-modules Flag Not Honored

**Summary:** Fixed Issue #15 where --skip-modules CLI flag was recognized but not honored during execution, and added 5 regression tests.

**Session Focus:** Bug fix for --skip-modules functionality in AssessmentOrchestrator.ts

**Changes Made:**
- Modified `client/src/services/assessment/AssessmentOrchestrator.ts` - Made core assessor properties optional, added conditional instantiation in constructor, added execution guards in parallel and sequential modes
- Modified `client/src/services/assessment/AssessmentOrchestrator.test.ts` - Added 5 new regression tests for module skipping behavior

**Key Decisions:**
- Used same pattern as extended modules (optional properties + conditional checks) for consistency
- Added comprehensive test coverage to prevent regression

**Commits:**
- 93ae975 - test: add regression tests for --skip-modules behavior (Issue #15)
- (fix commit already pushed earlier in session)

**Next Steps:**
- Monitor for any edge cases in --skip-modules behavior
- Consider adding CLI integration test

**Notes:**
- Issue #15 closed
- All 17 orchestrator tests passing (12 existing + 5 new)
- Fix verified against hardened-mcp server

---

## 2026-01-03: Created Inspector Assessment Code Reviewer Agent

**Summary:** Created inspector-assessment-code-reviewer agent - a specialized Claude Code agent primed with inspector framework knowledge for code review.

**Session Focus:** Creating a specialized code review agent that follows the code-reviewer-pro format but is customized for the MCP Inspector codebase.

**Changes Made:**
- Created `/home/bryan/triepod-ai-mcp-audit/.claude/agents/inspector-assessment-code-reviewer.md` (new agent definition)
- Created symlink at `~/.claude/agents/inspector-assessment-code-reviewer.md` for global access

**Key Decisions:**
- Named agent "inspector-assessment-code-reviewer" (renamed from initial "assessment-module-reviewer")
- Used Sonnet model for balance of speed and capability
- Included MCP tools: context7 and sequential-thinking
- Focus on Code + Architecture (assessor modules, orchestration, scoring)
- Agent stored in triepod-ai-mcp-audit repo with symlink to ~/.claude/agents/

**Technical Details:**
- Agent includes comprehensive framework knowledge: React 18.3.1, TypeScript 5.5.3 strict mode, Tailwind/shadcn/ui, Jest 29.7.0, MCP SDK 1.24.3
- Contains detailed review checklists: Assessment Module (8 items), React Component (7 items), TypeScript (5 items), Testing (5 items)
- Documents all 17 assessor modules and BaseAssessor pattern
- Includes reference paths to key source files

**Next Steps:**
- Test agent with sample code review request
- Consider adding more inspector-specific patterns as discovered
- May need to update agent as inspector evolves

**Notes:**
- Used code-reviewer-pro agent to generate initial framework inventory
- Followed existing agent format from ~/.claude/agents/agentgen-imports/

---

## 2026-01-03: Fixed npm Workspace Dependency Issue (v1.22.7)

**Summary:** Fixed npm workspace dependency issue causing ETARGET errors and published v1.22.7.

**Session Focus:** npm workspace dependency fix for inspector-assessment package

**Changes Made:**
- `/home/bryan/inspector/package.json` - Removed unpublished workspace dependencies (@bryan-thompson/inspector-assessment-cli, -client, -server, concurrently, ts-node)
- `/home/bryan/inspector/scripts/sync-workspace-versions.js` - Updated to not add workspace dependencies back during version sync

**Key Decisions:**
- Workspace packages are bundled via relative imports (e.g., `../../client/lib/...`), not npm dependencies
- Root package.json should only contain external dependencies like @modelcontextprotocol/sdk
- Published v1.22.7 with the fix

**Next Steps:**
- Monitor npm package usage
- Consider documenting the workspace bundling approach in README

**Notes:**
- Verified fix with tarball installation, npx installation, and full mcp-auditor audit
- Audit completed successfully: 97% score, 29 tools, 27 aligned, 0 review_recommended

---

## 2026-01-03: Fixed Annotation Inference False Positives

**Summary:** Fixed annotation inference false positives by adding confidence guards to event emission code.

**Session Focus:** Annotation inference logic fix - eliminating false positive misalignment events when inference confidence is low

**Changes Made:**
- Modified: `client/src/services/assessment/modules/ToolAnnotationAssessor.ts`
  - Added confidence guards to readOnlyHint event emission (lines 689-708)
  - Added confidence guards to destructiveHint event emission (lines 732-751)
  - Updated default inference reason message from "defaulting to write operation" to "Could not infer behavior from name pattern"

**Key Decisions:**
- When inference confidence is low (50%) or ambiguous, trust explicit annotations rather than emitting misalignment events
- Philosophy: "Absence of evidence is not evidence of absence" - don't assert misalignment without confident inference

**Technical Details:**
- Root cause: Event emission code bypassed confidence guards that assessTool() correctly implements
- The assessTool() method already had guards (lines 1156-1161) preventing MISALIGNED status for low-confidence cases
- But event emission (lines 669-741) was still emitting annotation_misaligned events regardless

**Results:**
- All 48 ToolAnnotationAssessor tests passing
- hardened-mcp misalignments: 23 -> 0 (eliminated all false positives)
- Commit: 6627915 "fix(annotations): add confidence guards to event emission"

**Next Steps:**
- Consider publishing new version with this fix
- Monitor for any edge cases in production assessments

**Notes:**
- Fix aligns with existing assessTool() logic that already implemented confidence guards
- Ensures consistent behavior between assessment results and emitted events

---

## 2026-01-03: Preventive Measures for Workspace Dependency Bug

**Summary:** Implemented preventive measures against workspace dependency bug that caused npm installation failures.

**Session Focus:** Code review of recent commit 09d8198 and implementation of safeguards to prevent recurrence of workspace dependency bug.

**Changes Made:**
- Created: `.github/workflows/verify-publish.yml` - Post-publish CI verification workflow
- Created: `client/src/services/assessment/__tests__/package-structure.test.ts` - Unit tests preventing workspace deps in package.json
- Created: `scripts/validate-publish.js` - Pre-publish validation script with 4 automated checks
- Updated: `CLAUDE.md` - Added "Workspace Architecture (Critical)" documentation section
- Updated: `package.json` - Added prepublishOnly hook and validate:publish script

**Key Decisions:**
- Workspace packages are bundled via `files` array, NOT npm dependencies
- Added multiple layers of protection: unit tests, pre-publish hook, CI workflow, documentation
- prepublishOnly hook runs automatically before any npm publish

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
