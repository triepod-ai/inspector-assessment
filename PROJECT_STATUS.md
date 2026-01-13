# Project Status: MCP Inspector

## Current Version

- **Version**: 1.36.4 (published to npm as "@bryan-thompson/inspector-assessment")

**Recent Releases:**
- v1.36.4: Issue #160 fix - emitToolDiscovered() non-suffixed annotation fallback
- v1.36.3: Issue #159 fix - transport interception for hint preservation
- v1.36.2: Issue #158 fix - totalToolsFound legacy compatibility
- v1.36.1: Issue #153, #154 fixes - connection error detection, skipped module scoring
- v1.36.0: Issue #155 fix - tool annotation detection in events

---

## 2026-01-13: v1.36.4 Release - Issue #160 Fix

**Summary:** Fixed incomplete Issue #150 implementation by adding non-suffixed annotation fallback to `emitToolDiscovered()`.

**Problem:** Servers using `annotations: { readOnly: true }` (non-suffixed) were incorrectly flagged as having missing annotations (0% detection rate).

**Root Cause:** Issue #150 fix was applied to `AlignmentChecker.resolveAnnotationValue()` but not to `emitToolDiscovered()` in the CLI JSONL events module.

**Changes Made:**
- `cli/src/lib/jsonl-events.ts` - Added non-suffixed fallback for all 4 priority locations:
  - Priority 1: tool.annotations object
  - Priority 2: Direct properties on tool
  - Priority 3: tool.metadata object
  - Priority 4: tool._meta object
- `cli/src/__tests__/jsonl-events.test.ts` - Added 8 test cases for non-suffixed detection

**Fix Pattern:**
```typescript
// Before (only checked *Hint)
readOnlyHint = annotationsAny.readOnlyHint;

// After (checks both with fallback)
if (typeof annotationsAny.readOnlyHint === "boolean") {
  readOnlyHint = annotationsAny.readOnlyHint;
} else if (typeof annotationsAny.readOnly === "boolean") {
  readOnlyHint = annotationsAny.readOnly;
}
```

**Commits:**
- 5a32b6b1: fix(annotations): Add non-suffixed fallback to emitToolDiscovered() (Issue #160)
- 760d906a: 1.36.4

**Issue Closed:** #160

---

## 2026-01-13: Fixed Issue #152 - Security Module Scoring Bug

**Summary:** Fixed Issue #152 security module scoring bug and created follow-up Issue #157 for retry logic.

**Session Focus:** Issue #152 - Security module returning empty results with 90% score

**Changes Made:**
- `client/src/lib/assessment/resultTypes.ts` - Added testExecutionMetadata interface
- `client/src/lib/moduleScoring.ts` - Added score validation logic with coverage checks
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Populated test execution metadata
- `client/src/lib/__tests__/moduleScoring.test.ts` - Added 10 new tests for scoring validation
- Created GitHub Issue #157 for connection retry enhancement

**Key Decisions:**
- Score 0% when no tests completed due to connection errors
- Cap score at 50% when test coverage < 50%
- Metadata is optional for backward compatibility
- Connection retry logic deferred to Issue #157

**Next Steps:**
- Implement Issue #157 connection retry logic
- Consider extracting magic numbers to named constants (P3)
- Address remaining unstaged test file changes

**Notes:**
- Code review identified P1 comment clarification (fixed)
- 10 new tests all passing
- Commit: e40f2052

---

## 2026-01-13: Fixed Issue #153 - ErrorHandling Module Scoring Bug

**Summary:** Fixed errorHandling module returning 100% score when no tests executed due to connection errors.

**Session Focus:** Bug fix for errorHandling module scoring validation (Issue #153)

**Changes Made:**
- `client/src/lib/assessment/resultTypes.ts` - Added testExecutionMetadata interface to ErrorHandlingAssessment
- `client/src/services/assessment/modules/ErrorHandlingAssessor.ts` - Populated testExecutionMetadata with tool-level coverage tracking
- `client/src/lib/moduleScoring.ts` - Added score validation logic (0% for all failures, cap at 50% for <50% coverage)
- `client/src/lib/__tests__/moduleScoring.test.ts` - Added 9 new test cases for errorHandling metadata validation

**Key Decisions:**
- Followed same pattern as Issue #152 (security module) for consistency
- Used tool-based counting for coverage (tracks connection failures per tool)
- Code review identified P1 semantic inconsistency - user requested refactor to match SecurityAssessor's test-based counting

**Next Steps:**
- Refactor to use test-based counting for semantic consistency with SecurityAssessor
- Commit changes with proper conventional commit message

**Notes:**
- All 43 moduleScoring tests passing (9 new)
- All 71 ErrorHandlingAssessor tests passing
- Build succeeds with no TypeScript errors
- Issue #153 identified same pattern as Issue #152

---

## 2026-01-13: Fixed False-Positive Scoring Bugs (Issues #153, #154)

**Summary:** Fixed false-positive scoring bugs in prohibitedLibraries and errorHandling assessment modules.

**Session Focus:** Issue #154 (prohibitedLibraries reports 0 files scanned returning PASS) and Issue #153 (errorHandling returns 100% score with no tests executed)

**Changes Made:**
- `client/src/lib/assessment/extendedTypes.ts` - Added skipped?, skipReason? fields to ProhibitedLibrariesAssessment
- `client/src/services/assessment/modules/ProhibitedLibrariesAssessor.ts` - Added createSkippedResult() method and early return check
- `client/src/services/assessment/modules/ProhibitedLibrariesAssessor.test.ts` - Added 8 tests for skip behavior (158 lines)
- `cli/src/lib/assessment-runner/assessment-executor.ts` - CLI always shows warning when source path not found
- `client/src/lib/moduleScoring.ts` - Validate test execution before returning score
- `client/src/services/assessment/modules/ErrorHandlingAssessor.ts` - Added testExecutionMetadata tracking
- `client/src/lib/assessment/resultTypes.ts` - Added TestExecutionMetadata interface
- `client/src/lib/__tests__/moduleScoring.test.ts` - Added 119 lines of score validation tests

**Key Decisions:**
- Used established createSkippedResult() pattern from ConformanceAssessor/FileModularizationAssessor
- Return NEED_MORE_INFO (not new SKIPPED status) for backward compatibility
- Test execution validation: 0 score if all tests fail, cap at 50 if >50% fail

**Commits:**
- c6b675a3: fix(prohibitedLibraries): Return NEED_MORE_INFO when no files to scan (Issue #154)
- 4dc203bb: fix(errorHandling): Validate test execution before scoring (Issue #153)

**Issues Closed:** #153, #154

**Next Steps:**
- Monitor for any edge cases in production usage
- Consider similar validation patterns for other assessment modules

**Notes:**
- Code review workflow found no P0 issues
- All 35 ProhibitedLibraries tests passing including 8 new ones

---

## 2026-01-13: Added --debug-annotations CLI Flag (Issue #155)

**Summary:** Added debug flag and expanded annotation detection to 5 locations for Issue #155.

**Session Focus:** Issue #155 - Tool annotation detection returns 0% for servers with runtime annotations

**Changes Made:**
- `client/src/services/assessment/modules/annotations/AlignmentChecker.ts` - Added setAnnotationDebugMode(), debug logging, expanded to check _meta and annotations.hints
- `cli/src/lib/cli-parser.ts` - Added --debug-annotations flag with help text
- `cli/src/lib/assessment-runner/assessment-executor.ts` - Enable debug mode when flag is used
- `client/src/services/assessment/modules/annotations/index.ts` - Export new debug functions
- `client/src/services/assessment/__tests__/AlignmentChecker-Issue155.test.ts` - New test file with 12 test cases

**Key Decisions:**
- Extraction logic was already correct; issue is server frameworks not serializing top-level hints
- Added debug flag to help developers diagnose annotation location issues
- Expanded to 5 annotation locations: annotations object, direct properties, metadata, _meta, annotations.hints

**Next Steps:**
- Run tests to verify no regressions
- Document the --debug-annotations flag in CLI docs

**Notes:**
- Root cause identified: FastMCP doesn't serialize top-level readOnlyHint properties
- Servers should use annotations=ToolAnnotations(readOnlyHint=True) instead of readOnlyHint: true at tool root
- 12 new test cases covering all annotation location combinations

---

## 2026-01-13: Fixed Skipped Module Scoring in calculateModuleScore (Issue #154 Follow-up)

**Summary:** Fixed module scoring to properly return null for skipped modules, completing Issue #154 fix.

**Session Focus:** Investigating reopened Issue #154 where prohibitedLibraries module still showed 100% score with 0 scanned files despite the initial fix.

**Changes Made:**
- `client/src/lib/moduleScoring.ts` - Added early return check for `skipped: true` flag to return `null` instead of calculating score
- `client/src/lib/__tests__/moduleScoring-skipped.test.ts` - New test file with 6 comprehensive test cases for skipped module scoring behavior

**Key Decisions:**
- Root cause: `calculateModuleScore()` wasn't honoring the `skipped: true` flag that modules set via `createSkippedResult()`
- Fix location: Added check at the start of `calculateModuleScore()` before any score calculation
- Return value: `null` for skipped modules (consistent with how UI should handle missing/unavailable data)
- Test coverage: Added tests for direct skipped flag, nested result.skipped, and various edge cases

**Commits:**
- 1eb59519: fix(moduleScoring): Return null for skipped modules in calculateModuleScore (Issue #154)

**Issues Updated:** #154 (added follow-up comments explaining the additional fix)

**Related Issues Created:**
- mcp-auditor#140: Investigate libraryMetrics display transformation (found during investigation)

**Next Steps:**
- Monitor production usage to ensure skipped modules display correctly
- Consider adding similar skipped handling to other scoring utilities if needed

**Notes:**
- The initial Issue #154 fix added `createSkippedResult()` call in ProhibitedLibrariesAssessor
- This follow-up fix ensures the scoring layer respects that skipped flag
- Both fixes together complete the full solution: module marks itself skipped AND scoring honors it
- All 1566 tests passing including 6 new skipped module scoring tests

---

## 2026-01-13: Fixed Tool Annotation Detection for Runtime Annotations (Issue #155)

**Summary:** Fixed annotation detection returning 0% for servers with runtime annotations

**Session Focus:** Bug fix for annotation detection in CLI JSONL events where servers providing annotations at runtime were not being detected.

**Changes Made:**
- `cli/src/lib/jsonl-events.ts` - Fixed `emitToolDiscovered()` to check 4 annotation locations:
  1. `tool.annotations` object (MCP spec standard location)
  2. Direct properties (`tool.readOnlyHint`, etc.)
  3. `tool.metadata` object
  4. `tool._meta` object
- `cli/src/__tests__/jsonl-events.test.ts` - Added 4 test cases covering annotation detection from various locations
- Improved comment documentation per code review feedback explaining the design choice

**Key Decisions:**
- Used simplified annotation extraction (only `*Hint`-suffixed properties) vs full AlignmentChecker logic
- Documented this as intentional design choice in code comments - balances coverage vs complexity
- Checked 4 annotation locations to handle various server framework implementations

**Commits:**
- 7ecb6fee: fix(annotations): Detect tool annotations from multiple locations (Issue #155)
- b49fb305: fix(annotations): Add comment explaining extraction design choice (Issue #158 + code review)

**Issues Closed:** #155

**Next Steps:**
- Monitor for any remaining annotation detection issues in production
- Consider adding non-suffixed property fallbacks if needed (P2 suggestion from code review)

**Notes:**
- Root cause: Different MCP server frameworks serialize annotations to different locations
- FastMCP uses `annotations` object, other frameworks may use direct properties or metadata
- All 65 CLI tests passing after fix

---

## 2026-01-13: Published v1.36.3 with Issue #155 Fix

**Summary:** Published v1.36.3 to npm with Issue #155 fix for tool annotation detection

**Session Focus:** Publishing the transport-level interception fix for tool annotation detection that was merged but not yet published to npm.

**Changes Made:**
- Published @bryan-thompson/inspector-assessment@1.36.3 to npm
- Created and pushed git tag v1.36.3
- Added confirmation comment to GitHub Issue #155

**Key Decisions:**
- Stashed pending PROJECT_STATUS.md changes to ensure clean publish
- Used standard publish workflow (build -> publish-all -> tag -> push)

**Next Steps:**
- Monitor for any remaining annotation detection issues
- Update stashed PROJECT_STATUS.md content if needed

**Notes:**
- Issue #155 fix uses transport-level interception to capture raw MCP messages before SDK validation strips hint properties
- This resolves false negatives where servers with `readOnlyHint: true` as direct properties showed `annotations: null`

---
