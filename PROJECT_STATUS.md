# Project Status: MCP Inspector

## Current Version

- **Version**: 1.36.4 (published to npm as "@bryan-thompson/inspector-assessment")

**Session Focus:** Issue #160 complete fix and npm release v1.36.5

**Changes Made:**
- Implemented two-part solution for non-suffixed annotation property detection:
  1. `cli/src/tools-with-hints.ts`: Transport interception to preserve non-suffixed properties (readOnly, destructive, idempotent, openWorldHint) before MCP SDK Zod validation strips them
  2. `cli/src/jsonl-events.ts`: Fallback detection for non-suffixed properties in JSONL event emission
- Published v1.36.5 to npm (all 4 packages: root, client, server, cli)
- Updated GitHub Issue #160 with release comment

**Commits:**
- e7728e0c: feat(cli): Transport interception for non-suffixed annotation properties (Issue #160)
- 5a32b6b1: feat(cli): Add fallback detection for non-suffixed annotation properties in JSONL events
- 2df75352: 1.36.5

**Key Decisions:**
- Two-part fix was required because MCP SDK Zod validation strips non-spec properties
- Transport-level interception captures raw MCP messages before SDK processing
- JSONL event emission includes fallback to ensure non-suffixed properties appear in output
- Approach maintains compatibility with both spec-compliant (suffixed) and non-spec (non-suffixed) servers

**Next Steps:**
- Test with actual non-suffixed server (like Tomba MCP which reportedly uses readOnly instead of readOnlyHint)
- Monitor GitHub Issues for reports from users with non-standard annotation servers
- Consider documenting supported annotation property variants

**Notes:**
- hardened-mcp validation showed 46/46 tools detected (100% detection rate)
- Issue #160 was originally reported as annotations showing null despite server using readOnly property
- This fix resolves false negatives where non-suffixed annotation properties were being stripped by SDK validation

---

## 2026-01-14: GitHub Issue Triage - Closed Duplicate Issues #161 and #162

**Summary:** Issue triage - closed 2 duplicate issues (#161, #162) already fixed in v1.36.5

**Session Focus:** GitHub issue review and cleanup

**Changes Made:**
- Reviewed 8 open GitHub issues
- Investigated issues #161 and #162 - both reported 'post' keyword false positive in readOnlyHint detection
- Confirmed fix was already implemented in v1.36.5 (commit 2eccd6a2)
- Closed issue #161 as resolved
- Closed issue #162 as duplicate of #161

**Key Decisions:**
- Identified both issues as duplicates of the same already-fixed problem
- The noun-context detection fix using READONLY_PREFIX_PATTERNS and NOUN_KEYWORDS_IN_READONLY_CONTEXT resolved the false positive

**Next Steps:**
- Continue with remaining 6 open issues

**Notes:**
- The 'post' keyword false positive occurred because 'post' matched HTTP method pattern but was actually referring to a blog/forum post noun
- Fix implemented context-aware noun detection to distinguish between HTTP POST method and noun usage

## 2026-01-14: GitHub Issue Triage - Closed Duplicate Issues #161 and #162

**Summary:** Issue triage - closed 2 duplicate issues (#161, #162) already fixed in v1.36.5

**Session Focus:** GitHub issue review and cleanup

**Changes Made:**
- Reviewed 8 open GitHub issues
- Investigated issues #161 and #162 - both reported 'post' keyword false positive in readOnlyHint detection
- Confirmed fix was already implemented in v1.36.5 (commit 2eccd6a2)
- Closed issue #161 as resolved
- Closed issue #162 as duplicate of #161

**Key Decisions:**
- Identified both issues as duplicates of the same already-fixed problem
- The noun-context detection fix using READONLY_PREFIX_PATTERNS and NOUN_KEYWORDS_IN_READONLY_CONTEXT resolved the false positive

**Next Steps:**
- Continue with remaining 6 open issues

**Notes:**
- The 'post' keyword false positive occurred because 'post' matched HTTP method pattern but was actually referring to a blog/forum post noun
- Fix implemented context-aware noun detection to distinguish between HTTP POST method and noun usage

---

## 2026-01-14: Issue #160 Review - Non-Suffixed Annotation Properties Validation

**Summary:** Reviewed Issue #160 fix completeness - verified GitHub validation and test coverage

**Session Focus:** Issue #160 review - non-suffixed annotation property detection fix validation

**Changes Made:**
- Reviewed GitHub Issue #160 comments and validation notes
- Analyzed test coverage for Issue #160 fix
- Verified all 13 Issue #160 tests pass across jsonl-events.test.ts and tools-with-hints.test.ts
- Confirmed GitHub validation from bryan-anthropic (Tomba MCP: 0% → 100% annotation coverage)

**Key Decisions:**
- Issue #160 fix is complete with proper test coverage
- No additional tests needed - existing 13 tests cover all code paths
- GitHub validation confirms real-world effectiveness

**Next Steps:**
- Monitor for any edge cases with other non-suffixed annotation servers
- Consider documenting supported annotation property variants in user docs

**Notes:**
- Test coverage: 8 tests in jsonl-events.test.ts + 5 tests in tools-with-hints.test.ts
- Related Issue #150 has 22 additional tests in AlignmentChecker-Issue150.test.ts
- All tests passing as of this session

---

## 2026-01-14: Issue #157 Code Review - Security Module Connection Retry Logic

**Summary:** Completed 7-stage code review and P1 fix for ECONNRESET retry handling

**Session Focus:** Code review and P1 issue resolution for Issue #157 Security Module Connection Retry Logic

**Changes Made:**
- Added /ECONNRESET/i pattern to TRANSIENT_ERROR_PATTERNS in SecurityPatternLibrary.ts
- Added /ECONNRESET/i pattern to CONNECTION_ERROR_PATTERNS.unambiguous
- Added 5 integration tests for testPayloadWithRetry() in SecurityPayloadTester-Retry.test.ts
- Updated PERFORMANCE_TUNING_GUIDE.md with securityRetryMaxAttempts and securityRetryBackoffMs documentation
- Updated test expectations (pattern count from 8 to 9, ECONNRESET test from false to true)

**Key Decisions:**
- Use real timers instead of fake timers for async retry metadata test due to Jest timer complexities
- Added ECONNRESET as transient error since it is a common Node.js connection reset error code
- P3 issues deferred (jitter for backoff, enhanced logging) as non-blocking enhancements

**Next Steps:**
- P3 issues remain open for future enhancement consideration
- Monitor retry behavior in production usage

**Notes:**
- All 32 retry tests passing
- Code review verdict: APPROVED
- Commit reviewed: d81eaaf2

---

## 2026-01-14: Codebase Analysis and Refactoring Issue Creation

**Summary:** Analyzed codebase for large files that could be modularized to improve LLM-friendliness

**Session Focus:** Code analysis and refactoring issue creation

**Changes Made:**
- Analyzed source files to find largest non-test TypeScript files
- Identified `securityPatterns.ts` (2,202 lines), `extendedTypes.ts` (1,145 lines), and `App.tsx` (1,293 lines) as top candidates
- Created GitHub issue #163: Modularize securityPatterns.ts by attack category
- Created GitHub issue #164: Modularize extendedTypes.ts by domain (61 exports to 9 modules)
- Created GitHub issue #165: Extract App.tsx logic into custom hooks

**Key Decisions:**
- Proposed splitting securityPatterns.ts into 6-7 modules organized by attack category (injection, traversal, authentication, etc.)
- Proposed splitting extendedTypes.ts into 9 domain-specific type files
- Proposed extracting App.tsx callbacks into 6 custom hooks (useTabState, useToolExecution, useSamplingHandler, etc.)
- All refactoring maintains backward compatibility via barrel exports

**Next Steps:**
- Implement refactoring starting with simpler extractions (useNotifications, useTabState)
- Consider marking issues as "good first issue" for contributors

**Notes:**
- Refactoring improves LLM context efficiency by reducing file sizes to 100-300 lines each
- No code changes made this session - planning/issue creation only
- Issues created: #163, #164, #165

---

## 2026-01-14: Fixed False Positive Issues #166 and #167

**Summary:** Fixed two false positive issues in Temporal and Annotation assessors

**Session Focus:** Reducing false positives in Inspector assessment modules

**Changes Made:**
- Issue #166: Added external API tool detection and isError variance handling in VarianceClassifier.ts and TemporalAssessor.ts
- Issue #167: Implemented conditional severity for description length warnings (LOW for length-only, MEDIUM for length+patterns)
- Created 34 new tests for external API handling (TemporalAssessor-ExternalAPI.test.ts)
- Added 5 new tests for conditional severity logic
- Commits: 1aa7d380 (Issue #167), b5fc1492 (Issue #166)

**Key Decisions:**
- External API tools detected via name patterns (16) and description patterns (7 regex)
- isError variance (error vs success responses) treated as LEGITIMATE for external/stateful tools
- Length-only description warnings get LOW severity (informational, no FAIL)

**Testbed Validation:**
- Vulnerable-MCP: 456 vulnerabilities, 1594 vulnerable tests
- Hardened-MCP: 0 vulnerabilities, 0 vulnerable tests
- A/B detection gap maintained, zero false positives

**Next Steps:**
- 9 open issues remaining (#168, #165, #164, #163, #149, #133, #130, #129, #48)

**Notes:**
- Both issues closed with comprehensive test coverage
- No regressions in testbed validation
- Pattern-based detection preserves precision while reducing false positives

---

## 2025-01-14: Implemented External API Dependency Detector (Issue #168)

**Summary:** Created shared ExternalAPIDependencyDetector helper for cross-assessor external API detection

**Session Focus:** Create shared ExternalAPIDependencyDetector helper for cross-assessor external API detection

**Changes Made:**
- NEW: `client/src/services/assessment/helpers/ExternalAPIDependencyDetector.ts` - shared helper with 18 name patterns + 7 description patterns
- NEW: `client/src/services/assessment/__tests__/ExternalAPIDependencyDetector.test.ts` - 122 unit tests
- MODIFIED: AssessmentOrchestrator.ts - added externalAPIDependencies to AssessmentContext
- MODIFIED: assessment-executor.ts - runs detector during context preparation
- MODIFIED: TemporalAssessor.ts - uses context-based detection with VarianceClassifier fallback
- MODIFIED: FunctionalityAssessor.ts - accepts expected API errors as "working" status
- MODIFIED: ErrorHandlingAssessor.ts - accounts for external service failures
- MODIFIED: VarianceClassifier.ts - delegates to shared detector, removed duplicate patterns
- MODIFIED: resultTypes.ts - added note field to ToolTestResult

**Key Decisions:**
- Pattern-only MVP approach (no source code URL scanning in this release)
- Context enrichment pattern - detection runs during preparation phase before assessors
- Word-boundary matching to prevent false positives (e.g., "api" shouldn't match "capital")

**Next Steps:**
- Future: Source code URL scanning for higher confidence detection
- Future: JSONL event for external_api_detected
- Future: Report section for "External Dependencies"

**Notes:**
- Commit: 112a6473 - feat(assessment): Add shared ExternalAPIDependencyDetector (Issue #168)
- Testbed validation passed: vulnerable-mcp (451 vulns), hardened-mcp (0 vulns), 0 false positives on safe tools
- A/B detection gap maintained with pure behavior-based detection
