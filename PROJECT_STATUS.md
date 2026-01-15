# Project Status: MCP Inspector

## Current Version

- **Version**: 1.37.0 (published to npm as "@bryan-thompson/inspector-assessment")

---

## 2026-01-15: Issue #168 - Enhanced ExternalAPIDependencyDetector with Source Code Scanning

**Summary:** Enhanced the ExternalAPIDependencyDetector helper to support source code scanning for more accurate external API dependency detection.

**Session Focus:** Issue #168 implementation - source code scanning for external API detection

**Changes Made:**
- Extended `ExternalAPIDependencyInfo` interface with new fields: `domains`, `sourceCodeScanned`, `implications`
- Added `ExternalAPIImplications` interface for downstream assessor guidance
- Implemented `scanSourceCode()` method with 7 regex patterns for HTTP client calls:
  - fetch() calls (JavaScript/TypeScript)
  - axios HTTP client calls (get, post, put, patch, delete, request)
  - URL construction (new URL())
  - API base URL constants (API_BASE_URL, BASE_URL, API_URL, ENDPOINT)
  - Generic HTTP client .get/.post calls
  - Python requests library calls
  - Python httpx library calls
- Added localhost/local network URL filtering (127.0.0.1, 192.168.x, 10.x, .local, example.com)
- Added test file skipping patterns (node_modules, .test.ts, .spec.ts, .d.ts, etc.)
- Updated `detect()` method signature to accept optional `sourceCodeFiles` parameter
- Added input sanitization limits (500KB max file size, 100 max matches per file)
- Used `String.matchAll()` for thread-safe regex matching
- Updated CLI (`assessment-executor.ts`) to pass `sourceCodeFiles` to detector
- Fixed type safety issues (imported `SourceFiles` type, updated `PackageJson` type)
- Added 36+ new tests for source code scanning functionality

**Files Modified:**
- `client/src/services/assessment/helpers/ExternalAPIDependencyDetector.ts` - Core implementation
- `cli/src/lib/assessment-runner/assessment-executor.ts` - CLI integration
- `cli/src/lib/assessment-runner/types.ts` - Type definitions
- `client/src/services/assessment/__tests__/ExternalAPIDependencyDetector.test.ts` - Tests

**Key Decisions:**
- Enhanced existing helper rather than merging with ExternalAPIScannerAssessor (separate concerns)
- Used `Map.forEach()` and `Array.from(matchAll())` for TypeScript compatibility
- Added input sanitization to prevent ReDoS attacks on large/adversarial files
- Backward compatible - existing callers without source code continue to work

**Test Results:**
- All 161 tests passing for ExternalAPIDependencyDetector
- Build successful

**Acceptance Criteria Met:**
- ✅ Source code scanning extracts domains from fetch/axios/URL patterns
- ✅ Localhost/local URLs are filtered out
- ✅ Results include `domains`, `sourceCodeScanned`, and `implications`
- ✅ CLI passes sourceCodeFiles to detector when available
- ✅ All existing tests pass
- ✅ New tests cover source code scanning scenarios

**Next Steps:**
- Test with world-bank MCP server (known external API)
- Verify TemporalAssessor handles enhanced info correctly

---

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

---

## 2026-01-15: npm Release v1.37.0 - Minor version bump with new features

**Summary:** Published npm package version 1.37.0 with accumulated features and fixes

**Session Focus:** Publishing npm package version 1.37.0 with accumulated features and fixes

**Changes Made:**
- Bumped version from 1.36.5 to 1.37.0 (minor bump for new features)
- Committed pending PROJECT_STATUS.md changes
- Built and published all 4 workspace packages to npm
- Pushed v1.37.0 tag to GitHub

**Key Decisions:**
- Used minor version bump (not patch) due to 3 feature commits since last release

**What's in 1.37.0:**

Features:
- ECONNRESET pattern and retry integration tests (#157)
- Shared ExternalAPIDependencyDetector (#168)
- Connection retry logic for transient errors (#157)

Fixes:
- try-finally for console spy cleanup (#149)
- Handle isError variance for external API tools (#166)
- Conditional severity for description length warnings (#167)

**Next Steps:**
- Continue development on upcoming features
- Monitor npm package for any issues

**Notes:**
- Package: @bryan-thompson/inspector-assessment@1.37.0
- All 4 workspace packages published successfully
- Tag v1.37.0 pushed to GitHub

---

## 2026-01-15: Issue #163 Complete - Modularized securityPatterns.ts by attack category

**Summary:** Split monolithic 2,202-line security patterns file into 7 focused modules for maintainability

**Session Focus:** Modularizing securityPatterns.ts to improve code organization and maintainability

**Changes Made:**
- Split `securityPatterns.ts` (2,202 lines) into 7 focused modules:
  - `injectionPatterns.ts` - 6 injection attack patterns (SQL, NoSQL, LDAP, XPath, Command, Template)
  - `validationPatterns.ts` - 5 validation bypass patterns (Path Traversal, SSRF, XXE, Deserialization, Schema)
  - `toolSpecificPatterns.ts` - 7 tool-specific patterns (Calculator, Filesystem, Code Exec, Network, Logging, Memory, LLM)
  - `resourceExhaustionPatterns.ts` - 2 resource exhaustion patterns (Timeout, Memory)
  - `authSessionPatterns.ts` - 5 auth/session patterns (Token, Session, Privilege, IDOR, Rate Limit)
  - `advancedExploitPatterns.ts` - 7 advanced exploit patterns (Prototype Pollution, Unicode, Race, Payload Size, Type Confusion, Chained, Multi-step)
- Updated `securityPatterns.ts` to re-export from modules (maintains backward compatibility)
- Added explicit 184 payload count assertion in integrity tests (17 tests total)
- Updated documentation: SECURITY_PATTERNS_CATALOG.md, ASSESSMENT_MODULE_DEVELOPER_GUIDE.md

**Key Decisions:**
- Organized by attack category rather than alphabetically for logical grouping
- Used re-export pattern to maintain backward compatibility with existing imports
- Added payload count assertion to catch accidental pattern loss during refactoring
- Kept original file as aggregation point to avoid breaking changes

**Next Steps:**
- Consider similar modularization for other large files if needed
- Monitor for any import issues in downstream code

**Notes:**
- Commit: e886353d - feat(security): Modularize securityPatterns.ts by attack category (Issue #163)
- Full code review workflow passed (0 P0/P1 issues)
- All 17 integrity tests passing with explicit payload count validation
- Issue #163 closed on GitHub

## 2026-01-15: Issue #168 Code Review & ReDoS Protection Tests

**Summary:** Completed Issue #168 code review workflow and added ReDoS protection test coverage

**Session Focus:** Issue #168 implementation validation through 6-stage code review and test enhancement

**Changes Made:**
- Executed 6-stage code review workflow on Issue #168 (shared ExternalAPIDependencyDetector)
- Stage 1: Code review identified 4 issues (0 P0, 1 P1, 1 P2, 2 P3)
- Stage 2: P1 validation - empty catch block in extractDomain() confirmed correct (URL parsing only throws TypeError)
- Stage 3: QA validation - identified need for ReDoS (Regular Expression Denial of Service) protection tests
- Stage 4: Added 3 new ReDoS protection tests to ExternalAPIDependencyDetector.test.ts
  - Test 1: MAX_CONTENT_LENGTH enforcement (500KB limit)
  - Test 2: MAX_MATCHES_PER_FILE enforcement (100 match limit)
  - Test 3: Regex performance under pathological input patterns
- Stage 5: Documentation enhancement
  - docs/ASSESSMENT_CATALOG.md (+19 lines)
  - docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md (+131 lines)
  - New section: "Pattern 8: Shared Detection Helpers" with ReDoS best practices
- Stage 6: Final validation - all 164 tests passing, build successful

**Key Decisions:**
- Validated empty catch block as intentional design (only TypeError can occur)
- Implemented explicit ReDoS protection limits rather than relying on timeout
- Documented MAX_CONTENT_LENGTH and MAX_MATCHES_PER_FILE as critical security parameters
- Enhanced developer guide with shared detector pattern documentation

**Next Steps:**
- Commit all Issue #168 changes to main branch
- Close GitHub Issue #168 as complete
- Consider applying similar ReDoS protection patterns to other regex-based detectors

**Notes:**
- Total files modified: 7 (980 insertions, 21 deletions)
- New test suite: 3 ReDoS protection tests
- Code review verdict: PASS - ready for production
- Test coverage: 164/164 passing (100% success rate)

---
