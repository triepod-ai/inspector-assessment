# Project Status: MCP Inspector

## Current Version

- **Version**: 1.20.4 (published to npm as "@bryan-thompson/inspector-assessment")

**Summary:** npm binary now has full JSONL event parity with local script, plus bug fix for mcpServers http transport config.

**Session Focus:** JSONL event emission alignment between npm binary and local development script, documentation updates, and config loader bug fix.

**Changes Made:**
- `cli/src/assess-full.ts` - Added full JSONL event emission with onProgress callback
- `cli/src/lib/jsonl-events.ts` - NEW: CLI-local JSONL event emitters
- `scripts/run-full-assessment.ts` - Added missing annotation_review_recommended handler
- `cli/src/assess-full.ts` & `scripts/run-full-assessment.ts` - Fixed mcpServers http transport config bug
- `CLAUDE.md` - Added npm/local script parity rule and test server documentation

**Key Decisions:**
- Created CLI-local jsonl-events.ts due to TypeScript rootDir constraints (can't import from scripts/)
- Both CLI files must stay synchronized (documented in CLAUDE.md parity rule)
- mcpServers wrapper config now properly detects http/sse transport before defaulting to stdio

**Key Results:**
- All 11 JSONL event types now emitted by npm binary
- mcpServers config format works with http transport
- Verified against vulnerable-mcp testbed

**Commits:**
- `77bfb65` feat(cli): add JSONL event emission to npm binary
- `ccaf410` docs: add npm binary / local script parity rule to CLAUDE.md
- `2d7eba1` fix(cli): support http transport in mcpServers config wrapper
- `72479cd` v1.20.4

**Next Steps:**
- Consider adding assessment resume capability for long-running assessments
- Add automated A/B comparison tool (scripts/compare-assessments.sh)
- Add retry logic with exponential backoff for transient failures

**Notes:**
- Test servers documented in CLAUDE.md: test-server (10651), firecrawl (10777), dvmcp (9001-9006)
- npm binary / local script parity now enforced through documentation

---

## 2025-12-31: v1.20.4 Release - mcpServers HTTP Transport Config Fix

**Summary:** Fixed config loader bug that ignored http/sse transport when using mcpServers wrapper format.

**Bug:** Configs like `{"mcpServers": {"server": {"transport": "http", "url": "..."}}}` were incorrectly treated as stdio transport.

**Fix:** Check for url/transport properties inside serverConfig before defaulting to stdio.

**Files Modified:**
- `cli/src/assess-full.ts` - Lines 105-133
- `scripts/run-full-assessment.ts` - Lines 104-132

**Commits:**
- `2d7eba1` fix(cli): support http transport in mcpServers config wrapper
- `72479cd` v1.20.4

---

## 2025-12-31: v1.20.3 Release - Full JSONL Event Emission in npm Binary

**Summary:** Added all 11 JSONL event types to npm binary, matching local development script functionality.

**Session Focus:** JSONL event parity between `cli/src/assess-full.ts` and `scripts/run-full-assessment.ts`.

**Changes Made:**
- `cli/src/assess-full.ts` - Added onProgress callback with handlers for all event types
- `cli/src/lib/jsonl-events.ts` - NEW: CLI-local event emitters (created due to rootDir constraints)
- `scripts/run-full-assessment.ts` - Added missing annotation_review_recommended handler
- `CLAUDE.md` - Added parity rule and test server documentation

**JSONL Events Now Emitted:**
1. `server_connected` - On successful connection
2. `tool_discovered` - For each tool (replaces old `TOOL_DISCOVERED:` format)
3. `tools_discovery_complete` - After all tools discovered
4. `module_started` - When assessment module begins
5. `test_batch` - Progress updates during testing
6. `vulnerability_found` - When vulnerability detected
7. `annotation_missing` - Missing tool annotations
8. `annotation_misaligned` - Misaligned annotations
9. `annotation_review_recommended` - Ambiguous annotations
10. `module_complete` - When module finishes
11. `assessment_complete` - Final results

**Commits:**
- `77bfb65` feat(cli): add JSONL event emission to npm binary
- `ccaf410` docs: add npm binary / local script parity rule to CLAUDE.md
- `3c2e19a` v1.20.3

---

## 2025-12-31: v1.20.2 Release - Security Review Findings & ReDoS Fix

**Summary:** Comprehensive three-agent review (code, QA, security) identified and fixed ReDoS vulnerability, type safety issues, and version sync problems.

**Session Focus:** Multi-agent code review followed by implementation of security and code quality fixes.

**Changes Made:**
- `SecurityAssessor.ts` - Bounded 6 ReDoS-vulnerable regex patterns with `{0,500}` quantifiers
- `run-security-assessment.ts` - Type-safe property access replaces unsafe `as any` cast
- `moduleScoring.ts` - Version constant synced from 1.12.0 to 1.20.2
- `AssessmentOrchestrator.ts` - Removed unused eslint-disable directive

**Security Fix Details:**
```typescript
// Before (vulnerable to ReDoS):
/"safe"\s*:\s*true[^}]*("message"|"result"|"status"|"response")/i

// After (bounded, safe):
/"safe"\s*:\s*true[^}]{0,500}("message"|"result"|"status"|"response")/i
```

**Validation Results:**
- Tests: 1148 passed, 4 skipped, 0 failed
- A/B Gap: 175 vs 0 vulnerabilities (proves behavior-based detection)
- Precision: 100% (0 false positives on safe tools)
- Lint: 0 errors, 133 warnings (all pre-existing)

**Commits:**
- `a238ac6` fix: address security review findings and version sync
- `33d237e` 1.20.2

---

## 2025-12-31: v1.19.5 Release - Unicode Bypass Security Tests Now Executing in Basic Mode

**Summary:** Fixed Unicode Bypass security tests not being executed in basic mode by adding the pattern to criticalPatterns array, validated with A/B testbed comparison, and published v1.19.5 to npm.

**Session Focus:** Bug investigation using code-reviewer-pro agent, root cause analysis of Unicode Bypass test gap, security assessment validation, and npm package release.

**Changes Made:**
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Added "Unicode Bypass" to criticalPatterns array (lines 342-349)
- Version bump to 1.19.5
- Published @bryan-thompson/inspector-assessment@1.19.5 to npm

**Key Decisions:**
- **Root cause was NOT createTestParameters()**: Code review proved the parameter matching logic works correctly. The actual issue was Unicode Bypass being excluded from basic mode's criticalPatterns array.
- **Added to basic mode**: Unicode Bypass is now the 5th critical pattern tested in basic mode (was 4)
- **A/B validation approach**: Tested against both vulnerable-mcp (167 vulns) and hardened-mcp (0 vulns) to confirm no false positives

**Key Results:**
- Unicode Bypass tests: 0 -> 58
- Vulnerabilities detected: 6 on unicode_processor_tool
- False positives: 0 (A/B validated)
- Total tests: 3422

**Commits:**
- `704ef33` fix(security): add Unicode Bypass to basic mode critical patterns
- `4defa99` chore: bump version to 1.19.5

**Next Steps:**
- Consider adding Nested Injection to criticalPatterns (same exclusion issue)
- Add unit tests for createTestParameters() to prevent future regressions
- Document which patterns are tested in Basic vs Advanced mode

**Notes:**
- Bug report suspected wrong location - code review was essential to find actual root cause
- Docker logs proved payloads were never being sent (not a detection issue)
- Single-line fix with major security coverage impact

---

## 2025-12-31: v1.19.6 Release - AUP Module JSONL Enrichment for Downstream Claude Analysis

**Summary:** Added AUP enrichment to JSONL module_complete events enabling downstream Claude analysis of policy violations

**Session Focus:** Enhancing the AUP (Acceptable Use Policy) module's JSONL output with structured violation data for downstream analysis tools.

**Changes Made:**
- `scripts/lib/jsonl-events.ts` - Added AUP types (AUPViolationSample, AUPViolationMetrics, AUPEnrichment) and buildAUPEnrichment helper function
- `client/src/services/assessment/AssessmentOrchestrator.ts` - Emit AUP enrichment data when module=aup in module_complete events
- `docs/REAL_TIME_PROGRESS_OUTPUT.md` - Documented new AUP event format with field descriptions
- Version bump to 1.19.6
- Updated CLAUDE.md version reference to 1.19.6
- Published @bryan-thompson/inspector-assessment@1.19.6 to npm

**Key Decisions:**
- **Enriched existing event**: Extended module_complete event rather than creating a separate aup_findings event, maintaining consistency with existing JSONL event patterns
- **Severity-prioritized sampling**: Violations sampled CRITICAL > HIGH > MEDIUM, capped at 10 samples to balance detail with payload size
- **Comprehensive metrics**: Added violationMetrics with total/critical/high/medium counts plus byCategory breakdown

**New AUP Enrichment Fields:**
- `violationsSample` - Up to 10 sampled violations, prioritized by severity
- `samplingNote` - Human-readable note about sampling (e.g., "10 of 17 violations shown")
- `violationMetrics` - Aggregated counts: total, critical, high, medium, byCategory
- `scannedLocations` - Array of locations that were scanned
- `highRiskDomains` - Array of detected high-risk domains

**Validation Results:**
- Tested against vulnerable-mcp server
- 17 total violations detected
- 10 violations sampled with correct severity prioritization
- All fields populated correctly in JSONL output

**Commits:**
- `[version bump]` chore: bump version to 1.19.6

**Next Steps:**
- Monitor downstream tool consumption of new AUP enrichment fields
- Consider similar enrichment patterns for other assessment modules
- Add unit tests for buildAUPEnrichment helper

**Notes:**
- This enhancement enables AI-powered analysis pipelines to process AUP findings without parsing full assessment results
- Sampling approach prevents payload bloat while preserving high-severity findings
- JSONL format maintains real-time streaming capability for large assessments

---

## 2025-12-31: v1.19.7 Release - TemporalAssessor False Positive Fix for Accumulation Operations

**Summary:** Fixed TemporalAssessor false positive that flagged accumulation operations like add_observations as rug pull vulnerabilities

**Session Focus:** Bug fix for TemporalAssessor - preventing false positives on stateful accumulation operations

**Changes Made:**
- `client/src/services/assessment/modules/TemporalAssessor.ts` - Added accumulation patterns to STATEFUL_TOOL_PATTERNS, implemented word-boundary regex matching, expanded normalizeResponse counter patterns
- `client/src/services/assessment/__tests__/TemporalAssessor.test.ts` - Added tests for accumulation operations, word-boundary matching, and integration test for add_observations scenario

**Key Decisions:**
- **Word-boundary regex matching**: Used pattern `(^|_|-)pattern($|_|-)` instead of substring matching to prevent false matches (e.g., "address_validator" won't match "add")
- **Accumulation patterns added**: 8 new patterns - add, append, store, save, log, record, push, enqueue
- **Destructive tool priority**: Kept destructive tool check first to ensure tools like "add_and_delete" still get strict comparison

**Technical Details:**
- Root cause: Substring matching caused "add" to match any tool containing those letters
- Fix: Word-boundary regex ensures only exact pattern matches at word boundaries
- Counter field expansion: Added totalRecords, pendingCount, queueLength to normalizeResponse

**Validation Results:**
- All 1148 tests passing
- Verified fix against memory-mcp server (temporal module passes)
- Published as v1.19.7 to npm

**Commits:**
- `fix(temporal)` - Prevent false positives on accumulation operations

**Next Steps:**
- Monitor for any edge cases with new stateful patterns
- Consider adding more counter field patterns as discovered

**Notes:**
- This fix improves precision of rug pull detection while maintaining sensitivity to actual temporal manipulation attacks
- The word-boundary approach is more robust than maintaining an exclusion list
- Pattern applies to tool names like add_observations, append_data, store_result, etc.

---

## 2025-12-31: CLI Module Flag & JSONL Events API Documentation

**Summary:** Added --module flag for individual assessment module execution and created comprehensive JSONL Events API documentation

**Session Focus:** CLI enhancement for module-specific testing and documentation of JSONL event streaming interface

**Changes Made:**
- `scripts/run-security-assessment.ts` - Major refactor: added MODULE_REGISTRY with 13 assessors, --module CLI flag, generic runModule() function, combined results structure
- `docs/JSONL_EVENTS_API.md` - NEW: 1,693-line comprehensive event reference for CLI/auditor integration (11 event types, TypeScript interfaces, integration examples)
- `CLAUDE.md` - Added JSONL API reference in Feature Documentation section
- `/home/bryan/mcp-auditor/CLAUDE.md` - Added Inspector JSONL Output Mapping section with event-to-usage table

**Key Decisions:**
- **Default modules changed**: Now includes both security and aupCompliance (was security only)
- **Full module names only**: No shortcuts like "sec" -> "security" for clarity
- **Comprehensive approach**: ~3-4 hour effort chosen over minimal enhancement to provide complete module access

**Technical Details:**
- All 13 modules now individually testable via CLI:
  - security, aupCompliance, functionality, documentation, errorHandling
  - usability, mcpSpec, toolAnnotations, prohibitedLibraries, manifestValidation
  - portability, externalAPIScanner, temporal
- Backward compatibility: deprecated --aup flag still works
- Combined results structure when running multiple modules

**Commits:**
- `8bf6813` feat(cli): add --module flag for individual assessment module execution

**Next Steps:**
- Test module combinations in CI/CD pipeline
- Update mcp-auditor to consume new JSONL events
- Consider adding module-specific CLI flags for common patterns

**Notes:**
- JSONL Events API doc covers all 11 event types with TypeScript interfaces
- Module registry pattern enables easy addition of future assessment modules
- Documentation enables third-party tool integration with inspector output stream

---

## 2025-12-31: JSONL Annotation Event Alignment with MCP Auditor

**Summary:** Completed JSONL annotation event alignment between inspector and MCP Auditor, adding missing handlers and publishing v1.20.1

**Session Focus:** JSONL Events API alignment and annotation event implementation

**Changes Made:**
- `docs/JSONL_EVENTS_API.md` - Version bump 1.19.5 to 1.20.0, fixed 14 version references in examples
- `scripts/run-security-assessment.ts` - Added annotation event emission handlers for onProgress callback pattern
- `package.json` (all 4 packages) - Version 1.20.1
- MCP Auditor `server/workers/audit-worker.js` - Added annotation_missing handler (line 1472), DB storage for annotation_misaligned
- MCP Auditor `docs/INSPECTOR_JSONL_ALIGNMENT.md` - Updated handler status and line numbers
- `/tmp/mcp-auditor-annotation-test-instructions.md` - Created test instructions for auditor team

**Key Decisions:**
- Follow existing annotation handler pattern in auditor (WebSocket + DB storage + console log)
- Support both camelCase and snake_case field names for compatibility
- Emit annotation events through onProgress callback pattern in CLI

**Commits:**
- Inspector: f41e974, 795fbdf, 9a85ef5, d6fcce1 (v1.20.1)
- MCP Auditor: ed5d934e, c662106b, 5d6c6efd

**Next Steps:**
- MCP Auditor team to test annotation event flow using exported instructions
- Verify WebSocket progress updates in auditor UI
- Verify DB storage of annotation events

**Notes:**
- All 11 JSONL events now handled by MCP Auditor (was 10/11)
- annotation_missing was the only unhandled event
- Code review found and fixed annotation_misaligned missing DB storage
- Both projects now fully aligned on JSONL event streaming interface

---

## 2025-12-31: Three-Agent Code Review and v1.20.2 Release

**Summary:** Comprehensive three-agent code review identified and fixed ReDoS vulnerability, type safety issues, and version sync; published v1.20.2 to npm

**Session Focus:** Multi-agent code review using code-reviewer-pro, qa-expert, and security-auditor agents, followed by implementing identified fixes and releasing v1.20.2

**Changes Made:**
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Fixed ReDoS vulnerability (6 regex patterns bounded with `{0,500}`)
- `scripts/run-security-assessment.ts` - Replaced unsafe `as any` with proper type guard
- `client/src/lib/moduleScoring.ts` - Synced INSPECTOR_VERSION from 1.12.0 to 1.20.2
- `client/src/services/assessment/AssessmentOrchestrator.ts` - Removed unused eslint-disable directive
- `.gitignore` - Added security/ directory
- `CHANGELOG.md` - Added v1.20.1 and v1.20.2 entries

**Key Decisions:**
- Bounded regex quantifiers (`{0,500}`) prevent ReDoS from malicious server responses
- Type guards preferred over `as any` for TypeScript safety
- Security audit reports kept local (not committed)

**Key Results:**
- Review Grades: Code (GOOD), QA (A-), Security (B+)
- Tests: 1148 passed, 0 failed
- A/B validation: 175 vs 0 vulnerabilities
- Published v1.20.2 to npm

**Next Steps:**
- Consider adding assessment resume capability
- Add automated A/B comparison tool
- Add retry logic with exponential backoff

**Notes:**
- Security audit report saved to /home/bryan/inspector/security/SECURITY_AUDIT_REPORT.md
- All 133 lint warnings are pre-existing no-explicit-any
- Three-agent review process provides comprehensive coverage: code quality, QA, and security

---
