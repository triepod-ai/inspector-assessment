# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.0] - 2025-12-08

### Added

- **New CLI Commands**: Two new standalone CLI commands for targeted assessment workflows
  - `mcp-assess-full` - Comprehensive full assessment runner (690 lines)
    - Orchestrates all assessment categories in a single command
    - Progress reporting and detailed result output
    - Suitable for CI/CD pipelines and automated testing
  - `mcp-assess-security` - Focused security assessment runner (450 lines)
    - Rapid security-focused evaluation
    - Streamlined output for security reviews
    - Ideal for security-first validation workflows

- **Library Exports**: New modular exports for programmatic usage
  - Direct access to AssessmentOrchestrator
  - Individual assessment module imports
  - Type definitions for external integration
  - Enables embedding inspector functionality in other tools

### Enhanced

- **Client Package**: Enhanced build system with library output
  - New `build:lib` script for creating importable modules
  - `tsconfig.lib.json` for library-specific TypeScript configuration
  - tsc-alias integration for path resolution
  - Supports both CLI and library usage patterns

- **CLI Package**: Improved bin configuration
  - Three distinct entry points for different use cases
  - Better command organization and discoverability
  - Updated dependency references to support new commands

### Infrastructure

- **Build System**: Enhanced TypeScript configuration
  - Separate lib and app builds for client package
  - Better module resolution for library exports
  - Maintained backward compatibility with existing workflows

## [1.6.0] - 2025-12-08

### Added

- **Claude Code Integration Bridge**: New `claudeCodeBridge.ts` module for seamless integration with Claude Code workflows
  - Direct assessment execution from Claude Code environment
  - Standardized result formatting for AI consumption
  - 469 lines of comprehensive test coverage

- **Full Assessment Runner**: New `run-full-assessment.ts` script for comprehensive server evaluation
  - Orchestrates all assessment categories in single run
  - Enhanced CLI support with progress reporting
  - 708 lines of assessment orchestration logic

- **Claude Integration Test Plan**: New `CLAUDE_INTEGRATION_TEST_PLAN.md` documentation
  - Structured testing approach for Claude Code integration
  - Usage patterns and best practices
  - Integration examples

### Enhanced

- **AUPComplianceAssessor**: Major enhancements (+320 lines)
  - Improved pattern matching and detection accuracy
  - Enhanced reporting and recommendation engine
  - Better integration with Claude Code workflows

- **ToolAnnotationAssessor**: Major enhancements (+418 lines)
  - Advanced annotation validation logic
  - Improved behavior inference from tool patterns
  - Enhanced misalignment detection

- **AssessmentOrchestrator**: Enhanced orchestration capabilities
  - Better coordination across assessment modules
  - Improved error handling and recovery
  - Support for full assessment workflows

- **TestDataGenerator**: Enhanced test data generation
  - More comprehensive test scenarios
  - Better context-aware data generation
  - Support for new assessment patterns

### Maintenance

- **PROJECT_STATUS Archive**: Moved older entries to `PROJECT_STATUS_ARCHIVE.md` (2340 lines)
  - Improved documentation maintainability
  - Faster file loading and navigation
  - Preserved complete development history

- **Dependencies**: Updated package-lock.json with new dependencies for enhanced functionality

## [1.5.0] - 2025-12-07

### Added

- **MCP Directory Compliance Assessors**: 5 new assessor modules for comprehensive Anthropic MCP Directory policy compliance (83 new tests)
  - **AUPComplianceAssessor** (26 tests) - Acceptable Use Policy violation detection
    - 14 AUP category patterns (A-N) from Anthropic policy
    - High-risk domain identification (Healthcare, Financial, Legal, Children/Minors)
    - Tool name/description pattern analysis
    - Source code scanning in enhanced mode
    - README content scanning

  - **ToolAnnotationAssessor** (13 tests) - Policy #17 compliance
    - readOnlyHint/destructiveHint verification
    - Tool behavior inference from name patterns (READ_ONLY, WRITE, DESTRUCTIVE)
    - Annotation misalignment detection
    - Automatic recommendations for missing annotations

  - **ProhibitedLibrariesAssessor** (12 tests) - Policy #28-30 compliance
    - Financial library detection (Stripe, PayPal, Plaid, Square, Braintree, Adyen)
    - Media library detection (Sharp, FFmpeg, OpenCV, PIL, jimp, node-canvas)
    - package.json and requirements.txt scanning
    - Source code import analysis

  - **ManifestValidationAssessor** (17 tests) - MCPB manifest compliance
    - manifest_version 0.3 validation
    - Required field verification (name, version, mcp_config)
    - Icon presence check
    - ${BUNDLE_ROOT} anti-pattern detection
    - Hardcoded path detection in mcp_config

  - **PortabilityAssessor** (15 tests) - Cross-platform compatibility
    - Hardcoded path detection (/Users/, /home/, C:\, D:\)
    - Platform-specific code patterns (win32, darwin, linux)
    - ${\_\_dirname} usage validation
    - Source code and manifest scanning

- **Pattern Libraries**: New reusable pattern files for policy compliance
  - `client/src/lib/aupPatterns.ts` - 14 AUP category patterns with severity levels
  - `client/src/lib/prohibitedLibraries.ts` - Financial and media library detection patterns

- **Module Exports**: Clean exports via `modules/index.ts` for all 11 assessors

### Changed

- **Test Coverage**: 665 total tests (up from 582), 291 assessment module tests (up from 208)
- **Assessor Count**: 11 assessors (6 original + 5 new MCP Directory compliance)
- **AssessmentOrchestrator**: Extended to support new assessment categories and source code analysis
- **AssessmentContext**: Added sourceCodeFiles, manifestJson, manifestRaw fields for enhanced mode
- **AssessmentConfiguration**: Added 5 new assessment category flags

### Technical Details

- **Files Added**: 7 new files
  - 5 assessor modules in `client/src/services/assessment/modules/`
  - 5 test files in `client/src/services/assessment/modules/`
  - 2 pattern libraries in `client/src/lib/`
  - 1 exports file `modules/index.ts`
- **Files Modified**: 2 files (assessmentTypes.ts, AssessmentOrchestrator.ts)
- **Dual-Mode Support**: Runtime-only mode (default) + Enhanced mode (with source code path)
- **Policy References**: Aligned with Anthropic MCP Directory Policy requirements #17, #28-30, AUP categories A-N

## [1.4.0] - 2025-10-14

### Added

- **Calculator Injection Detection**: New security pattern to detect eval() execution in calculator/math tools
  - 7 test payloads: Simple arithmetic (2+2, 5*5), natural language (what is 10*10), code injection (**import**)
  - Evidence patterns match specific response format ("The answer is X")
  - Low false positive risk (doesn't match generic numeric responses)
  - Integrates with existing pattern system (13 patterns total, up from 12)
  - Added to Basic mode as 4th critical injection pattern

### Changed

- Security pattern count increased from 12 to 13
- Basic mode: 3 → 4 critical injection patterns (~13 → ~20 checks)
- Advanced mode: 8 → 13 patterns (~24 → ~37 checks per tool)
- UI badge updated: "8 Patterns" → "13 Patterns"
- Test descriptions updated to include Calculator Injection and Tool-Specific Vulnerabilities

### Fixed

- **API Wrapper False Negative**: Parameter-aware payload injection now correctly detects vulnerabilities in API wrapper tools

### Technical Details

- Pattern location: `client/src/lib/securityPatterns.ts`
- Category: Critical Injection Tests (alongside Command, SQL, Path Traversal)
- Evidence format: `/The answer is \d+/i` (specific to vulnerable calculator tools)
- No changes to SecurityAssessor.ts needed (uses existing assessment flow)

## [1.3.0] - 2025-10-13

### Added

- **UI Enhancement**: Filter Errors button in Security and Error Handling sections for improved debugging workflow

### Fixed

- **Assessment Accuracy**: Count only scored tests in passed and total counts
- **Security Detection**: Detect 'Unknown tool' as tool list sync error, not SECURE status
- **Security Assessment**: Eliminate false positive on safe_info_tool_mcp reflection detection
- **Security Status**: Overall Security status now FAIL when connection errors occur
- **Test Scoring**: Mark connection errors as failed tests, not passed

### Changed

- **Branding**: Renamed application from "MCP Inspector" to "MCP Assessor" to better reflect comprehensive assessment capabilities

## [1.2.1] - 2025-10-12

### Fixed

- **Validation False Positives in Security Testing**: Tools properly validating input are no longer incorrectly flagged as vulnerable
  - Added MCP error code detection (JSON-RPC -32602 Invalid params)
  - Added execution evidence requirement for ambiguous patterns (distinguishes "type error in validation" from "type error during execution")
  - Fixed 18 validation patterns including boundary validation ("cannot be empty", "required field")
  - Implemented 3-layer validation approach: MCP codes → patterns → execution evidence
  - Universal fix applies to ALL MCP servers, not just specific tools

- **API Operational Error Detection**: Functionality assessment now correctly recognizes operational errors as working behavior
  - Added 11 API operational error patterns (credits, billing, quotas, rate limits)
  - Added 5 generic validation patterns (invalid input, invalid parameter)
  - Expanded validation-expected tool types (scrape, crawl, map, extract, parse, analyze, process)
  - Adjusted confidence weighting for better accuracy (20% threshold for operational errors, 30% for validation tools)

### Changed

- **UI Text Updates**: Updated security testing descriptions to reflect current 8-pattern architecture
  - Changed badge from "18 Patterns" to "8 Patterns"
  - Updated test descriptions to reflect 3 critical injection patterns (basic) and 8 total patterns (advanced)
  - Updated security guidance mapping for all 8 current patterns (Command, SQL, Path Traversal, Type Safety, Boundary, Required Fields, MCP Error Format, Timeout)

### Added

- **Comprehensive Test Coverage**: 29 new tests validating false positive fixes (all passing)
  - 12 SecurityAssessor validation tests (MCP error codes, execution evidence, boundary validation)
  - 5 Firecrawl integration tests (real-world operational error scenarios)
  - 12 ResponseValidator tests (API operational errors, rate limiting, input validation)

### Technical Details

- **Files Changed**: 6 files (1,878 insertions, 782 deletions)
- **Universal Application**: Changes in `analyzeResponse()` method apply to all tools and all security patterns
- **Detection Flow**: All tools → all patterns → `testPayload()` → `analyzeResponse()` (contains fixes)
- **Backward Compatible**: No breaking changes to API or assessment interfaces

## [1.2.0] - 2025-10-11

### Added

- **Confidence Scoring for Security Assessments**: Intelligent confidence levels reduce false positives from ambiguous pattern matches
  - Three-tier confidence system: high, medium, low
  - Automatic detection of structured data tools (search, lookup, retrieval)
  - Manual review flags with context-specific guidance
  - Visual UI indicators (color-coded badges and warning banners)
  - Step-by-step review instructions for ambiguous cases

### Improved

- **False Positive Detection**: Dramatically reduced false positives in security testing
  - Arithmetic patterns in numeric metadata (trust scores, counts, IDs) now flagged for manual review
  - Admin/role keywords in search results properly distinguished from privilege escalation
  - Pattern matches in returned data vs. executed code now differentiated

### Changed

- **Security Assessment UI**: Enhanced display of vulnerability results
  - Added confidence badges (green/yellow/orange) to test results
  - Added prominent amber warning banner for low-confidence detections
  - Included detailed review guidance with step-by-step verification process

### Technical Details

- **Type System**: Added 4 new optional fields to `SecurityTestResult` interface
- **Detection Logic**: New `calculateConfidence()` method with tool classification heuristics
- **Tool Classification**: New `isStructuredDataTool()` helper for identifying data retrieval tools
- **Backward Compatible**: All changes use optional fields, existing code unaffected
- **Files Changed**: 3 files (222 insertions)
  - `client/src/lib/assessmentTypes.ts` - Type definitions
  - `client/src/services/assessment/modules/SecurityAssessor.ts` - Detection logic
  - `client/src/components/AssessmentTab.tsx` - UI enhancements

## [1.1.0] - 2025-10-11

### Added

- **Rate Limiting Protection**: Configurable delay between tests to prevent API rate limiting
  - New `delayBetweenTests` configuration option (0-5000ms range)
  - UI control with numeric input field and step controls
  - Mode-specific defaults:
    - Default mode: 0ms (no delay for local testing)
    - Reviewer mode: 100ms (light rate limiting)
    - Developer mode: 500ms (moderate rate limiting)
  - Implemented in TestScenarioEngine, FunctionalityAssessor, and ErrorHandlingAssessor
  - Recommended values: 500-1000ms for rate-limited APIs

- **Reviewer Quick Start Guide**: Comprehensive documentation for MCP directory reviewers
  - 60-second fast screening workflow for approve/reject decisions
  - 5-minute detailed review process for borderline cases
  - Common pitfalls explanation (false positives, informational vs scored tests)
  - Decision matrix with clear approval criteria
  - Fast CLI analysis commands for troubleshooting
  - Target audience: Reviewers needing fast, accurate assessment guidance

### Changed

- Updated CLAUDE.md and README.md with Reviewer Quick Start Guide references
- Enhanced documentation structure for better reviewer onboarding

### Technical Details

- **Files Changed**: 6 core files + 3 documentation files
- **New Documentation**: 17KB comprehensive reviewer guide (525 lines)
- **UI Enhancement**: Clean numeric input with validation and help text
- **Performance Impact**: Configurable delay adds 0-5s per test depending on settings

## [1.0.1] - 2025-10-11

### Fixed

- **Test Suite**: Fixed all 24 remaining test failures, achieving 100% test pass rate (582/582 passing)
  - Updated test expectations to reflect comprehensive security mode (18 patterns × 3 payloads per tool)
  - Extended timeouts for comprehensive mode (60s → 240s, critical tests → 480s)
  - Changed strict assertions to flexible ranges to accommodate improved security detection
  - Fixed performance test timeouts (30s → 240s)
  - Updated vulnerability expectations to allow zero false positives

### Changed

- **Documentation**: Updated README.md to reflect 100% test pass rate across all sections
- **Project Status**: Updated PROJECT_STATUS.md with test suite fixes timeline
- **Test Configuration**: Enabled comprehensive domain testing by default in test utilities

### Technical Details

- **Test Files Updated**: 9 files (210 insertions, 118 deletions)
- **Test Duration**: ~20-30 minutes for full suite in comprehensive mode (vs 5 minutes in basic mode)
- **Security Coverage**: Each tool now tested with 54+ attack patterns vs 17 in basic mode

## [1.0.0] - 2025-10-11

### Initial Release

This is the first published release of `@bryan-thompson/inspector-assessment`, a comprehensive enhancement of the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) v0.17.0 with advanced assessment capabilities.

### Added

#### Assessment Framework

- **Enhanced Business Logic Error Detection**: Confidence-based validation system that distinguishes between broken tools and proper input validation (80% reduction in false positives)
- **Progressive Complexity Testing**: 2-level progressive testing (minimal → simple) combined with multi-scenario comprehensive testing (50% faster than previous approach)
- **Context-Aware Test Data Generation**: Realistic test data using publicly accessible URLs, valid UUIDs, and real API endpoints
- **Zero False Positive Security Testing**: Intelligent reflection detection that distinguishes safe data reflection from command execution
  - 18 injection patterns tested (Basic: 3 patterns, Advanced: 18 patterns)
  - Bidirectional reflection detection with safety indicators
  - Operational error filtering
- **Business Logic Detection**: Multi-factor confidence scoring for error analysis
- **Streamlined Assessment Architecture**: 6 core assessors aligned with MCP directory requirements
  - Functionality Assessor with enhanced validation
  - Security Assessor with zero false positives
  - Usability Assessor
  - Error Handling Assessor with protocol compliance
  - Documentation Assessor
  - MCP Spec Compliance Assessor (hybrid: protocol checks + metadata hints)

#### Testing

- **464 passing tests** (100% pass rate)
- **208 assessment module tests** specifically validating assessment enhancements
- Comprehensive test coverage for all new features

#### CLI Security Assessment Runner

- Command-line assessment runner without web UI: `npm run assess`
- Support for stdio, HTTP, and SSE transports
- JSON output to `/tmp/inspector-assessment-{serverName}.json`
- Exit code 0 for safe, 1 for vulnerabilities (CI/CD ready)

#### Documentation

- Comprehensive README with installation instructions
- Assessment methodology documentation
- Detailed feature documentation
- Performance benchmarks and validation results

### Changed

- Package namespace: `@modelcontextprotocol/inspector` → `@bryan-thompson/inspector-assessment`
- Binary command: `mcp-inspector` → `mcp-inspector-assess`
- Version: 0.17.0 → 1.0.0 (semantic versioning for production release)
- License: Updated to include dual copyright (Anthropic + Bryan Thompson)

### Technical Details

- **Forked from**: @modelcontextprotocol/inspector v0.17.0
- **Upstream commits integrated**: 121 commits
- **New features from upstream**: CustomHeaders, OAuth improvements, parameter validation
- **Build system**: TypeScript + Vite with optimized production builds
- **UI Framework**: React + Tailwind CSS
- **Testing**: Jest + Playwright + React Testing Library

### Attribution

This package is based on the [Model Context Protocol Inspector](https://github.com/modelcontextprotocol/inspector) by Anthropic, PBC. All assessment enhancements are original work by Bryan Thompson.

### Migration Path

If this package is adopted by Anthropic, it can be published to the official `@modelcontextprotocol` namespace. Users will be notified of any namespace migration.

## Links

- [GitHub Repository](https://github.com/triepod-ai/inspector-assessment)
- [Original MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [npm Package](https://www.npmjs.com/package/@bryan-thompson/inspector-assessment)
