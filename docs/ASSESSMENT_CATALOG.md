# MCP Inspector Assessment Catalog

A comprehensive reference for all assessment modules in the MCP Inspector Assessment tool.

## Overview

The MCP Inspector Assessment runs **18 active modules** organized in **4 tiers** (plus 1 opt-in module and 1 deprecated module) to validate MCP servers for functionality, security, protocol compliance, and Anthropic MCP Directory policy adherence.

### Module Tier Organization (v1.25.0+)

| Tier                      | Modules | Purpose                               | Profile Required |
| ------------------------- | ------- | ------------------------------------- | ---------------- |
| **Tier 1: Core Security** | 6       | Essential security validation         | `quick`          |
| **Tier 2: Compliance**    | 4       | MCP Directory requirements            | `compliance`     |
| **Tier 3: Capability**    | 3       | Resource/Prompt testing (conditional) | `full`           |
| **Tier 4: Extended**      | 4       | Developer experience & code quality   | `full`           |

### CLI Profiles

```bash
# Fast CI/CD check (~30 seconds)
mcp-assess-full my-server --profile quick

# Security-focused audit (~2-3 minutes)
mcp-assess-full my-server --profile security

# MCP Directory submission check (~5 minutes)
mcp-assess-full my-server --profile compliance

# Comprehensive audit (~10-15 minutes)
mcp-assess-full my-server --profile full
```

### All Module Names (for `--profile` / `--skip-modules` / `--only-modules`)

```
Tier 1 (Core Security):
  functionality, security, temporal, protocolCompliance, aupCompliance

Tier 2 (Compliance):
  toolAnnotations, prohibitedLibraries, manifestValidation, authentication

Tier 3 (Capability-Based):
  resources, prompts, crossCapability

Tier 4 (Extended):
  developerExperience, portability, externalAPIScanner*, fileModularization
```

\* `externalAPIScanner` only runs when `--source` flag is provided

### Deprecated Module Names (backward compatible)

The following module names are deprecated but still work via aliasing:

| Old Name              | New Name              | Migration |
| --------------------- | --------------------- | --------- |
| `documentation`       | `developerExperience` | Merged    |
| `usability`           | `developerExperience` | Merged    |
| `mcpSpecCompliance`   | `protocolCompliance`  | Merged    |
| `protocolConformance` | `protocolCompliance`  | Merged    |

### Scoring

- **Pass**: All critical checks pass, no high-severity issues
- **Fail**: Critical security vulnerabilities or blocking policy violations
- **Warning**: Medium-severity issues requiring review

---

## Core Modules (Always Run)

### 1. Functionality Assessment

**Purpose**: Validate that MCP tools work correctly with realistic inputs.

**Test Approach**:

- Multi-scenario validation with progressive complexity (2 levels)
- Context-aware test data generation based on parameter semantics
- Business logic error detection via response analysis
- Coverage tracking across all tools

**Key Tests**:
| Test Type | Description |
|-----------|-------------|
| Basic Invocation | Can each tool be called without errors? |
| Parameter Validation | Does the tool validate required parameters? |
| Response Structure | Does the response match expected MCP format? |
| Business Logic | Does the tool perform its stated function? |
| Edge Cases | How does the tool handle boundary inputs? |

**Pass Criteria**:

- ≥80% of tools return successful responses
- No tools crash or hang
- Response format matches MCP specification

**Implementation**: `client/src/services/assessment/modules/FunctionalityAssessor.ts` (225 lines)

---

### 2. Security Assessment

**Purpose**: Detect backend API security vulnerabilities with zero false positives.

**Test Approach**:

- 30 distinct attack patterns with context-aware reflection detection
- Pure behavior-based detection (no metadata reliance)
- Domain-specific payloads based on parameter semantics
- Confidence levels (high/medium/low) for findings
- **Annotation-aware severity adjustment** (Issue #170): Reduces false positives by considering tool annotations (readOnlyHint, openWorldHint) when scoring vulnerability severity

**31 Attack Patterns** (organized by category):

| #                           | Attack Type                      | Risk   | Description                                                          |
| --------------------------- | -------------------------------- | ------ | -------------------------------------------------------------------- |
| **Critical Injection (7)**  |                                  |        |
| 1                           | Command Injection                | HIGH   | Tests for shell command execution (`whoami`, `ls -la`, `; rm -rf /`) |
| 2                           | AppleScript Command Injection    | HIGH   | Tests for AppleScript/osascript execution via string interpolation   |
| 3                           | SQL Injection                    | HIGH   | Tests for SQL command execution (`'; DROP TABLE`, `' OR '1'='1`)     |
| 4                           | Calculator Injection             | HIGH   | Tests for eval() execution (`2+2`, `__import__('os').system()`)      |
| 5                           | Path Traversal                   | HIGH   | Tests for file system access (`../../../etc/passwd`, `file://`)      |
| 6                           | XXE Injection                    | HIGH   | Tests for XML External Entity attacks (file disclosure, SSRF)        |
| 7                           | NoSQL Injection                  | HIGH   | Tests for MongoDB/Redis command execution (`$gt`, `$where`, EVAL)    |
| **Input Validation (3)**    |                                  |        |
| 8                           | Type Safety                      | MEDIUM | Tests parameter type validation (string vs number)                   |
| 9                           | Boundary Testing                 | MEDIUM | Tests edge cases (empty strings, 10K characters, negatives)          |
| 10                          | Required Fields                  | MEDIUM | Tests missing parameter handling                                     |
| **Protocol Compliance (2)** |                                  |        |
| 11                          | MCP Error Format                 | LOW    | Verifies error responses follow MCP spec                             |
| 12                          | Timeout Handling                 | LOW    | Tests long operation graceful handling                               |
| **Tool-Specific (7)**       |                                  |        |
| 13                          | Indirect Prompt Injection / SSRF | HIGH   | Tests URL fetching, localhost, cloud metadata, internal IPs          |
| 14                          | Unicode Bypass                   | MEDIUM | Tests unicode-encoded command execution                              |
| 15                          | Nested Injection                 | MEDIUM | Tests hidden instructions in nested JSON                             |
| 16                          | Package Squatting                | MEDIUM | Tests typosquatted package download attempts                         |
| 17                          | Data Exfiltration                | HIGH   | Tests credential/secret/env var leakage attempts                     |
| 18                          | Configuration Drift              | HIGH   | Tests privilege escalation via config (`set admin=true`)             |
| 19                          | Tool Shadowing                   | HIGH   | Tests tool creation/override attempts                                |
| **Resource Exhaustion (1)** |                                  |        |
| 20                          | DoS/Resource Exhaustion          | HIGH   | Tests ReDoS, deep JSON nesting, zip bombs, XML billion laughs        |
| **Deserialization (1)**     |                                  |        |
| 21                          | Insecure Deserialization         | HIGH   | Tests pickle, Java serialized objects, YAML exploits                 |

**Pass Criteria**:

- Zero HIGH risk vulnerabilities
- No command/SQL/path traversal execution
- Proper input validation demonstrated

**Configuration Options**:

```typescript
{
  securityPatternsToTest?: number;    // Number of patterns to test (default 8)
  enableDomainTesting?: boolean;      // Advanced testing (default true)
  selectedToolsForTesting?: string[]; // Specific tools to test (default: all)
  securityTestTimeout?: number;       // Per-payload timeout in ms (default: 5000)
}
```

The `securityTestTimeout` option allows optimization of security assessment speed. It sets a timeout specifically for payload-based security tests, enabling faster scans on servers with slow-responding tools without impacting functionality test timeouts. See [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md#option-security-test-timeout) for configuration examples.

**Annotation-Aware Severity Adjustment** (Issue #170):

The security assessor automatically adjusts vulnerability severity based on tool annotations to reduce false positives:

- **Read-Only Tools** (`readOnlyHint: true`): Execution-type attacks (Command Injection, AppleScript Command Injection, Code Execution, Path Traversal) are downgraded from HIGH/MEDIUM to LOW
- **Closed-World Tools** (`openWorldHint: false`): Exfiltration-type attacks (SSRF, Data Exfiltration, Token Theft) are downgraded from HIGH/MEDIUM to LOW
- **Server-Level Flags**: If ALL tools are read-only or closed-world, server-level adjustments apply even without per-tool annotations
- **Transparency**: All adjustments are tracked in `SecurityTestResult.annotationAdjustment` with original severity, adjusted severity, and reason

**Implementation**:

- Core: `client/src/services/assessment/modules/SecurityAssessor.ts` (443 lines)
- Severity Adjustment: `client/src/services/assessment/modules/securityTests/AnnotationAwareSeverity.ts`
- Annotation Extraction: `client/src/services/assessment/helpers/ToolAnnotationExtractor.ts`

---

### 3. Error Handling Assessment

> **Note**: Error handling assessment has been merged into the Protocol Compliance module (Issue #188). This section is maintained for reference and backward compatibility. See [Protocol Compliance](#6-protocol-compliance-unified) for current implementation.

**Purpose**: Validate MCP protocol compliance and error response quality.

**Test Approach**:

- Send invalid inputs across multiple error categories
- Analyze error response structure and content
- Score compliance with MCP specification
- Test resilience to malformed requests

**Error Categories Tested**:
| Category | Description |
|----------|-------------|
| Invalid Parameters | Wrong types, missing required fields |
| Malformed JSON | Invalid JSON structure |
| Unknown Methods | Non-existent tool names |
| Out-of-Range Values | Numbers beyond valid bounds |
| Invalid Encoding | Malformed unicode, binary data |

**Pass Criteria**:

- Error responses include `isError: true` flag
- Error messages are descriptive (not generic)
- No stack traces or internal details exposed
- Server remains stable after errors

**Graceful Degradation Recognition** (Issue #173):

The assessor recognizes graceful degradation patterns for optional parameters and rewards helpful error messages:

- **Optional Parameter Handling**: Tools that return neutral responses (empty arrays, "no results found") for optional empty parameters receive +15 bonus points instead of penalties
- **Suggestion Detection**: Error messages containing "Did you mean", "Valid options", "Available" patterns receive +10 bonus points
- **Required vs Optional**: Only penalizes poor handling of **required** parameters; optional parameter graceful handling is valid behavior

**Scoring Bonuses**:
| Scenario | Bonus Points |
|----------|--------------|
| Graceful degradation on optional param | +15 |
| Error with suggestions ("Did you mean...") | +10 |
| Specific field name in error message | +10 |
| Descriptive error message (>30 chars) | +5 |
| Proper error code included | +5 |

**Graceful Response Patterns Recognized**:

- Empty JSON arrays/objects: `[]`, `{}`
- "No results found", "returned 0 items"
- "Empty list", "no data", "no matching"
- JSON with empty results: `{"results": []}`

**Backward Compatibility** (Issue #188):

- Assessment results still include `errorHandling` field for compatibility
- Config flag `errorHandling` is now an alias for `protocolCompliance`
- Both flags enable the unified Protocol Compliance module

**Implementation**: `client/src/services/assessment/modules/ProtocolComplianceAssessor/ErrorHandlingTests.ts` (modular structure)

---

### 4. Documentation Assessment

**Purpose**: Evaluate README completeness and API documentation quality.

**Test Approach**:

- Parse README.md structure and content
- Extract and validate code examples
- Check for required documentation sections
- Assess parameter documentation completeness

**Documentation Checks**:
| Check | Description |
|-------|-------------|
| README Existence | Does README.md exist in root? |
| Installation Instructions | Clear setup steps provided? |
| Usage Examples | Code examples for key tools? |
| Tool Documentation | Each tool described with parameters? |
| License Information | Open source license specified? |

**Pass Criteria**:

- README exists with basic structure
- At least one usage example provided
- Tool descriptions match actual behavior

**Implementation**: `client/src/services/assessment/modules/DocumentationAssessor.ts` (274 lines)

---

### 5. Usability Assessment

**Purpose**: Evaluate naming conventions and API design quality.

**Test Approach**:

- Analyze tool and parameter naming patterns
- Check for consistent conventions
- Evaluate parameter clarity and discoverability
- Score against best practices

**Usability Checks**:
| Check | Description |
|-------|-------------|
| Naming Consistency | snake_case, camelCase, or kebab-case used consistently? |
| Descriptive Names | Do tool names convey purpose? |
| Parameter Clarity | Are required vs optional params clear? |
| Type Annotations | Are parameter types specified? |
| Verb Prefixes | Do action tools use verbs (get, create, delete)? |

**Pass Criteria**:

- Consistent naming convention used
- Tool purposes clear from names
- Parameters have descriptions

**Implementation**: `client/src/services/assessment/modules/UsabilityAssessor.ts` (290 lines)

---

## Core Modules: MCP Directory Compliance

These core modules validate compliance with Anthropic's MCP Directory Policy requirements.

### 6. Protocol Compliance (Unified)

**Purpose**: Verify adherence to MCP protocol specification and conformance requirements.

> **v1.25.3**: This module unifies error handling validation, MCP spec compliance, and protocol conformance into a single `ProtocolComplianceAssessor` (Issue #188). The deprecated modules remain exported for backwards compatibility.

**Test Approach**:

- Hybrid validation combining static and dynamic checks
- JSON-RPC 2.0 compliance verification
- Protocol message format validation
- Response structure conformance testing
- Error response format validation
- Content type support validation
- Initialization handshake validation
- Multi-source transport detection (server.json, package.json, source code, runtime config)

**Protocol Checks**:
| Check | Description |
|-------|-------------|
| JSON-RPC 2.0 | Proper id, jsonrpc, method, params fields |
| Tool Schema | Valid inputSchema for all tools |
| Response Format | Proper content array with type/text |
| Error Format | Standard error codes and messages |
| Capabilities | Valid capability declarations |
| Error Response Format | Validates `isError: true` flag, content array |
| Content Type Support | Validates all content items use valid MCP types |
| Initialization Handshake | Validates serverInfo.name, version, capabilities |
| Error Handling Quality | Descriptive messages, graceful degradation (Issue #188) |
| Invalid Input Resilience | Server stability with malformed requests (Issue #188) |

**Pass Criteria**:

- All tool calls return valid JSON-RPC responses
- Error codes match MCP specification
- No protocol violations detected
- Error responses include `isError: true` flag
- Server provides name during initialization

**Transport Detection** (Issue #172):

The module uses `StdioTransportDetector` to accurately detect stdio transport from multiple sources, fixing false failures (C6/F6) for valid stdio servers:

1. **server.json manifest** - `packages[0].transport.type` field (highest confidence)
2. **package.json bin entries** - Indicates CLI/stdio capability (high confidence)
3. **Source code patterns** - Scans for `StdioServerTransport`, `mcp.run(transport="stdio")`, stdin/stdout usage (medium confidence)
4. **Runtime config** - Actual transport used for the assessment connection (highest confidence)

Detection results include:

- Set of detected transport modes (stdio, http, sse)
- Overall confidence level (high/medium/low)
- Detailed evidence from each source
- Boolean flags for quick checks (supportsStdio, supportsHTTP, supportsSSE)

**Module Structure** (Issue #188 - Modularized):

The unified ProtocolComplianceAssessor uses a modular directory structure:

```
ProtocolComplianceAssessor/
├── index.ts                    # Main orchestrator
├── ErrorHandlingTests.ts       # Error handling validation
├── ProtocolConformanceTests.ts # Protocol conformance checks
└── MCPSpecComplianceTests.ts   # MCP spec compliance
```

**Backward Compatibility**:

- `errorHandling` result field still populated via `additionalResultFields` pattern
- Config flag `errorHandling` is an alias for `protocolCompliance`
- Deprecated assessors (ErrorHandlingAssessor, MCPSpecComplianceAssessor, ProtocolConformanceAssessor) re-exported for compatibility

**Implementation**:

- `client/src/services/assessment/modules/ProtocolComplianceAssessor/` (modular directory)
- `client/src/services/assessment/helpers/StdioTransportDetector.ts` (Issue #172)

---

### 7. AUP Compliance

**Purpose**: Detect Acceptable Use Policy violations per Anthropic policy.

**Reference**: [Anthropic AUP](https://www.anthropic.com/policies/aup)

**14 AUP Categories (A-N)**:

| Cat | Name                    | Severity | Description                               |
| --- | ----------------------- | -------- | ----------------------------------------- |
| A   | CSAM                    | CRITICAL | Child sexual abuse material               |
| B   | WMD                     | CRITICAL | Weapons of mass destruction               |
| C   | Malware                 | CRITICAL | Malware/cyberweapons creation             |
| D   | Disinformation          | HIGH     | Election interference, fake news          |
| E   | Fraud                   | HIGH     | Phishing, scams, identity theft           |
| F   | Harassment              | HIGH     | Stalking, doxxing, cyberbullying          |
| G   | Privacy                 | HIGH     | Unauthorized surveillance, PII scraping   |
| H   | Unauthorized Practice   | MEDIUM   | Unlicensed medical/legal/financial advice |
| I   | Copyright               | MEDIUM   | DRM bypass, piracy tools                  |
| J   | High-Risk Decisions     | MEDIUM   | Automated hiring/firing, credit scoring   |
| K   | Critical Infrastructure | MEDIUM   | SCADA attacks, power grid exploits        |
| L   | Adult Content           | FLAG     | NSFW generation (context-dependent)       |
| M   | Illegal Activities      | FLAG     | Drug/weapon trading, money laundering     |
| N   | Other Prohibited        | FLAG     | Gambling bots, spam generators            |

**High-Risk Domains** (require additional review):

- Healthcare (HIPAA concerns)
- Financial Services (regulatory)
- Legal (privileged information)
- Government/Defense (classified data)
- Education (FERPA, academic integrity)
- Children/Minors (COPPA, safety)
- Insurance (claims processing)

**Test Approach**:

- Pattern matching on tool names and descriptions
- README content analysis
- Source code scanning (enhanced mode)
- Tool capability inference (Issue #194)
- Pattern coverage tracking

**Pass Criteria**:

- No CRITICAL violations
- No unmitigated HIGH violations
- Appropriate disclaimers for flagged domains

**Stage B Enrichment (Issue #194)**:

The AUP module now generates enriched context for Claude validation:

- **Tool Inventory** - Server tools with inferred capabilities (file_system, network, exec, database, auth, crypto, system)
- **Pattern Coverage** - Metadata about 150+ AUP patterns checked across categories A-N
- **Review Flags** - Tools with sensitive capabilities flagged for human review (even without violations)
- **Token Efficiency** - Limits to 50 tools, 300-char descriptions, 10 high-risk domains

This enrichment is included in JSONL `module_complete` events for the `aup` module, enabling Claude to understand server capabilities for more accurate violation validation.

**Implementation**:

- `client/src/services/assessment/modules/AUPComplianceAssessor.ts` - Main assessor with enrichment data building
- `client/src/services/assessment/lib/moduleEnrichment.ts` - Tool capability inference and enrichment utilities
- `client/src/lib/aupPatterns.ts` - AUP pattern definitions (150+ patterns)

---

### 8. Tool Annotations

**Purpose**: Validate Policy #17 tool annotation compliance.

**Reference**: MCP Directory Policy #17 - Tool annotations must accurately reflect behavior.

**Required Annotations**:
| Annotation | Values | Purpose |
|------------|--------|---------|
| `readOnlyHint` | true/false | Tool only reads data, no side effects |
| `destructiveHint` | true/false | Tool can delete or modify data |
| `idempotentHint` | true/false | Repeated calls have same effect |
| `openWorldHint` | true/false | Tool interacts with external systems |

**Test Approach**:

- Infer expected annotations from tool name patterns
- Compare against declared annotations
- Flag misalignments (e.g., `delete_user` without `destructiveHint: true`)

**Inference Rules**:
| Pattern | Expected Annotation |
|---------|---------------------|
| get*, read*, list*, fetch* | `readOnlyHint: true` |
| delete*, remove*, drop* | `destructiveHint: true` |
| create*, update*, write* | `destructiveHint: false` (modifying) |
| external URL/API calls | `openWorldHint: true` |

**Pass Criteria**:

- All tools with side effects have `destructiveHint`
- Read-only tools marked as `readOnlyHint: true`
- No annotation/behavior mismatches

**Known Exemptions** (Issue #18):

Tools with "run" prefix and analysis-related suffixes are treated as read-only operations:

- **Example tools**: `runAccessibilityAudit`, `runSEOAudit`, `runSecurityScan`, `runHealthCheck`
- **Exempt suffixes**: audit, check, scan, test, mode, analyze, report, status, validate, verify, inspect, lint, benchmark, diagnostic
- **Rationale**: These tools fetch/analyze data without modifying state, so `readOnlyHint=true` is appropriate even though "run" is typically associated with state-modification

**Implementation**: `client/src/services/assessment/modules/ToolAnnotationAssessor.ts`

#### Enhanced Behavior Inference (Issue #57)

The Tool Annotations module now uses **multi-signal behavior inference** for more accurate annotation validation.

**Four Signal Sources**:

1. **Name patterns** - Tool name keywords (high confidence)
2. **Description analysis** - Description text keywords (medium-high confidence)
3. **Input schema** - Parameter structure patterns (medium confidence)
4. **Output schema** - Return value patterns (medium confidence)

**Signal Aggregation**:

- Multiple agreeing signals increase confidence
- Conflicting signals trigger ambiguity warnings
- Destructive signals take priority when confidence ≥ 70

**Persistence Classification**:

- CREATE operations (create*, add*, insert\_) are **never** destructive
- UPDATE operations check server persistence model (immediate vs. deferred)
- Description keywords override name-pattern inference

See [Behavior Inference Guide](BEHAVIOR_INFERENCE_GUIDE.md) for complete documentation.

#### Architecture Detection (Issue #57)

The assessor can optionally analyze server architecture to provide context for annotation validation.

**Detects**:

- Database backends (Neo4j, MongoDB, PostgreSQL, etc.)
- Transport modes (stdio, HTTP, SSE)
- Server classification (local, hybrid, remote)
- External service dependencies

See [Architecture Detection Guide](ARCHITECTURE_DETECTION_GUIDE.md) for complete documentation.

---

### 9. Prohibited Libraries

**Purpose**: Detect Policy #28-30 violations for financial/media libraries.

**Reference**: MCP Directory Policies #28-30

**Policy Summary**:

- **#28**: No financial transaction processing
- **#29**: No payment processing libraries
- **#30**: Media processing requires justification

**Financial Libraries (BLOCKING)**:
| Library | Category | Reason |
|---------|----------|--------|
| Stripe | payments | Payment processing |
| PayPal | payments | Payment processing |
| Square | payments | Payment processing |
| Braintree | payments | Payment processing |
| Plaid | banking | Bank account access |
| Coinbase | financial | Cryptocurrency transactions |
| Binance | financial | Crypto trading |
| ethers.js | financial | Blockchain transactions (HIGH, may allow read-only) |
| web3.js | financial | Blockchain transactions (HIGH, may allow read-only) |

**Media Libraries (HIGH - require justification)**:
| Library | Category | Reason |
|---------|----------|--------|
| Pillow/PIL | media | Image manipulation |
| OpenCV | media | Computer vision |
| Sharp | media | Image processing (Node.js) |
| FFmpeg | media | Video/audio processing |
| MoviePy | media | Video editing |
| PyDub | media | Audio manipulation |

**Test Approach**:

- Scan package.json dependencies
- Scan requirements.txt
- Source code import analysis

**Pass Criteria**:

- No BLOCKING libraries in dependencies
- HIGH libraries have documented justification
- No direct payment/banking API calls

**Implementation**: `client/src/services/assessment/modules/ProhibitedLibrariesAssessor.ts` + `client/src/lib/prohibitedLibraries.ts`

---

### 10. Manifest Validation

**Purpose**: Validate MCPB manifest.json compliance for bundled servers.

**Reference**: MCPB Manifest Specification v0.3

**Required Fields**:
| Field | Type | Description |
|-------|------|-------------|
| manifest_version | "0.3" | Must be version 0.3 |
| name | string | Server name (no spaces) |
| version | string | Semantic version |
| mcp_config | object | MCP configuration |

**Optional Fields**:
| Field | Description |
|-------|-------------|
| description | Server purpose |
| icon | Path to icon file |
| author | Creator information |
| homepage | Project URL |

**Anti-Patterns Detected**:
| Pattern | Issue |
|---------|-------|
| `${BUNDLE_ROOT}` | Hardcoded paths break portability |
| Missing icon | Reduces directory visibility |
| Invalid semver | Version must be X.Y.Z format |

**Pass Criteria**:

- All required fields present
- manifest_version = "0.3"
- No `${BUNDLE_ROOT}` anti-patterns
- Valid semantic versioning

**Implementation**: `client/src/services/assessment/modules/ManifestValidationAssessor.ts`

---

### 11. Portability Assessment

**Purpose**: Ensure cross-platform compatibility.

**Test Approach**:

- Detect hardcoded paths
- Identify platform-specific code patterns
- Check for environment assumptions

**Portability Checks**:
| Check | Pattern | Issue |
|-------|---------|-------|
| Unix Paths | `/Users/`, `/home/` | Hardcoded user directories |
| Windows Paths | `C:\`, `D:\` | Hardcoded drive letters |
| Temp Paths | `/tmp/`, `%TEMP%` | Platform-specific temp dirs |
| Path Separators | `/` vs `\` | Should use path.join() |
| Environment | `process.env.HOME` | May not exist on all platforms |

**Pass Criteria**:

- No hardcoded user paths
- Path construction uses cross-platform utilities
- Environment variables have fallbacks

**Implementation**: `client/src/services/assessment/modules/PortabilityAssessor.ts`

---

### 12. External API Scanner

**Purpose**: Detect external service dependencies and affiliations.

**Test Approach**:

- Scan tool descriptions and names for API indicators (always available)
- Extract actual external API domains from source code when available (Issue #168)
- Identify third-party service dependencies
- Check for affiliation disclosure requirements

**Detection Methods**:

1. **Name/Description Patterns** (always runs)
   - 18 name patterns: `api`, `weather`, `stock`, `fetch_from`, etc.
   - 7 description regex patterns: `external api`, `fetches from`, `real-time`, etc.

2. **Source Code Scanning** (when `--source` flag provided)
   - Scans for actual HTTP client calls: `fetch()`, `axios.get()`, `requests.post()`, etc.
   - Extracts real domain names from detected URLs
   - Skips localhost and local network URLs
   - ReDoS protected: max 500KB/file, max 100 matches/file

**External API Categories**:

| Category      | Examples                     | Concern          |
| ------------- | ---------------------------- | ---------------- |
| AI Services   | OpenAI, Anthropic, Google AI | API key exposure |
| Cloud Storage | S3, GCS, Azure Blob          | Data residency   |
| Payment       | Stripe, PayPal               | PCI compliance   |
| Social Media  | Twitter, LinkedIn            | Terms of service |
| Analytics     | GA, Mixpanel                 | Privacy policies |

**Pass Criteria**:

- External dependencies are documented
- API keys are not hardcoded
- Affiliate relationships disclosed if required

**Implementation**: `client/src/services/assessment/modules/ExternalAPIScannerAssessor.ts`

**Helper**: `client/src/services/assessment/helpers/ExternalAPIDependencyDetector.ts` (Issue #168)

- Shared helper used by TemporalAssessor, FunctionalityAssessor, and ProtocolComplianceAssessor
- Returns detection results with confidence levels and domain extraction

---

### 13. Authentication

**Purpose**: Evaluate OAuth/auth configuration appropriateness for deployment context.

**Detection Logic**:

1. Check if server uses OAuth (via serverInfo/manifest)
2. Analyze if tools access local resources (files, apps, OS features)
3. If OAuth + no local deps = recommend cloud deployment
4. If OAuth + local deps = warn about mixed model

**Authentication Patterns**:

| Pattern       | Detection              | Recommendation                 |
| ------------- | ---------------------- | ------------------------------ |
| OAuth only    | OAuth patterns found   | Cloud deployment optimal       |
| API Key only  | API key patterns found | Standard validation            |
| OAuth + Local | Mixed patterns         | Review deployment model        |
| None          | No auth detected       | Consider adding authentication |

**Local Resource Indicators**:

- File system access (`fs.read`, `fs.write`)
- Process execution (`child_process`, `execSync`)
- OS-specific paths (`__dirname`, `homedir`)
- Localhost references

**Transport Security Checks**:

- HTTPS vs HTTP usage
- TLS validation settings
- CORS configuration
- Security headers (httpOnly, sameSite)

**Pass Criteria**:

- Auth method matches deployment model
- No insecure transport patterns
- Secure defaults enabled

**Implementation**: `client/src/services/assessment/modules/AuthenticationAssessor.ts`

---

### 14. Temporal Assessment

**Purpose**: Detect rug pull / temporal behavior changes (behavior varying over invocations).

**Test Approach**:

- Invoke each tool multiple times (default: 3 invocations)
- Compare responses for consistency
- Detect behavior drift patterns

**Temporal Checks**:

| Check                | Method                             | Detection                    |
| -------------------- | ---------------------------------- | ---------------------------- |
| Schema Stability     | Compare schemas across invocations | Schema should not change     |
| Response Consistency | Hash/compare responses             | Significant drift flagged    |
| Error Pattern        | Track error frequency              | Increasing errors suspicious |
| Timing Analysis      | Response time variance             | Unusual timing patterns      |

**Pass Criteria**:

- Tool behavior consistent across invocations
- No schema changes detected
- No suspicious timing patterns

**Implementation**: `client/src/services/assessment/modules/TemporalAssessor.ts` (orchestrator, 561 lines)

**Helper Modules** (Issue #106 refactoring):

- `client/src/services/assessment/modules/temporal/MutationDetector.ts` (202 lines) - Definition & content mutation detection
- `client/src/services/assessment/modules/temporal/VarianceClassifier.ts` (517 lines) - Tool classification & variance analysis

---

### 15. Resources Assessment

**Purpose**: Validate MCP resource capability implementation and detect security issues.

**Test Approach**:

- Enumerate available resources
- Test resource read operations
- Validate resource URIs and metadata
- Probe for hidden/undeclared resources (with rate limiting)
- Test path traversal and injection vulnerabilities
- Detect binary resource vulnerabilities (Issue #127, Challenge #24)

**Resource Checks**:

| Check            | Description                                         |
| ---------------- | --------------------------------------------------- |
| Discovery        | List resources via resources/list                   |
| Read Success     | Attempt to read each resource                       |
| URI Format       | Validate URI structure                              |
| Metadata         | Check resource descriptions                         |
| Error Handling   | Test invalid resource requests                      |
| Path Traversal   | Attempt directory traversal attacks                 |
| Hidden Resources | Probe undeclared resources (50ms delay)             |
| URI Injection    | Test SQL, template, and code injection              |
| Sensitive Data   | Detect exposed secrets in resource URIs             |
| Blob DoS         | Detect excessive binary payloads (CWE-400, CWE-409) |
| Polyglot Files   | Detect dual-format files (CWE-434, CWE-436)         |
| MIME Validation  | Verify content matches declared type (CWE-436)      |

**Binary Resource Security** (Issue #127):

- **Blob DoS Detection**: Flags binary payloads exceeding 100KB (configurable threshold)
- **Polyglot Detection**: Tests for dual-format files (PNG/JAR, GIF/JS) using magic byte analysis
- **MIME Validation**: Compares declared Content-Type with actual content magic bytes
- **Detection Method**: Magic bytes checked first (primary), JSON self-reporting as supplementary

**Rate Limiting**:

- Hidden resource probes: 50ms delay between attempts (prevents overwhelming servers)
- Reduces false positives from rate-limited endpoints
- Applies to all parameterized resource testing

**Pass Criteria**:

- Resources are discoverable
- Read operations succeed for valid resources
- Error handling for invalid resources
- No path traversal vulnerabilities
- Sensitive data not exposed
- No blob DoS vulnerabilities
- No polyglot file vulnerabilities
- MIME types match actual content

**Implementation**: `client/src/services/assessment/modules/ResourceAssessor.ts` (Issue #119, Issue #127)

---

### 16. Prompts Assessment

**Purpose**: Validate MCP prompt capability implementation.

**Test Approach**:

- Enumerate available prompts
- Test prompt execution
- Validate argument handling

**Prompt Checks**:

| Check      | Description                     |
| ---------- | ------------------------------- |
| Discovery  | List prompts via prompts/list   |
| Execution  | Test prompt invocation          |
| Arguments  | Validate required/optional args |
| Multimodal | Check content type support      |
| Templates  | Validate template rendering     |

**Pass Criteria**:

- Prompts are discoverable
- Execution produces valid output
- Argument validation works correctly

**Implementation**: `client/src/services/assessment/modules/PromptsAssessor.ts`

---

### 17. Cross-Capability Assessment

**Purpose**: Detect chained vulnerabilities across tools, resources, and prompts.

**Test Approach**:

- Analyze tool combinations for attack chains
- Test multi-step attack scenarios
- Identify capability escalation paths

**Cross-Capability Patterns**:

| Pattern                | Risk                 | Example                       |
| ---------------------- | -------------------- | ----------------------------- |
| Tool Chaining          | Privilege escalation | Read file → Execute command   |
| Resource + Tool        | Data exfiltration    | Get resource → Send external  |
| Prompt Injection Chain | Control flow         | Prompt → Tool with user input |

**Pass Criteria**:

- No obvious attack chains detected
- Privilege boundaries maintained
- Input validation at each step

**Implementation**: `client/src/services/assessment/modules/CrossCapabilitySecurityAssessor.ts`

---

### 18. File Modularization Assessment

**Purpose**: Detect large monolithic tool files and recommend modularization patterns (Issue #104).

**Test Approach**:

- Scan source code files for line count and tool density
- Detect language-specific tool definition patterns
- Evaluate modularization structure (tools/ directory, distributed files)
- Calculate modularization score (0-100)

**Language Support**:

- Python: `@mcp.tool`, `@server.tool`, `@app.tool`, `*_tool` function patterns
- TypeScript/JavaScript: `server.tool()`, `.setRequestHandler()`, `registerTool()`, `.addTool()`
- Go: `*Tool` function names, `mcp.NewTool()`, `tools.Register()`
- Rust: `*_tool` functions, `#[tool]` macros, `.register_tool()`

**Modularization Checks**:

| Check             | Threshold                | Severity |
| ----------------- | ------------------------ | -------- |
| File size         | >2000 lines              | HIGH     |
| File size         | 1000-2000 lines          | MEDIUM   |
| Tools per file    | >20 tools                | HIGH     |
| Tools per file    | 10-20 tools              | MEDIUM   |
| Modular structure | No tools/ dir + <3 files | LOW      |

**Scoring System**:

- Starts at 100 points
- -15 per file >2000 lines, -8 per file 1000-2000 lines
- -12 per file with >20 tools, -6 per file 10-20 tools
- -10 for no modular structure
- +5 for tools/ subdirectory, +3 for multiple tool files, +2 for shared utilities

**Pass Criteria**:

- No files exceed 2000 lines (HIGH threshold)
- No files contain >20 tools (HIGH threshold)
- Modularization score ≥70

**Configuration**:

```typescript
{
  fileModularization?: boolean;      // Enable this assessment (default: true in full profile)
  enableSourceCodeAnalysis?: boolean; // Required: scan source files (default: true)
}
```

**Implementation**: `client/src/services/assessment/modules/FileModularizationAssessor.ts` (675 lines)

---

### 19. Protocol Conformance Assessment (Deprecated)

> **⚠️ DEPRECATED v1.25.2**: This module has been merged into **Protocol Compliance (#6)**. The standalone `ProtocolConformanceAssessor` remains exported for backwards compatibility but will be removed in v2.0.0. Use `ProtocolComplianceAssessor` for new code.

**Purpose**: Validate MCP protocol-level compliance with conformance-inspired tests.

**Relationship to Other Modules**:

- **ErrorHandlingAssessor** (#3): Merged into ProtocolComplianceAssessor (Issue #188)
- **ProtocolComplianceAssessor** (#6): Unified protocol compliance (replaces this module)

**Test Approach**:

- Error response format validation (isError flag, content array structure)
- Content type support validation (text, image, audio, resource, resource_link)
- Initialization handshake validation (serverInfo completeness)

**Protocol Checks**:

| Check                    | Description                                                  | Confidence  |
| ------------------------ | ------------------------------------------------------------ | ----------- |
| Error Response Format    | Validates `isError: true` flag, content array with text type | high/medium |
| Content Type Support     | Validates all content items use valid MCP types              | high/medium |
| Initialization Handshake | Validates serverInfo.name, version, capabilities             | high/medium |

**MCP Specification References**:

Spec URLs are configurable via `config.mcpProtocolVersion` (defaults to "2025-06"):

- Lifecycle: `https://modelcontextprotocol.io/specification/{version}/basic/lifecycle`
- Tools: `https://modelcontextprotocol.io/specification/{version}/server/tools`

**Test Details**:

| Test           | Method                                                | What It Validates                                              |
| -------------- | ----------------------------------------------------- | -------------------------------------------------------------- |
| Error Format   | Call up to 3 representative tools with invalid params | `isError: true`, content array with `type: "text"` (all tools) |
| Content Types  | Call tool with empty/valid params                     | Content array uses only valid types                            |
| Initialization | Inspect serverInfo                                    | Server name (required), version (recommended), capabilities    |

**Multi-Tool Testing** (v1.24.2+):

The error format check tests up to 3 representative tools for better coverage:

- If 1-3 tools: Tests all tools
- If 4+ tools: Tests first, middle, and last tools (indices 0, floor(n/2), n-1)
- All tested tools must pass for the check to pass
- Results are aggregated with per-tool details in the output

**Pass Criteria**:

- Error responses include `isError: true` flag when errors occur (across all tested tools)
- All content items use valid MCP content types
- Server provides name during initialization
- No tools throw exceptions instead of returning error responses

**Status Determination**:

| Score  | Critical Checks               | Status         |
| ------ | ----------------------------- | -------------- |
| ≥90%   | All pass                      | PASS           |
| 70-89% | OR low confidence on critical | NEED_MORE_INFO |
| <70%   | OR critical failure           | FAIL           |

**Critical Checks** (must pass for overall PASS):

- `errorResponseFormat`
- `initializationHandshake`

**Configuration**:

Enabled in these config presets:

- `DEVELOPER_MODE_CONFIG`: ✓
- `AUDIT_MODE_CONFIG`: ✓
- `CLAUDE_ENHANCED_AUDIT_CONFIG`: ✓

**Implementation**: `client/src/services/assessment/modules/ProtocolConformanceAssessor.ts` (~300 lines)

> **Note**: This file is deprecated. Use `ProtocolComplianceAssessor.ts` for unified protocol compliance.

---

## Opt-In Modules (Experimental)

### Official MCP Conformance Testing

**Purpose**: Run official MCP protocol conformance tests from Anthropic's `@modelcontextprotocol/conformance` package.

**Requirements**:

- HTTP or SSE transport (STDIO transport not supported)
- Server must expose an HTTP endpoint accessible by the conformance CLI

**Test Approach**:

- Runs official MCP server scenarios via subprocess
- Validates server initialization, tools, resources, and prompts
- Parses conformance check results from JSON output

**Scenarios Tested**:

| Scenario            | Description                      |
| ------------------- | -------------------------------- |
| `server-initialize` | MCP initialization handshake     |
| `tools-list`        | Tool listing endpoint validation |
| `tools-call`        | Tool invocation scenarios        |
| `resources-list`    | Resource listing compliance      |
| `resources-read`    | Resource read operations         |
| `prompts-list`      | Prompt listing compliance        |
| `prompts-get`       | Prompt retrieval operations      |

**Result Structure**:

```typescript
interface ConformanceAssessment {
  status: AssessmentStatus;
  conformanceVersion: string; // e.g., "0.1.9"
  protocolVersion: string; // e.g., "2025-06"
  scenarios: ConformanceScenario[];
  officialChecks: ConformanceCheck[];
  passedChecks: number;
  totalChecks: number;
  complianceScore: number; // 0-100%
  explanation: string;
  recommendations: string[];
  skipped?: boolean;
  skipReason?: string;
}
```

**CLI Usage**:

```bash
# Enable conformance testing (requires HTTP/SSE transport)
mcp-assess-full my-server --config http-config.json --conformance

# HTTP config example
# { "transport": "http", "url": "http://localhost:10900/mcp" }
```

**When Skipped**:

- Returns `NEED_MORE_INFO` status with skip reason
- Skipped if serverUrl not available (STDIO transport)
- Skipped if MCP conformance package not installed
- Provides recommendations for enabling HTTP/SSE transport and installing dependencies
- Does not fail the overall assessment

**Dependencies**:

The ConformanceAssessor requires the official MCP conformance package:

```bash
npm install -g @modelcontextprotocol/conformance
```

If not available, the module logs a warning and skips gracefully.

**Implementation**: `client/src/services/assessment/modules/ConformanceAssessor.ts` (~420 lines)

---

## Quick Reference Table

| #   | Module               | Tests               | Policy Ref     | Severity | Tier          |
| --- | -------------------- | ------------------- | -------------- | -------- | ------------- |
| 1   | Functionality        | ~10 per tool        | Core           | Medium   | Tier 1: Core  |
| 2   | Security             | 31 patterns × tools | Core           | High     | Tier 1: Core  |
| 3   | Error Handling       | ~20 per tool        | MCP Spec       | Medium   | Merged (#188) |
| 4   | Documentation        | ~10 checks          | Core           | Low      | Tier 1: Core  |
| 5   | Usability            | ~8 checks           | Core           | Low      | Tier 1: Core  |
| 6   | Protocol Compliance  | ~20 checks          | MCP Spec       | High     | Tier 1: Core  |
| 7   | AUP Compliance       | 14 categories       | AUP A-N        | Critical | Tier 2: Comp  |
| 8   | Tool Annotations     | Per tool            | Policy #17     | Medium   | Tier 2: Comp  |
| 9   | Prohibited Libraries | ~25 libraries       | Policy #28-30  | Blocking | Tier 2: Comp  |
| 10  | Manifest Validation  | ~10 checks          | MCPB v0.3      | Medium   | Tier 2: Comp  |
| 11  | Portability          | ~8 patterns         | Cross-platform | Low      | Tier 4: Ext   |
| 12  | External API Scanner | API detection       | Disclosure     | Medium   | Tier 2: Comp  |
| 13  | Authentication       | Auth patterns       | Security       | High     | Tier 2: Comp  |
| 14  | Temporal             | 3 invocations/tool  | Rug pull       | High     | Tier 1: Core  |
| 15  | Resources            | Per resource        | MCP Spec       | Medium   | Tier 3: Cap   |
| 16  | Prompts              | Per prompt          | MCP Spec       | Medium   | Tier 3: Cap   |
| 17  | Cross-Capability     | Multi-tool chains   | Security       | High     | Tier 3: Cap   |
| 18  | File Modularization  | Per file            | Code quality   | Medium   | Tier 4: Ext   |
| 19  | Protocol Conformance | 3 protocol checks   | MCP Spec       | High     | Deprecated    |
| 20  | MCP Conformance      | 7 scenarios         | Official MCP   | High     | Opt-In        |

---

## Running Assessments

### CLI Usage

```bash
# Full 17-point assessment
npx @bryan-thompson/inspector-assessment assess:full --config config.json

# Security-focused assessment
npx @bryan-thompson/inspector-assessment assess:security --config config.json

# Specific server
npm run assess -- --server my-mcp --config /path/to/config.json

# Selective module testing - skip specific modules
mcp-assess-full --server my-mcp --skip-modules security,aupCompliance

# Selective module testing - run only specific modules
mcp-assess-full --server my-mcp --only-modules functionality,toolAnnotations
```

### Selective Module Testing

You can run specific modules or skip modules for faster, targeted assessments:

| Flag                    | Mode      | Example                                        |
| ----------------------- | --------- | ---------------------------------------------- |
| `--skip-modules <list>` | Blacklist | `--skip-modules security,temporal`             |
| `--only-modules <list>` | Whitelist | `--only-modules functionality,toolAnnotations` |

**Note:** These flags are mutually exclusive. See [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md#selective-module-testing) for the full list of valid module names.

### Config File Format

**HTTP Transport**:

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

**STDIO Transport**:

```json
{
  "command": "python3",
  "args": ["server.py"],
  "env": {}
}
```

### Output

Results saved to `/tmp/inspector-assessment-{serverName}.json`

```bash
# Quick vulnerability check
cat /tmp/inspector-assessment-*.json | jq '.security.vulnerabilities'

# Check AUP violations
cat /tmp/inspector-assessment-*.json | jq '.aupCompliance.violations'

# Get overall status
cat /tmp/inspector-assessment-*.json | jq '.overallStatus'
```

---

## Related Documentation

- [Testbed Setup Guide](TESTBED_SETUP_GUIDE.md) - A/B validation with vulnerable-mcp/hardened-mcp
- [Security Patterns Catalog](SECURITY_PATTERNS_CATALOG.md) - 31 attack patterns
- [Real-Time Progress Output](REAL_TIME_PROGRESS_OUTPUT.md) - CLI integration guide

---

**Version**: 1.9.3
**Last Updated**: 2026-01-06
