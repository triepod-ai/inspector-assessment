# MCP Inspector 11-Point Assessment Catalog

A comprehensive reference for all assessment modules in the MCP Inspector Assessment tool.

## Overview

The MCP Inspector Assessment runs **11 specialized modules** to validate MCP servers for functionality, security, protocol compliance, and Anthropic MCP Directory policy adherence.

### Module Organization

| Category         | Modules | Purpose                               |
| ---------------- | ------- | ------------------------------------- |
| **Core (5)**     | #1-5    | Essential server quality validation   |
| **Extended (6)** | #6-11   | MCP Directory compliance requirements |

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

- 20 distinct attack patterns with context-aware reflection detection
- Pure behavior-based detection (no metadata reliance)
- Domain-specific payloads based on parameter semantics
- Confidence levels (high/medium/low) for findings

**20 Attack Patterns** (organized by category):

| #                           | Attack Type                      | Risk   | Description                                                          |
| --------------------------- | -------------------------------- | ------ | -------------------------------------------------------------------- |
| **Critical Injection (6)**  |                                  |        |
| 1                           | Command Injection                | HIGH   | Tests for shell command execution (`whoami`, `ls -la`, `; rm -rf /`) |
| 2                           | SQL Injection                    | HIGH   | Tests for SQL command execution (`'; DROP TABLE`, `' OR '1'='1`)     |
| 3                           | Calculator Injection             | HIGH   | Tests for eval() execution (`2+2`, `__import__('os').system()`)      |
| 4                           | Path Traversal                   | HIGH   | Tests for file system access (`../../../etc/passwd`, `file://`)      |
| 5                           | XXE Injection                    | HIGH   | Tests for XML External Entity attacks (file disclosure, SSRF)        |
| 6                           | NoSQL Injection                  | HIGH   | Tests for MongoDB/Redis command execution (`$gt`, `$where`, EVAL)    |
| **Input Validation (3)**    |                                  |        |
| 7                           | Type Safety                      | MEDIUM | Tests parameter type validation (string vs number)                   |
| 8                           | Boundary Testing                 | MEDIUM | Tests edge cases (empty strings, 10K characters, negatives)          |
| 9                           | Required Fields                  | MEDIUM | Tests missing parameter handling                                     |
| **Protocol Compliance (2)** |                                  |        |
| 10                          | MCP Error Format                 | LOW    | Verifies error responses follow MCP spec                             |
| 11                          | Timeout Handling                 | LOW    | Tests long operation graceful handling                               |
| **Tool-Specific (7)**       |                                  |        |
| 12                          | Indirect Prompt Injection / SSRF | HIGH   | Tests URL fetching, localhost, cloud metadata, internal IPs          |
| 13                          | Unicode Bypass                   | MEDIUM | Tests unicode-encoded command execution                              |
| 14                          | Nested Injection                 | MEDIUM | Tests hidden instructions in nested JSON                             |
| 15                          | Package Squatting                | MEDIUM | Tests typosquatted package download attempts                         |
| 16                          | Data Exfiltration                | HIGH   | Tests credential/secret/env var leakage attempts                     |
| 17                          | Configuration Drift              | HIGH   | Tests privilege escalation via config (`set admin=true`)             |
| 18                          | Tool Shadowing                   | HIGH   | Tests tool creation/override attempts                                |
| **Resource Exhaustion (1)** |                                  |        |
| 19                          | DoS/Resource Exhaustion          | HIGH   | Tests ReDoS, deep JSON nesting, zip bombs, XML billion laughs        |
| **Deserialization (1)**     |                                  |        |
| 20                          | Insecure Deserialization         | HIGH   | Tests pickle, Java serialized objects, YAML exploits                 |

**Pass Criteria**:

- Zero HIGH risk vulnerabilities
- No command/SQL/path traversal execution
- Proper input validation demonstrated

**Implementation**: `client/src/services/assessment/modules/SecurityAssessor.ts` (443 lines)

---

### 3. Error Handling Assessment

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

**Implementation**: `client/src/services/assessment/modules/ErrorHandlingAssessor.ts` (692 lines)

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

## Extended Modules (MCP Directory Compliance)

These modules validate compliance with Anthropic's MCP Directory Policy requirements.

### 6. MCP Spec Compliance

**Purpose**: Verify adherence to MCP protocol specification.

**Test Approach**:

- Hybrid validation combining static and dynamic checks
- JSON-RPC 2.0 compliance verification
- Protocol message format validation
- Response structure conformance testing

**Protocol Checks**:
| Check | Description |
|-------|-------------|
| JSON-RPC 2.0 | Proper id, jsonrpc, method, params fields |
| Tool Schema | Valid inputSchema for all tools |
| Response Format | Proper content array with type/text |
| Error Format | Standard error codes and messages |
| Capabilities | Valid capability declarations |

**Pass Criteria**:

- All tool calls return valid JSON-RPC responses
- Error codes match MCP specification
- No protocol violations detected

**Implementation**: `client/src/services/assessment/modules/MCPSpecComplianceAssessor.ts` (560 lines)

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

**Pass Criteria**:

- No CRITICAL violations
- No unmitigated HIGH violations
- Appropriate disclaimers for flagged domains

**Implementation**: `client/src/services/assessment/modules/AUPComplianceAssessor.ts` + `client/src/lib/aupPatterns.ts`

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

**Implementation**: `client/src/services/assessment/modules/ToolAnnotationAssessor.ts`

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

## Quick Reference Table

| #   | Module               | Tests               | Policy Ref     | Severity |
| --- | -------------------- | ------------------- | -------------- | -------- |
| 1   | Functionality        | ~10 per tool        | Core           | Medium   |
| 2   | Security             | 20 patterns × tools | Core           | High     |
| 3   | Error Handling       | ~20 per tool        | MCP Spec       | Medium   |
| 4   | Documentation        | ~10 checks          | Core           | Low      |
| 5   | Usability            | ~8 checks           | Core           | Low      |
| 6   | MCP Spec Compliance  | ~15 checks          | MCP Spec       | High     |
| 7   | AUP Compliance       | 14 categories       | AUP A-N        | Critical |
| 8   | Tool Annotations     | Per tool            | Policy #17     | Medium   |
| 9   | Prohibited Libraries | ~25 libraries       | Policy #28-30  | Blocking |
| 10  | Manifest Validation  | ~10 checks          | MCPB v0.3      | Medium   |
| 11  | Portability          | ~8 patterns         | Cross-platform | Low      |

---

## Running Assessments

### CLI Usage

```bash
# Full 11-point assessment
npx @bryan-thompson/inspector-assessment assess:full --config config.json

# Security-focused assessment
npx @bryan-thompson/inspector-assessment assess:security --config config.json

# Specific server
npm run assess -- --server my-mcp --config /path/to/config.json
```

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

- [Assessment Methodology](ASSESSMENT_METHODOLOGY.md) - Detailed methodology for core modules
- [Reviewer Quick Start](REVIEWER_QUICK_START.md) - 60-second screening guide
- [MCP Vulnerability Testbed](mcp_vulnerability_testbed.md) - Validation testing
- [Real-Time Progress Output](REAL_TIME_PROGRESS_OUTPUT.md) - CLI integration guide

---

**Version**: 1.8.3
**Last Updated**: 2025-12-29 (Synchronized security patterns: 13 → 20 patterns matching securityPatterns.ts)
