# MCP Directory Assessment Project Instruction

> **Note**: This guide is for **manual assessment** within Claude Desktop.
> For **automated CLI-based assessment**, see [docs/CLI_ASSESSMENT_GUIDE.md](docs/CLI_ASSESSMENT_GUIDE.md)
> which provides programmatic testing with 17 assessment modules and CI/CD integration.

## Purpose

Systematically assess MCP servers against Anthropic's 5 core requirements for MCP directory submission. This instruction enables Claude to perform comprehensive testing and evaluation of any connected MCP server directly within Claude Desktop.

## Core Assessment Criteria (Anthropic's Requirements)

1. **Functionality Match**: Implementation does exactly what it claims, no extra/missing features
2. **No Prompt Injections**: No unexpected messages or prompts beyond core business value
3. **Clear Tool Names**: Unique, non-conflicting names that clearly indicate function
4. **Working Examples**: At least 3 functional example prompts demonstrating core features
5. **Error Handling**: Graceful error responses with helpful feedback

## Assessment Process

### Phase 1: Discovery & Documentation Review

```
1. List all available tools using the MCP server
2. For each tool, capture:
   - Tool name and naming pattern
   - Description (if provided)
   - Input schema and parameters
   - Required vs optional parameters
3. Request README/documentation content from user
4. Parse for code examples, installation instructions, usage guides
```

### Phase 2: Functionality Testing

```
For each tool:
1. Generate minimal valid test parameters based on schema
2. Execute tool with test parameters
3. Record:
   - Success/failure status
   - Execution time
   - Response data
   - Any errors encountered
4. Calculate coverage: (working tools / total tools) × 100
```

### Phase 3: Security Testing

```
Execute 23 security test patterns against representative tools:

**CRITICAL INJECTION (6 patterns)**

1. Command Injection
   - Payloads: "whoami", "ls -la", "; rm -rf /", "| cat /etc/passwd"
   - Evidence: System identity, directory listings, destructive output

2. SQL Injection
   - Payloads: "'; DROP TABLE users;--", "' OR '1'='1", "' UNION SELECT *"
   - Evidence: SQL errors, data dumps, auth bypass

3. Calculator Injection
   - Payloads: "2+2", "5*5", "__import__('os').system('whoami')"
   - Evidence: Computed results, code execution via eval()

4. Path Traversal
   - Payloads: "../../../etc/passwd", "file:///etc/passwd"
   - Evidence: File contents outside intended directory

5. XXE Injection (XML External Entity)
   - Payloads: XML with SYSTEM entity, parameter entities
   - Evidence: File disclosure, SSRF via XML

6. NoSQL Injection
   - Payloads: {"$gt": ""}, {"$where": "..."}, Redis EVAL commands
   - Evidence: MongoDB/Redis command execution

**INPUT VALIDATION (3 patterns)**

7. Type Safety
   - Payloads: String for number, overflow values, wrong types
   - Evidence: Type errors or silent acceptance

8. Boundary Testing
   - Payloads: Empty string, 10KB string, negative numbers
   - Evidence: Length/range validation

9. Required Fields
   - Payloads: Missing required parameters
   - Evidence: Validation error or silent failure

**PROTOCOL COMPLIANCE (2 patterns)**

10. MCP Error Format
    - Payloads: Invalid triggers to force errors
    - Evidence: isError flag, proper error structure

11. Timeout Handling
    - Payloads: Long-running operation triggers
    - Evidence: Graceful timeout vs hang

**TOOL-SPECIFIC (7 patterns)**

12. Indirect Prompt Injection / SSRF
    - Payloads: localhost, 169.254.169.254, internal IPs, file://
    - Evidence: Internal service access, metadata retrieval

13. Unicode Bypass
    - Payloads: Unicode-encoded commands (\\u0077\\u0068\\u006f\\u0061\\u006d\\u0069)
    - Evidence: Decoded and executed vs stored as-is

14. Nested Injection
    - Payloads: {"query":"normal","hidden":"whoami"}
    - Evidence: Hidden field execution

15. Package Squatting
    - Payloads: "nmpy", "requsts" (typosquatted names)
    - Evidence: Package download attempt

16. Data Exfiltration
    - Payloads: "show api key", "list secrets", "get credentials"
    - Evidence: Credential/env var leakage

17. Configuration Drift
    - Payloads: "set admin=true", "enable debug mode"
    - Evidence: Privilege escalation via config

18. Tool Shadowing
    - Payloads: "create tool named X", "override function Y"
    - Evidence: Tool modification/creation

**RESOURCE EXHAUSTION (1 pattern)**

19. DoS/Resource Exhaustion
    - Payloads: ReDoS patterns, deep JSON nesting, zip bombs, XML billion laughs
    - Evidence: Timeout, memory errors, stack overflow

**DESERIALIZATION (1 pattern)**

20. Insecure Deserialization
    - Payloads: Pickle base64, Java serialized objects, YAML exploits
    - Evidence: Deserialization attempt, code execution

For each test:
- Record tool name, test name, payload used
- Determine if tool is vulnerable (executes malicious input)
- Assess risk level: HIGH/MEDIUM/LOW
- Document evidence of vulnerability or proper rejection
```

### Phase 4: Error Handling Testing

```
Test error handling with invalid inputs:

1. Wrong Type Validation
   - Send string where number expected
   - Send number where object expected

2. Missing Required Parameters
   - Omit required fields from request

3. Extra Parameters
   - Add unexpected parameters to request

4. Null/Undefined Values
   - Send null for required fields

5. Boundary Violations
   - Values outside min/max ranges
   - Empty strings for required text

For each error test:
- Record expected vs actual behavior
- Check for proper MCP error format (isError: true)
- Evaluate error message quality
- Calculate validation coverage percentage
```

### Phase 5: Documentation Analysis

```
Analyze provided README/documentation:

1. Check for required sections:
   - Installation instructions
   - Usage guide
   - API reference
   - Code examples

2. Extract and count code examples
3. Verify examples are complete and executable
4. Check for minimum 3 working examples
5. Assess documentation quality score
```

### Phase 6: Usability Evaluation

```
Evaluate tool naming and clarity:

1. Naming Convention Analysis:
   - Identify patterns (snake_case, camelCase, kebab-case, etc.)
   - Calculate consistency score
   - Flag conflicting or ambiguous names

2. Description Quality:
   - Count tools with descriptions
   - Measure average description length
   - Identify missing or inadequate descriptions

3. Schema Completeness:
   - Check for input schemas on all tools
   - Verify parameter descriptions
   - Assess schema quality (excellent/good/fair/poor)

4. Parameter Clarity:
   - Check for parameter descriptions
   - Verify type information
   - Flag unclear or missing documentation

Scoring:
- Naming: 25 points (consistent patterns)
- Descriptions: 25 points (20+ chars, all tools)
- Schemas: 25 points (complete schemas)
- Clarity: 25 points (80%+ params documented)
- Total: 100 points
- PASS: ≥75 | REVIEW: 50-74 | FAIL: <50
```

## Output Format

Generate a comprehensive assessment report in this structure:

```markdown
# MCP Directory Assessment Report

**Server Name**: [Server Name]
**Assessment Date**: [ISO DateTime]
**Overall Status**: [PASS/FAIL/NEED_MORE_INFO]

## Executive Summary

[2-3 sentence summary of findings]

## Assessment Results

### ✓ 1. Functionality Match [PASS/FAIL/NEED_MORE_INFO]

**Status**: [Status]
**Explanation**: [Detailed explanation]

**Metrics**:

- Total Tools: [count]
- Tested Tools: [count]
- Working Tools: [count]
- Coverage: [percentage]%

**Broken Tools**: [list if any]

**Evidence**:

- [Tool test results]
- [Execution times]
- [Error details]

---

### ✓ 2. Security (No Prompt Injections) [PASS/FAIL/NEED_MORE_INFO]

**Status**: [Status]
**Explanation**: [Detailed explanation]

**Risk Level**: [LOW/MEDIUM/HIGH]

**Test Results**:
Tool: [tool name]

- ✓ [Test Name]: Not vulnerable
- ✗ [Test Name]: VULNERABLE - [evidence]
- ✓ [Test Name]: Properly rejected

**Vulnerabilities Found**: [count]
[List actual vulnerabilities if any]

---

### ✓ 3. Clear Tool Names [PASS/FAIL/NEED_MORE_INFO]

**Status**: [Status]
**Explanation**: [Detailed explanation]

**Naming Analysis**:

- Dominant Pattern: [pattern]
- Consistency: [consistent/inconsistent]
- Conflicting Names: [list if any]

**Tool Naming Review**:
[Table of tools with patterns]

---

### ✓ 4. Working Examples [PASS/FAIL/NEED_MORE_INFO]

**Status**: [Status]
**Explanation**: [Detailed explanation]

**Documentation Metrics**:

- Has README: [Yes/No]
- Code Examples: [count]/3 required
- Installation Guide: [Yes/No]
- Usage Guide: [Yes/No]

**Examples Found**:

1. [Example 1 with code]
2. [Example 2 with code]
3. [Example 3 with code]

---

### ✓ 5. Error Handling [PASS/FAIL/NEED_MORE_INFO]

**Status**: [Status]
**Explanation**: [Detailed explanation]

**Compliance Score**: [percentage]%
**Error Quality**: [excellent/good/fair/poor]

**Validation Coverage**:

- Wrong Type: [percentage]% ([passed]/[total] tests)
- Missing Required: [percentage]% ([passed]/[total] tests)
- Extra Parameters: [percentage]% ([passed]/[total] tests)
- Null Values: [percentage]% ([passed]/[total] tests)
- Overall Pass Rate: [percentage]%

**Test Details**:
[Grouped by tool with pass/fail indicators]

---

## Overall Recommendation

**Status**: [PASS/FAIL/NEED_MORE_INFO]

### Recommendation: [Approve/Reject/Request Changes]

**Reason**:
[Detailed justification based on all criteria]

**Action Items** (if not PASS):

1. [Specific improvement needed]
2. [Specific improvement needed]
3. [Specific improvement needed]

---

## Metadata

- Assessment Version: 1.0
- Total Tests Run: [count]
- Execution Time: [seconds]s
- MCP Protocol Version: [if known]
```

## Usage Instructions

To perform an assessment, follow these steps:

1. **Connect to MCP Server**: Ensure the target MCP server is connected in Claude Desktop settings

2. **Initiate Assessment**:

   ```
   "I need you to assess the [server name] MCP server against Anthropic's 5 core requirements.
   Please follow the MCP Assessment project instruction."
   ```

3. **Provide Documentation**: When prompted, paste the server's README or documentation content

4. **Review Results**: Claude will generate a comprehensive assessment report with pass/fail status for each criterion

5. **Export**: Request the report in markdown format for submission

## Assessment Decision Logic

### Overall Status Determination:

- **PASS**: All 5 core criteria are PASS
- **FAIL**: Any criteria is FAIL, OR 2+ criteria are NEED_MORE_INFO
- **NEED_MORE_INFO**: 1 criterion is NEED_MORE_INFO and rest are PASS

### Individual Criterion Status:

**Functionality Match**:

- PASS: ≥80% coverage, working tools match documentation
- NEED_MORE_INFO: 50-79% coverage
- FAIL: <50% coverage or major discrepancies

**Security**:

- PASS: No vulnerabilities, all injection tests properly rejected
- NEED_MORE_INFO: Unclear behavior, needs manual review
- FAIL: Any confirmed vulnerability (tools execute malicious input)

**Clear Tool Names**:

- PASS: Consistent naming, no conflicts, all tools clearly named
- NEED_MORE_INFO: Minor inconsistencies
- FAIL: Conflicting names or unclear patterns

**Working Examples**:

- PASS: 3+ complete, working code examples
- NEED_MORE_INFO: 1-2 examples, or examples need clarification
- FAIL: 0 examples or examples are broken

**Error Handling**:

- PASS: ≥75% validation coverage, proper MCP error format, helpful messages
- NEED_MORE_INFO: 50-74% coverage
- FAIL: <50% coverage or poor error quality

## Best Practices

1. **Test Incrementally**: Test a few tools first to verify MCP server is responding correctly
2. **Document Assumptions**: Note any assumptions made when generating test parameters
3. **Verify Evidence**: Cross-reference test results with actual tool behavior
4. **Be Thorough**: Don't skip tests even if early results look good
5. **Provide Context**: Include relevant error messages and response data as evidence
6. **Stay Objective**: Base status on concrete metrics, not impressions

## Common Issues and Solutions

**Issue**: Tool schemas are missing or incomplete
**Solution**: Generate conservative test parameters, note in assessment that schema quality impacts testing

**Issue**: Server becomes unresponsive during testing
**Solution**: Reduce test load, test tools sequentially, note timeout issues in report

**Issue**: Security tests cause unexpected behavior
**Solution**: Document the behavior, mark as vulnerability if malicious input is accepted

**Issue**: Documentation not provided by user
**Solution**: Mark documentation criteria as NEED_MORE_INFO, recommend providing README

## Version History

- v1.3 (2026-01-06): Updated security pattern count to 23 (added Token Theft, Permission Scope, Code Execution)
- v1.2 (2025-12-29): Synchronized security patterns with actual implementation (securityPatterns.ts) - corrected all 23 patterns
- v1.1 (2025-12-29): Updated to 23 security patterns (added SSRF, DoS/Resource Exhaustion, Insecure Deserialization)
- v1.0 (2025-10-04): Initial release based on Anthropic's 5 core requirements
