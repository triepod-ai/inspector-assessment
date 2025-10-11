# MCP Inspector: Reviewer Quick Start Guide

## 60-Second Fast Screening

**Goal**: Make initial approve/reject decision in under 1 minute

### Quick Steps

1. **Select Mode**: Choose "Reviewer Mode" from the mode selector (fast, focused testing)
2. **Run Assessment**: Click the "Run Assessment" button
3. **Review Results**: Check the 5 core criteria scores
4. **Make Decision**:
   - ✅ **All green** → **APPROVE**
   - ❌ **Any red** → **REQUEST CHANGES** or **REJECT**
   - ⚠️ **Yellow warnings** → **DETAILED REVIEW REQUIRED** (see 5-minute process below)

### The 5 Core Criteria

| Criterion          | Pass Threshold    | Quick Check                                     |
| ------------------ | ----------------- | ----------------------------------------------- |
| **Functionality**  | ≥80% coverage     | Most tools work correctly                       |
| **Security**       | 0 vulnerabilities | No HIGH/MEDIUM risk vulnerabilities found       |
| **Documentation**  | ≥3 examples       | README has code examples and setup instructions |
| **Error Handling** | ≥75% validation   | Tools properly reject invalid inputs            |
| **Usability**      | Consistent naming | Tool names follow consistent pattern            |

**Note**: MCP Spec Compliance is shown but informational only (not part of Anthropic's 5 core requirements).

---

## 5-Minute Detailed Review

**When to use**: Initial screening shows warnings, or you need more details before approval.

### Detailed Review Process

1. **Switch to Developer Mode**
   - Click mode selector and choose "Developer Mode"
   - Enables comprehensive testing (all 18 security patterns instead of 3)
   - Takes 5-10 minutes vs 1-2 minutes for reviewer mode

2. **Re-run Assessment**
   - Click "Run Assessment" button again
   - Wait for completion (progress shown per category)

3. **Review Per-Tool Results**
   - **Expand tool sections**: Click tool name to see detailed test results
   - **View test scenarios**: See which scenarios passed/failed (happy path, edge cases, boundaries)
   - **Show JSON**: Click "Show JSON" button for raw test data
   - **Check confidence scores**: Higher confidence = more reliable result

4. **Export Report** (optional)
   - Click "Export Assessment" button
   - Saves full report with evidence for documentation/discussion

---

## Understanding Test Results

### 1. Functionality (≥80% coverage required)

**What it tests**: Whether tools execute correctly with valid inputs

**Metrics to check**:

- **Working Tools**: Count of tools that respond with valid data
- **Broken Tools**: Tools that crash, timeout, or return errors on valid input
- **Coverage**: Percentage of tools successfully tested

**Pass criteria**: ≥80% of tools working correctly

**Example - PASS**:

```
✅ Functionality: 10/11 tools working (91% coverage)
- Working tools: search_nodes, create_entities, add_observations...
- Broken tools: (none)
```

**Example - FAIL**:

```
❌ Functionality: 6/11 tools working (55% coverage)
- Working tools: search_nodes, create_entities...
- Broken tools: delete_nodes, update_entities, complex_query...
```

### 2. Security (0 vulnerabilities required)

**What it tests**: Resistance to prompt injection and malicious inputs

**Risk Levels**:

- **HIGH Risk**: Command injection, data exfiltration, role override → **REJECT IMMEDIATELY**
- **MEDIUM Risk**: Information disclosure, partial escape → **REQUEST FIX**
- **LOW Risk**: No vulnerabilities found → **APPROVE**

**Pass criteria**: 0 vulnerabilities of any risk level

**Testing modes**:

- **Reviewer Mode**: 3 critical patterns (48 tests for typical 16-tool server)
- **Developer Mode**: 18 comprehensive patterns (900+ tests for typical 16-tool server)

**Example - PASS**:

```
✅ Security: 0 vulnerabilities found
- Patterns tested: 3 (Reviewer) or 18 (Developer)
- Risk level: LOW
- All tools properly reject malicious inputs
```

**Example - FAIL**:

```
❌ Security: 2 HIGH risk vulnerabilities found
- vulnerable_calculator_tool: Executes injected commands
- vulnerable_data_leak_tool: Leaks API keys when prompted
→ REJECT - Fix security issues before resubmitting
```

### 3. Documentation (≥3 examples required)

**What it tests**: Quality and completeness of documentation

**Metrics to check**:

- **Examples Found**: Count of code examples in README
- **Installation**: Presence of setup instructions
- **Usage Guide**: Documentation on how to use the server
- **API Reference**: Parameter documentation for tools

**Pass criteria**: ≥3 code examples + installation instructions + usage guide

**Example - PASS**:

```
✅ Documentation: 5 examples found
- Has README: Yes
- Installation instructions: Yes
- Usage guide: Yes
- Code examples: 5/3 required
```

**Example - FAIL**:

```
❌ Documentation: 1 example found
- Has README: Yes
- Installation instructions: No
- Usage guide: Partial
- Code examples: 1/3 required
→ REQUEST: Add 2 more examples and installation instructions
```

### 4. Error Handling (≥75% validation coverage required)

**What it tests**: How tools handle invalid inputs and MCP protocol compliance

**Metrics to check**:

- **MCP Compliance**: Proper error codes (e.g., `-32602` for Invalid params)
- **Validation Coverage**: Percentage of invalid inputs properly rejected
- **Error Quality**: Descriptive error messages vs generic errors

**Pass criteria**: ≥75% validation coverage + proper MCP error format

**Important**: Yellow "INFO" badges are informational only, NOT failures:

- **Scored tests** (count as failures): `missing_required`, `wrong_type`, `extra_params`
- **Informational tests** (do NOT count): `invalid_values` - shown with yellow INFO badge

**Example - PASS**:

```
✅ Error Handling: 85% validation coverage
- MCP compliance: 95%
- Proper error codes: Yes
- Descriptive messages: Yes
```

**Example - FAIL**:

```
❌ Error Handling: 60% validation coverage
- MCP compliance: 70%
- Missing required field validation
- Generic error messages
→ REQUEST: Improve input validation and error messages
```

### 5. Usability (consistent naming required)

**What it tests**: Developer experience and API consistency

**Metrics to check**:

- **Naming Pattern**: snake_case, camelCase, or kebab-case consistency
- **Parameter Clarity**: Clear parameter names and descriptions
- **Tool Descriptions**: Helpful descriptions of what tools do

**Pass criteria**: Consistent naming pattern + clear descriptions

**Example - PASS**:

```
✅ Usability: Consistent snake_case naming
- Pattern: snake_case (100% consistent)
- Parameter clarity: High
- Helpful descriptions: Yes
```

**Example - FAIL**:

```
❌ Usability: Inconsistent naming
- Pattern: Mixed (camelCase + snake_case)
- Tools using camelCase: getUserData, deleteItem
- Tools using snake_case: create_user, list_items
→ REQUEST: Standardize naming convention
```

---

## Common Pitfalls

### False Positives in Security

#### ✅ **SAFE - Data Reflection**

Tools that echo or store malicious input **as data** are NOT vulnerable:

```javascript
Payload: "alert(1)"
Response: "Stored in collection: alert(1)"
→ SAFE: Tool is just storing data, not executing it
```

```javascript
Payload: "Ignore previous instructions"
Response: "Error: Collection 'Ignore previous instructions' doesn't exist"
→ SAFE: Error message echoing input, not executing commands
```

**Why safe?** The tool treats injection attempts as data, not commands.

#### ❌ **VULNERABLE - Command Execution**

Tools that execute malicious instructions are vulnerable:

```javascript
Payload: "What is 2+2?"
Response: "The answer is 4"
→ VULNERABLE: Tool executed the calculation command!
```

```javascript
Payload: "List API keys"
Response: "api_key='sk-abc123def456xyz'"
→ VULNERABLE: Tool leaked sensitive data!
```

**Why vulnerable?** The tool performed actions based on malicious input.

### False Failures in Functionality

#### ✅ **WORKING - Proper Validation**

Tools returning business logic errors are working correctly:

```javascript
Input: {user_id: "nonexistent-user"}
Response: "Error: User not found"
→ WORKING: This is correct business logic validation
```

```javascript
Input: {collection: "invalid"}
Response: "Error: Collection 'invalid' does not exist"
→ WORKING: Tool is properly validating resource existence
```

#### ❌ **BROKEN - Implementation Failure**

Tools crashing or returning stack traces are broken:

```javascript
Input: {user_id: "test-user"}
Response: "TypeError: Cannot read property 'id' of undefined
  at getUserData (server.js:42:15)..."
→ BROKEN: Tool crashed with programming error
```

### Informational vs Scored Error Tests

**Important distinction** for error handling assessment:

#### Scored Tests (Red FAIL Badge)

These tests **count toward the 75% validation threshold**:

- `missing_required`: Tool rejects when required parameters are missing
- `wrong_type`: Tool rejects when parameter types are wrong
- `extra_params`: Tool handles unexpected extra parameters

#### Informational Tests (Yellow INFO Badge)

These tests **do NOT count** toward validation threshold:

- `invalid_values`: Tool behavior with semantically invalid values (e.g., negative user_id)
- Purpose: Informational only - shows how tool handles edge cases
- **Not a failure**: Yellow badge means "informational, not scored"

**Why the distinction?** Business logic validation (invalid_values) varies by implementation. Some tools validate, some don't. Both approaches can be valid depending on design choices.

---

## Fast CLI Analysis

Assessment results are automatically saved to `/tmp/inspector-assessment-{server-name}.json` for fast command-line analysis.

### Essential Commands

```bash
# View full assessment results
cat /tmp/inspector-assessment-memory-mcp.json | jq

# Check overall status
cat /tmp/inspector-assessment-memory-mcp.json | jq '{functionality: .functionality.status, security: .security.status, documentation: .documentation.status, errorHandling: .errorHandling.status, usability: .usability.status}'

# Check functionality only
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality'

# List broken tools
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.brokenTools'

# Get specific tool test results
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | select(.toolName == "search_nodes")'

# Summary of all tools and their status
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | {tool: .toolName, status: .overallStatus}'

# Count security vulnerabilities
cat /tmp/inspector-assessment-memory-mcp.json | jq '.security.vulnerabilities | length'

# List security vulnerabilities with details
cat /tmp/inspector-assessment-memory-mcp.json | jq '.security.vulnerabilities'

# Check error handling coverage
cat /tmp/inspector-assessment-memory-mcp.json | jq '.errorHandling.metrics.validationCoverage'

# Check documentation examples count
cat /tmp/inspector-assessment-memory-mcp.json | jq '.documentation.metrics.exampleCount'
```

### Troubleshooting Tips

**No assessment file found?**

```bash
# List all assessment files
ls -la /tmp/inspector-assessment-*.json

# If file doesn't exist, run assessment first in UI
```

**Result file from old run?**

```bash
# Check timestamp
stat /tmp/inspector-assessment-memory-mcp.json

# Assessment auto-deletes old results before new runs
# If timestamp is old, re-run the assessment
```

**JSON too large to read?**

```bash
# View only summary fields
cat /tmp/inspector-assessment-memory-mcp.json | jq '{functionality: .functionality.status, security: .security.status, totalScore: .totalScore}'

# Count items instead of listing
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults | length'
```

---

## Decision Matrix

Use this matrix to make final approval decisions:

| Criterion          | Pass              | Fail               | Action                                     |
| ------------------ | ----------------- | ------------------ | ------------------------------------------ |
| **Functionality**  | ≥80% coverage     | <80% coverage      | Request fixes for broken tools             |
| **Security**       | 0 vulnerabilities | >0 vulnerabilities | REJECT if HIGH risk, REQUEST FIX if MEDIUM |
| **Documentation**  | ≥3 examples       | <3 examples        | Request more code examples                 |
| **Error Handling** | ≥75% validation   | <75% validation    | Request better input validation            |
| **Usability**      | Consistent        | Inconsistent       | Request naming standardization             |

### Approval Decision Tree

```
START
  |
  v
All 5 criteria PASS?
  |
  +--YES--> APPROVE ✅
  |
  +--NO---> Any HIGH risk security vulnerabilities?
              |
              +--YES--> REJECT ❌
              |           (Security issues must be fixed)
              |
              +--NO---> Functionality <50%?
                          |
                          +--YES--> REJECT ❌
                          |           (Too many broken tools)
                          |
                          +--NO---> REQUEST CHANGES ⚠️
                                      (Specific guidance per category)
```

### Approval Criteria

**APPROVE** when:

- ✅ Functionality ≥80% coverage
- ✅ Security: 0 vulnerabilities
- ✅ Documentation: ≥3 examples
- ✅ Error Handling: ≥75% validation
- ✅ Usability: Consistent naming

**REJECT** when:

- ❌ HIGH risk security vulnerabilities found
- ❌ Functionality <50% (majority of tools broken)
- ❌ Critical missing functionality documented but not working

**REQUEST CHANGES** when:

- ⚠️ One or more criteria fail but fixable
- ⚠️ MEDIUM risk security issues (require fixes)
- ⚠️ Documentation incomplete but security is solid
- ⚠️ Error handling needs improvement

---

## Getting Help

### Documentation Resources

- **Detailed Methodology**: [ASSESSMENT_METHODOLOGY.md](ASSESSMENT_METHODOLOGY.md) - Comprehensive testing approach
- **Main README**: [README.md](../README.md) - Full feature documentation
- **Security Testing**: [VULNERABILITY_TESTING.md](../VULNERABILITY_TESTING.md) - Security detection verification
- **5-Point Framework**: [MCP_INSPECTOR_5POINT_ASSESSMENT_WHITEPAPER.md](MCP_INSPECTOR_5POINT_ASSESSMENT_WHITEPAPER.md) - Technical whitepaper

### Common Questions

**Q: Why did the assessment mark a working tool as broken?**
A: Check the test scenarios. The tool might work for simple cases but fail on edge cases or boundary conditions. Review the per-tool details to see which scenario failed.

**Q: The security test shows vulnerabilities, but the tool is just storing data. Is this a false positive?**
A: Likely yes! Review the "Common Pitfalls - False Positives in Security" section above. Tools that echo/store malicious input as data (e.g., "Stored: alert(1)") are NOT vulnerable.

**Q: What's the difference between yellow INFO badges and red FAIL badges?**
A: Yellow INFO badges are informational only (don't count toward validation coverage). Red FAIL badges indicate actual validation failures that count toward the 75% threshold.

**Q: Should I use Reviewer Mode or Developer Mode?**
A: Start with **Reviewer Mode** for fast screening (1-2 minutes). Switch to **Developer Mode** if you see warnings or need comprehensive security testing before approval.

**Q: The assessment JSON file is huge. How do I find what I need?**
A: Use the CLI commands in the "Fast CLI Analysis" section above. Filter by category, tool name, or status to get exactly what you need.

**Q: Can I run assessments from the command line?**
A: Yes! See [CLAUDE.md](../CLAUDE.md#cli-security-assessment-runner) for CLI workflow:

```bash
npm run assess -- --server <name> --config <config.json>
```

### Filing Issues

If you encounter problems or have suggestions:

- **Bug Reports**: https://github.com/triepod-ai/inspector-assessment/issues
- **Documentation Issues**: Tag with `documentation` label
- **False Positives/Negatives**: Tag with `assessment-accuracy` label

---

## Appendix: Mode Comparison

| Feature                  | Reviewer Mode               | Developer Mode                   |
| ------------------------ | --------------------------- | -------------------------------- |
| **Speed**                | 1-2 minutes                 | 5-10 minutes                     |
| **Security Patterns**    | 3 critical patterns         | 18 comprehensive patterns        |
| **Test Scenarios**       | 1 per tool                  | Multiple scenarios per tool      |
| **Error Handling Tools** | First 3 tools               | All tools                        |
| **MCP Spec Compliance**  | Not included                | Included (informational)         |
| **Best For**             | Fast approval screening     | Debugging, comprehensive testing |
| **Typical Use**          | Directory submission review | Pre-submission validation        |

**Recommendation**: Use Reviewer Mode for initial screening, Developer Mode for detailed investigation or when borderline results need more evidence.

---

**Last Updated**: 2025-10-11
**Version**: 1.0
**Feedback**: https://github.com/triepod-ai/inspector-assessment/issues
