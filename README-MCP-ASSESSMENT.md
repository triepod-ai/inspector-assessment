# MCP Assessment Framework for Claude Desktop

## Overview

This project provides comprehensive instructions for Claude to assess MCP servers against Anthropic's 5 core requirements for MCP directory submission. It replicates the functionality of your custom MCP Inspector assessment tab directly within Claude Desktop conversations.

## What It Does

The framework enables Claude to systematically evaluate any connected MCP server by:

1. **Discovering and cataloging** all available tools
2. **Testing functionality** with generated parameters
3. **Running 17 security tests** for prompt injection vulnerabilities
4. **Validating error handling** with invalid inputs
5. **Analyzing documentation** for completeness and examples
6. **Evaluating usability** through naming and schema quality
7. **Generating comprehensive reports** with pass/fail recommendations

## Files Created

```
~/.claude/
├── mcp-assessment-instruction.md      # Main assessment instruction (detailed)
├── mcp-assessment-quick-reference.md  # Quick reference guide (practical)
└── README-MCP-ASSESSMENT.md          # This file
```

## Memory Storage

The framework is also stored in:

- ✅ **Qdrant** (`mcp_assessment_framework` collection): 10 documents covering all aspects
- ✅ **Chroma** (`mcp_assessment_framework` collection): 5 summary documents

You can recall these from memory instead of reading files.

## How to Use in Claude Desktop

### Prerequisites

1. Have an MCP server connected in Claude Desktop settings
2. Have the server's README/documentation ready to share

### Basic Usage

**Step 1**: Start the assessment

```
"Assess the Notion MCP server following the MCP Assessment instruction."
```

**Step 2**: Provide documentation when prompted

```
[Paste README content here]
```

**Step 3**: Review the generated assessment report

**Step 4**: Export results

```
"Export this assessment as markdown for submission."
```

### Advanced Usage

**Quick assessment (skip some tests)**:

```
"Do a quick MCP assessment of [server-name], focus on the 5 core criteria only."
```

**Detailed assessment (full testing)**:

```
"Perform a comprehensive MCP assessment with detailed security and error testing."
```

**Re-assess specific criterion**:

```
"Re-run the error handling assessment for [server-name]."
```

**Compare with previous assessment**:

```
"Compare this assessment with the previous one and highlight what changed."
```

## The 5 Core Criteria

| #   | Criterion                | Pass Threshold     | Test Method                      |
| --- | ------------------------ | ------------------ | -------------------------------- |
| 1   | **Functionality Match**  | ≥80% coverage      | Test each tool with valid params |
| 2   | **No Prompt Injections** | 0 vulnerabilities  | Run 17 injection patterns        |
| 3   | **Clear Tool Names**     | Consistent pattern | Analyze naming conventions       |
| 4   | **Working Examples**     | 3+ examples        | Parse documentation              |
| 5   | **Error Handling**       | ≥75% validation    | Test invalid inputs              |

## Assessment Phases

### Phase 1: Discovery (1-2 min)

- List all available tools
- Capture schemas and descriptions
- Identify tool count and complexity

### Phase 2: Functionality Testing (2-5 min)

- Generate valid test parameters from schemas
- Execute each tool
- Calculate success rate and coverage

### Phase 3: Security Testing (3-8 min)

- Run 17 injection patterns on representative tools
- Document vulnerabilities
- Assess risk level (LOW/MEDIUM/HIGH)

### Phase 4: Error Handling (2-4 min)

- Test wrong types, missing params, extra params, null values
- Check MCP error format compliance
- Calculate validation coverage

### Phase 5: Documentation Analysis (1-2 min)

- Extract code examples
- Verify installation instructions
- Check usage guide completeness

### Phase 6: Usability Evaluation (1-2 min)

- Analyze naming consistency
- Score description quality
- Assess schema completeness
- Calculate clarity metrics

## Report Structure

```markdown
# MCP Directory Assessment Report

**Overall Status**: PASS/FAIL/NEED_MORE_INFO

## Executive Summary

[Brief summary of findings]

## Assessment Results

### ✓ 1. Functionality Match [STATUS]

- Metrics, evidence, broken tools

### ✓ 2. Security [STATUS]

- Test results, vulnerabilities, risk level

### ✓ 3. Clear Tool Names [STATUS]

- Naming analysis, patterns, conflicts

### ✓ 4. Working Examples [STATUS]

- Documentation metrics, examples found

### ✓ 5. Error Handling [STATUS]

- Compliance score, validation coverage

## Overall Recommendation

Approve/Reject/Request Changes with justification

## Action Items

Specific improvements needed (if any)

## Metadata

Tests run, execution time, version
```

## Example Assessment

From your document:

```markdown
# Notion MCP Server Assessment

**Overall Status**: PASS ✓

## Summary

Tool list perfectly matches documentation (13 tools). Security tests passed - no prompt injection vulnerabilities. Error handling meets MCP spec requirements. Documentation includes 3+ working examples.

## Criteria Results

1. ✓ Functionality Match - PASS (13/13 tools working, 100% coverage)
2. ✓ No Prompt Injections - PASS (0 vulnerabilities, LOW risk)
3. ✓ Clear Tool Names - PASS (consistent "notion-" prefix)
4. ✓ Working Examples - PASS (3 examples found)
5. ✓ Error Handling - PASS (graceful errors, helpful messages)

## Recommendation

**Approve for production use** with read-only or low-risk writes in sandboxed workspace. Enable human confirmation for write operations per security documentation.
```

## Security Test Patterns

The framework tests 17 patterns including:

**High Risk**:

- Direct Command Injection
- Role Override
- Data Exfiltration
- System Commands
- Tool Shadowing
- Metadata Exfiltration
- Sandbox Escape
- Confused Deputy

**Medium Risk**:

- Context Escape
- Instruction Confusion
- Unicode Bypass
- Nested Injection
- Configuration Drift
- Rug Pull
- Package Squatting

## Scoring Logic

### Individual Criteria

**Functionality**:

- PASS = ≥80% tools working
- REVIEW = 50-79% working
- FAIL = <50% working

**Security**:

- PASS = No vulnerabilities
- REVIEW = Unclear behavior
- FAIL = Any confirmed vulnerability

**Tool Names**:

- PASS = Consistent, clear
- REVIEW = Minor issues
- FAIL = Conflicts/unclear

**Examples**:

- PASS = 3+ complete examples
- REVIEW = 1-2 examples
- FAIL = 0 examples

**Error Handling**:

- PASS = ≥75% validation
- REVIEW = 50-74% validation
- FAIL = <50% validation

### Overall Status

- **PASS**: All 5 criteria are PASS
- **FAIL**: Any criterion is FAIL, OR 2+ are NEED_MORE_INFO
- **NEED_MORE_INFO**: 1 criterion is NEED_MORE_INFO, rest are PASS

## Time Estimates

- **Small Server** (1-5 tools): 3-5 minutes
- **Medium Server** (6-15 tools): 8-12 minutes
- **Large Server** (16+ tools): 15-25 minutes

_Actual time varies based on tool complexity and server response times_

## Troubleshooting

### "No tools available"

**Solution**: Verify MCP server is properly connected in Claude Desktop settings (Settings > Developer > Model Context Protocol)

### "Tools timing out"

**Solution**: Server may be slow or rate-limited. Try testing fewer tools or sequentially.

### "Security tests show false positives"

**Solution**: Review actual tool responses, not just error messages. Confirm if tool executed malicious input.

### "Documentation score is low"

**Solution**: Ensure you provided complete README content with proper formatting (markdown).

### "Error handling tests failing"

**Solution**: Server may not follow MCP error format. Check if errors use `isError: true` pattern.

## Best Practices

1. ✅ **Test incrementally**: Start with 1-2 tools to verify connectivity
2. ✅ **Document assumptions**: Note any assumptions made during testing
3. ✅ **Verify evidence**: Cross-reference results with actual behavior
4. ✅ **Be thorough**: Complete all tests even if early results look good
5. ✅ **Stay objective**: Base status on metrics, not impressions
6. ✅ **Export early**: Save reports before making changes
7. ✅ **Iterate**: Re-test after fixes to verify improvements

## Comparison with Inspector Tool

| Feature                | Custom Inspector    | Claude Desktop Framework |
| ---------------------- | ------------------- | ------------------------ |
| Tool Discovery         | ✅ Automatic        | ✅ Automatic             |
| Functionality Testing  | ✅ Visual UI        | ✅ Conversational        |
| Security Tests         | ✅ 17 patterns      | ✅ 17 patterns           |
| Error Handling         | ✅ Comprehensive    | ✅ Comprehensive         |
| Documentation Analysis | ✅ File upload      | ✅ Paste content         |
| Usability Scoring      | ✅ 100-point system | ✅ 100-point system      |
| Report Export          | ✅ JSON/Text        | ✅ Markdown/JSON         |
| Evidence Screenshots   | ✅ Built-in         | ❌ Text-based            |
| Parallel Testing       | ✅ Optional         | ❌ Sequential            |
| Persistence            | ✅ Session-based    | ✅ Memory-based          |

## Integration with Your Workflow

This framework complements your MCP Inspector tool:

**Use Inspector when**:

- You need visual evidence (screenshots)
- You want parallel test execution
- You're developing/debugging the server locally

**Use Claude Desktop when**:

- You want conversational interaction
- You need to assess remote servers
- You want to iterate quickly with natural language
- You're doing contractor evaluations (like your take-home project)

## Quick Command Reference

```bash
# Basic assessment
"Assess [server-name] using MCP Assessment instruction"

# With documentation
"Perform MCP assessment for [server]. Here's the README: [paste]"

# Focus on specific criterion
"Re-run security testing for [server-name]"

# Export results
"Export this assessment as markdown"

# Compare assessments
"Compare with previous [server-name] assessment"

# Quick check
"Quick MCP assessment of [server], just the 5 criteria"
```

## Memory Commands

```bash
# Recall framework from memory
"Recall the MCP Assessment framework from memory"

# Search for specific info
"Find security test patterns in assessment framework"

# Update framework
"Update the assessment framework with [new information]"
```

## Version History

- **v1.0** (2025-10-04): Initial release
  - Based on Anthropic's 5 core requirements
  - 17 security test patterns
  - 6-phase assessment process
  - Comprehensive scoring logic
  - Qdrant + Chroma memory storage

## Files Location

```
~/.claude/
├── mcp-assessment-instruction.md      # Full detailed instruction
├── mcp-assessment-quick-reference.md  # Quick reference guide
└── README-MCP-ASSESSMENT.md          # This documentation
```

## Next Steps

1. **Try it out**: Assess an MCP server you're familiar with
2. **Compare results**: Run same assessment in Inspector tool and Claude Desktop
3. **Refine**: Note any differences or improvements needed
4. **Share**: Use for contractor evaluations or directory submissions

## Support

For issues or improvements:

1. Check the troubleshooting section above
2. Review the Quick Reference guide
3. Consult the full instruction document
4. Update memory with lessons learned

## License

Created based on the MCP Inspector open source project and Anthropic's MCP directory requirements.

---

**Ready to assess?** Just say: _"Assess [server-name] using the MCP Assessment instruction"_
