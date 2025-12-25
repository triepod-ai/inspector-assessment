# Real-Time Progress Output (v1.8.1)

## Overview

The MCP Inspector emits real-time module completion status to stderr during assessment execution. This enables external tools (like the MCP Auditor) to display live progress and scores as each assessment module completes.

## Output Format

```
<emoji> <ModuleName>: <STATUS> (<score>%)
```

## Example Output

```
✅ Functionality: PASS (95%)
❌ Security: FAIL (70%)
⚠️ Documentation: NEED_MORE_INFO (50%)
✅ Error Handling: PASS (88%)
✅ Usability: PASS (100%)
✅ MCP Spec: PASS (92%)
```

## Emoji Mapping

| Emoji | Status                             |
| ----- | ---------------------------------- |
| ✅    | PASS                               |
| ❌    | FAIL                               |
| ⚠️    | NEED_MORE_INFO (or other statuses) |

## Score Calculation

Scores are calculated differently based on module type:

| Module Type         | Score Source                 | Calculation                          |
| ------------------- | ---------------------------- | ------------------------------------ |
| Functionality       | `workingPercentage`          | Direct percentage of working tools   |
| Error Handling      | `metrics.mcpComplianceScore` | MCP compliance percentage            |
| MCP Spec Compliance | `complianceScore`            | Direct compliance score              |
| Security            | `vulnerabilities[]`          | `100 - (vulnCount * 10)`, min 0      |
| AUP Compliance      | `violations[]`               | `100 - (violationCount * 10)`, min 0 |
| Others              | Status-based                 | PASS=100, FAIL=0, other=50           |

## Module Names

Progress is emitted for all 11 assessment modules:

**Core Modules (5):**

- Functionality
- Security
- Documentation
- Error Handling
- Usability

**Extended Modules (6)** - when `enableExtendedAssessment: true`:

- MCP Spec
- AUP
- Annotations
- Libraries
- Manifest
- Portability

## Implementation Details

- **File**: `client/src/services/assessment/AssessmentOrchestrator.ts`
- **Function**: `emitModuleProgress()` (lines 43-84)
- **Output Stream**: stderr (doesn't interfere with JSON stdout)
- **Emission Points**: After each module completes (both parallel and sequential execution)

## Usage

Progress output is automatic when running CLI assessments:

```bash
npm run assess -- --server <server-name> --config <config.json>
```

The progress lines appear on stderr while the final JSON results go to stdout, allowing both to be captured separately:

```bash
# Capture progress to file, JSON to variable
npm run assess -- --server my-server --config config.json 2>progress.log
```

## Consumer Integration

### MCP Auditor

The MCP Auditor backend parses this output to display live scores during audit execution. The regex pattern used:

```regex
^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$
```

### Custom Integration

To parse progress output in your own tools:

```javascript
const progressRegex = /^([✅❌⚠️]) ([^:]+): ([A-Z_]+) \((\d+)%\)$/;
const match = line.match(progressRegex);
if (match) {
  const [, emoji, moduleName, status, score] = match;
  // Update UI with module progress
}
```

## Tests

Comprehensive regression tests ensure the feature works correctly:

- **File**: `client/src/services/assessment/__tests__/emitModuleProgress.test.ts`
- **Test Count**: 14 test cases
- **Coverage**:
  - Emoji selection (PASS/FAIL/NEED_MORE_INFO)
  - Score calculation from various module result types
  - Output format validation
  - Core and extended module name coverage
  - Parallel and sequential execution modes
  - Edge cases (no tools, many tools)

## Version History

- **v1.8.1**: Initial implementation of real-time progress output
