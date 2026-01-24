# MCP Inspector Scoring Algorithm Guide

**Version**: 1.0.0
**Last Updated**: 2026-01-06

Complete reference for understanding how MCP Inspector calculates assessment scores, module weights, and final pass/fail determinations.

---

## Table of Contents

1. [Overview](#overview)
2. [Assessment Levels](#assessment-levels)
3. [Module Score Calculation](#module-score-calculation)
4. [Overall Score Calculation](#overall-score-calculation)
5. [Module Weights](#module-weights)
6. [Special Cases](#special-cases)
7. [Module Applicability](#module-applicability)
8. [Score Flow Diagram](#score-flow-diagram)
9. [Examples](#examples)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The MCP Inspector uses a **two-tier scoring system**:

1. **Per-Module Scores** (0-100): Each assessment module calculates its own score
2. **Overall Score** (0-100): Weighted average of 5 core module scores

The overall score determines the final **Assessment Level**: PASS, VERIFY, or FAIL.

```
┌─────────────────────────────────────────────────────────────────┐
│                    SCORING ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  18 Assessment Modules                                   │   │
│  │  (Each calculates 0-100 score independently)             │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  5 Core Modules Selected for Overall Score               │   │
│  │  - Functionality (25%)                                   │   │
│  │  - Security (25%)                                        │   │
│  │  - Documentation (20%)                                   │   │
│  │  - Error Handling (15%)                                  │   │
│  │  - Usability (15%)                                       │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Overall Score = Σ(module_score × weight)                │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Assessment Level                                        │   │
│  │  - PASS:   score >= 85                                   │   │
│  │  - VERIFY: score >= 50 && score < 85                     │   │
│  │  - FAIL:   score < 50                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Assessment Levels

| Level      | Score Range | Meaning                   | Recommended Action               |
| ---------- | ----------- | ------------------------- | -------------------------------- |
| **PASS**   | 85-100      | Production-ready quality  | Safe to publish/deploy           |
| **VERIFY** | 50-84       | Manual review recommended | Address issues before production |
| **FAIL**   | 0-49        | Significant issues found  | Not recommended for production   |

**Thresholds** (from `config.js`):

```javascript
const ASSESSMENT_THRESHOLDS = {
  PASS: 85, // Overall score >= 85
  VERIFY: 50, // Overall score >= 50 but < 85
  // FAIL: < 50 (implicit)
};
```

---

## Module Score Calculation

Each module calculates its score differently based on the type of assessment.

### Functionality Module

**Source Property**: `coveragePercentage`
**Formula**: Direct percentage of working tools

```javascript
// From moduleScoring.ts
if (r.coveragePercentage !== undefined) {
  return Math.round(r.coveragePercentage as number);
}
```

| Scenario           | Calculation             | Example Score |
| ------------------ | ----------------------- | ------------- |
| All tools working  | (working / total) × 100 | 100           |
| 8 of 10 tools work | (8 / 10) × 100          | 80            |
| Half tools broken  | (5 / 10) × 100          | 50            |

### Security Module

**Source Property**: `vulnerabilities` array
**Formula**: Penalty per vulnerability

```javascript
// From moduleScoring.ts
if (Array.isArray(r.vulnerabilities)) {
  const vulnCount = r.vulnerabilities.length;
  return vulnCount === 0 ? 100 : Math.max(0, 100 - vulnCount * 10);
}
```

| Vulnerabilities | Score |
| --------------- | ----- |
| 0               | 100   |
| 1               | 90    |
| 2               | 80    |
| 5               | 50    |
| 10+             | 0     |

### Error Handling Module

**Source Property**: `metrics.mcpComplianceScore`
**Formula**: Direct MCP protocol compliance percentage

```javascript
// From moduleScoring.ts
const metrics = r.metrics as Record<string, unknown> | undefined;
if (metrics?.mcpComplianceScore !== undefined) {
  return Math.round(metrics.mcpComplianceScore as number);
}
```

### MCP Spec Compliance Module

**Source Property**: `complianceScore`
**Formula**: Direct compliance percentage

```javascript
// From moduleScoring.ts
if (r.complianceScore !== undefined) {
  return Math.round(r.complianceScore as number);
}
```

### AUP Compliance Module

**Source Property**: `violations` array
**Formula**: Penalty per violation

```javascript
// From moduleScoring.ts
if (Array.isArray(r.violations)) {
  const violationCount = r.violations.length;
  return violationCount === 0 ? 100 : Math.max(0, 100 - violationCount * 10);
}
```

### Status-Based Modules

**Fallback**: Derive from `status` field

```javascript
// From moduleScoring.ts
// Default: derive from status field
return r.status === "PASS" ? 100 : r.status === "FAIL" ? 0 : 50;
```

| Status         | Score |
| -------------- | ----- |
| PASS           | 100   |
| NEED_MORE_INFO | 50    |
| FAIL           | 0     |

---

## Overall Score Calculation

The overall score is a **weighted average** of 5 core modules.

### Formula

```
Overall Score = Σ(module_score × weight)
             = (func × 0.25) + (sec × 0.25) + (doc × 0.20) + (err × 0.15) + (usab × 0.15)
```

### Implementation (from `utilities.js`)

```javascript
function calculateOverallScore(scores) {
  const weights = {
    functionality: 0.25,
    security: 0.25,
    documentation: 0.2,
    errorHandling: 0.15,
    usability: 0.15,
  };

  let total = 0;
  for (const [key, weight] of Object.entries(weights)) {
    total += (scores[key] || 0) * weight;
  }

  return Math.round(total);
}
```

---

## Module Weights

| Module             | Weight | Rationale                               |
| ------------------ | ------ | --------------------------------------- |
| **Functionality**  | 25%    | Core purpose - tools must work          |
| **Security**       | 25%    | Critical - vulnerabilities are blocking |
| **Documentation**  | 20%    | Important for usability and maintenance |
| **Error Handling** | 15%    | MCP protocol compliance matters         |
| **Usability**      | 15%    | User experience and best practices      |

### Weight Distribution Visualization

```
Functionality  ████████████████████████████████████████████████████ 25%
Security       ████████████████████████████████████████████████████ 25%
Documentation  ███████████████████████████████████████████         20%
Error Handling ██████████████████████████████                      15%
Usability      ██████████████████████████████                      15%
               |----|----|----|----|----|----|----|----|----|----|
               0%   10%  20%  30%  40%  50%  60%  70%  80%  90%  100%
```

### Modules NOT in Overall Score

These 12 modules are assessed but **do not affect** the overall score:

| Module               | Reason                                   |
| -------------------- | ---------------------------------------- |
| MCP Spec Compliance  | Informational - detailed protocol checks |
| AUP Compliance       | Informational - policy checks            |
| Tool Annotations     | Informational - metadata quality         |
| Prohibited Libraries | Informational - dependency audit         |
| Manifest Validation  | Only applies to MCPB bundles             |
| Portability          | Only applies to source code analysis     |
| Temporal             | Rug-pull detection (informational)       |
| Resources            | Optional capability (if server supports) |
| Prompts              | Optional capability (if server supports) |
| Cross-Capability     | Security analysis (informational)        |
| External APIs        | Informational - API usage audit          |

---

## Special Cases

### N/A Modules

Modules marked N/A (Not Applicable) receive a **score of 100** so they don't negatively impact results.

```javascript
// From MODULE_APPLICABILITY in config.js
const MODULE_APPLICABILITY = {
  github: {
    manifestValidation: false, // N/A - No manifest for GitHub repos
    temporal: false, // N/A - Timing tests need live server
  },
  http: {
    prohibitedLibraries: false, // N/A - Can't analyze source code
    documentation: false, // N/A - Can't analyze README
    portability: false, // N/A - Can't analyze source code
  },
};
```

### INFO-Only Modules

Some modules display as INFO (not PASS/FAIL) for certain audit types:

```javascript
// From INFO_ONLY_MODULES in config.js
const INFO_ONLY_MODULES = {
  github: ["portability", "manifestValidation"],
  http: ["portability", "manifestValidation"],
  local: [], // Local audits show real PASS/FAIL status
};
```

### Zero Score Handling

If a core module returns 0, it can significantly impact the overall score:

| Scenario                       | Score Impact        |
| ------------------------------ | ------------------- |
| Security = 0 (10+ vulns)       | -25 points from max |
| Functionality = 0 (all broken) | -25 points from max |
| Documentation = 0              | -20 points from max |

### Missing Module Data

If module data is missing (`undefined` or `null`):

```javascript
// From utilities.js
total += (scores[key] || 0) * weight; // Missing = 0
```

---

## Module Applicability

Different audit types enable different modules:

| Module               | GitHub | HTTP | Local |
| -------------------- | ------ | ---- | ----- |
| Functionality        | ✅     | ✅   | ✅    |
| Security             | ✅     | ✅   | ✅    |
| Documentation        | ✅     | ❌   | ✅    |
| Error Handling       | ✅     | ✅   | ✅    |
| Usability            | ✅     | ✅   | ✅    |
| MCP Spec Compliance  | ✅     | ✅   | ✅    |
| AUP Compliance       | ✅     | ✅   | ✅    |
| Tool Annotations     | ✅     | ✅   | ✅    |
| Prohibited Libraries | ✅     | ❌   | ✅    |
| Manifest Validation  | ❌     | ❌   | ✅    |
| Portability          | ✅     | ❌   | ✅    |
| Temporal             | ❌     | ✅   | ✅    |
| Resources            | ✅     | ✅   | ✅    |
| Prompts              | ✅     | ✅   | ✅    |
| Cross-Capability     | ✅     | ✅   | ✅    |

**Legend**: ✅ = Applicable, ❌ = N/A (scored as 100)

---

## Score Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                       SCORING FLOW EXAMPLE                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Input: MCP Server Assessment Results                                   │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │
│  │ Functionality   │  │ Security        │  │ Documentation   │        │
│  │ 10/10 tools ok  │  │ 0 vulns found   │  │ README exists   │        │
│  │ ────────────────│  │ ────────────────│  │ ────────────────│        │
│  │ Score: 100      │  │ Score: 100      │  │ Score: 85       │        │
│  │ Weight: 25%     │  │ Weight: 25%     │  │ Weight: 20%     │        │
│  │ Contribution: 25│  │ Contribution: 25│  │ Contribution: 17│        │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘        │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐                              │
│  │ Error Handling  │  │ Usability       │                              │
│  │ 90% MCP compliant│ │ Good naming     │                              │
│  │ ────────────────│  │ ────────────────│                              │
│  │ Score: 90       │  │ Score: 88       │                              │
│  │ Weight: 15%     │  │ Weight: 15%     │                              │
│  │ Contribution:13.5│ │ Contribution:13.2│                             │
│  └─────────────────┘  └─────────────────┘                              │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  Overall Score = 25 + 25 + 17 + 13.5 + 13.2 = 93.7 → 94                │
│                                                                         │
│  94 >= 85 → Level: PASS ✅                                              │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Examples

### Example 1: Perfect Score (PASS)

```json
{
  "functionality": { "coveragePercentage": 100 },
  "security": { "vulnerabilities": [] },
  "documentation": { "status": "PASS" },
  "errorHandling": { "metrics": { "mcpComplianceScore": 100 } },
  "usability": { "status": "PASS" }
}
```

**Calculation**:

- Functionality: 100 × 0.25 = 25.0
- Security: 100 × 0.25 = 25.0
- Documentation: 100 × 0.20 = 20.0
- Error Handling: 100 × 0.15 = 15.0
- Usability: 100 × 0.15 = 15.0
- **Overall: 100 → PASS**

### Example 2: Security Vulnerabilities (VERIFY)

```json
{
  "functionality": { "coveragePercentage": 95 },
  "security": { "vulnerabilities": ["vuln1", "vuln2", "vuln3"] },
  "documentation": { "status": "PASS" },
  "errorHandling": { "metrics": { "mcpComplianceScore": 85 } },
  "usability": { "status": "PASS" }
}
```

**Calculation**:

- Functionality: 95 × 0.25 = 23.75
- Security: (100 - 3×10) = 70 × 0.25 = 17.5
- Documentation: 100 × 0.20 = 20.0
- Error Handling: 85 × 0.15 = 12.75
- Usability: 100 × 0.15 = 15.0
- **Overall: 89 → PASS** (still passes due to other strong scores)

### Example 3: Multiple Issues (FAIL)

```json
{
  "functionality": { "coveragePercentage": 40 },
  "security": { "vulnerabilities": ["v1", "v2", "v3", "v4", "v5", "v6"] },
  "documentation": { "status": "FAIL" },
  "errorHandling": { "metrics": { "mcpComplianceScore": 30 } },
  "usability": { "status": "FAIL" }
}
```

**Calculation**:

- Functionality: 40 × 0.25 = 10.0
- Security: (100 - 6×10) = 40 × 0.25 = 10.0
- Documentation: 0 × 0.20 = 0.0
- Error Handling: 30 × 0.15 = 4.5
- Usability: 0 × 0.15 = 0.0
- **Overall: 24.5 → 25 → FAIL**

---

## Troubleshooting

### Common Score Issues

| Issue                  | Cause                              | Solution                                |
| ---------------------- | ---------------------------------- | --------------------------------------- |
| Score unexpectedly low | Security vulnerabilities           | Check `.security.vulnerabilities` array |
| Score shows 0          | All tools broken or module crashed | Check functionality test results        |
| N/A showing for module | Audit type doesn't support module  | Expected behavior (see applicability)   |
| Score not updating     | Cache or stale results             | Rerun assessment with `force: true`     |

### Debug Commands

```bash
# Check overall score
cat /tmp/inspector-assessment-*.json | jq '.overallScore'

# Check module scores
cat /tmp/inspector-assessment-*.json | jq '{
  functionality: .modules.functionality.coveragePercentage,
  security: (100 - (.modules.security.vulnerabilities | length) * 10),
  protocolCompliance: .modules.protocolCompliance.metrics.mcpComplianceScore
}'

# Count vulnerabilities
cat /tmp/inspector-assessment-*.json | jq '.modules.security.vulnerabilities | length'

# Check module applicability
cat /tmp/inspector-assessment-*.json | jq 'keys'
```

### Score Verification

To manually verify a score:

```javascript
// Calculate expected overall score
const scores = {
  functionality: 90, // from .functionality.coveragePercentage
  security: 80, // from 100 - (vulnCount * 10)
  documentation: 100, // from status === "PASS" ? 100 : 0
  errorHandling: 85, // from .errorHandling.metrics.mcpComplianceScore
  usability: 100, // from status === "PASS" ? 100 : 0
};

const weights = {
  functionality: 0.25,
  security: 0.25,
  documentation: 0.2,
  errorHandling: 0.15,
  usability: 0.15,
};

let total = 0;
for (const [key, weight] of Object.entries(weights)) {
  total += scores[key] * weight;
}
console.log(`Expected: ${Math.round(total)}`);
// Output: Expected: 91
```

---

## Source Code References

| File                                       | Purpose                            |
| ------------------------------------------ | ---------------------------------- |
| `client/src/lib/moduleScoring.ts`          | Per-module score calculation       |
| `server/workers/audit-worker/utilities.js` | Overall score calculation          |
| `server/workers/audit-worker/config.js`    | Thresholds, weights, applicability |

---

## Version History

| Version | Date       | Changes               |
| ------- | ---------- | --------------------- |
| 1.0.0   | 2026-01-03 | Initial documentation |

---

## Related Documentation

- [Assessment Catalog](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- [Audit Worker Architecture](/home/bryan/mcp-auditor/docs/AUDIT_WORKER_ARCHITECTURE.md) - Data flow
- [Inspector/Auditor Data Contract](/home/bryan/mcp-auditor/docs/INSPECTOR_AUDITOR_DATA_CONTRACT.md) - Property mapping
