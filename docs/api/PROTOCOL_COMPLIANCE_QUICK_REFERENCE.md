# Protocol Compliance Assessor - Quick Reference

**Version**: 1.25.2
**Last Updated**: 2025-01-07

## One-Minute Overview

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);

console.log(result.complianceScore); // 0-100 score
console.log(result.status); // PASS | FAIL | NEED_MORE_INFO
console.log(result.explanation); // Human summary
console.log(result.recommendations); // Improvement suggestions
```

---

## Quick Start Templates

### Template 1: Basic Assessment

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  assessmentCategories: {
    protocolCompliance: true,
  },
});

const result = await assessor.assess({
  serverInfo: { name: "my-server", version: "1.0.0" },
  tools: [...],
  callTool: async (name, params) => { ... },
});
```

### Template 2: Production Configuration

```typescript
import { AUDIT_MODE_CONFIG } from "@/lib/assessment/configTypes";

const config = {
  ...AUDIT_MODE_CONFIG,
  assessmentCategories: {
    ...AUDIT_MODE_CONFIG.assessmentCategories,
    protocolCompliance: true,
  },
};

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);
```

### Template 3: Developer/Debug Mode

```typescript
import { DEVELOPER_MODE_CONFIG } from "@/lib/assessment/configTypes";

const config = {
  ...DEVELOPER_MODE_CONFIG,
  assessmentCategories: {
    ...DEVELOPER_MODE_CONFIG.assessmentCategories,
    protocolCompliance: true,
  },
  logging: { level: "debug" },
};

const assessor = new ProtocolComplianceAssessor(config);
```

---

## 10 Protocol Checks at a Glance

| #   | Check Name                | What It Tests                                   | Confidence |
| --- | ------------------------- | ----------------------------------------------- | ---------- |
| 1   | JSON-RPC Compliance       | Request/response structure                      | High       |
| 2   | Server Info Validity      | Name, version, metadata format                  | High       |
| 3   | Schema Compliance         | Tool input schema validation                    | High       |
| 4   | Error Response Compliance | Error format basics                             | High       |
| 5   | Structured Output Support | outputSchema presence                           | High       |
| 6   | Capabilities Compliance   | Declared vs actual capabilities                 | High       |
| 7   | Error Response Format     | Multi-tool error testing                        | High       |
| 8   | Content Type Support      | Valid content types (text/image/audio/resource) | High       |
| 9   | Initialization Handshake  | Server info completeness                        | High       |
| 10  | Protocol-Level Checks     | Combined scoring                                | Varies     |

---

## Result Interpretation

### Status Meanings

```
PASS         → complianceScore >= 90%
NEED_MORE_INFO → 70% <= complianceScore < 90%
FAIL         → complianceScore < 70% OR serverInfo invalid
```

### Quick Score Guide

- **95-100%**: Excellent - Production ready
- **80-94%**: Good - Minor issues to address
- **70-79%**: Fair - Recommend review before submission
- **Below 70%**: Poor - Critical issues to fix

### Confidence Levels

- **High**: Directly tested or validated
- **Medium**: Partial validation or metadata-based
- **Low**: Metadata-based hints only (requires manual verification)

---

## Configuration Cheat Sheet

### Key Options

```typescript
{
  testTimeout: 30000,              // ms per test (default)
  securityTestTimeout: 5000,       // ms for security tests
  skipBrokenTools: false,          // Skip non-responsive tools
  mcpProtocolVersion: "2025-06",   // MCP spec version for links

  assessmentCategories: {
    protocolCompliance: true,      // Enable protocol assessment
    // ... other categories
  },

  logging: { level: "info" },      // Log level
}
```

### Preset Configs

| Config         | Use Case       | Timeout | Speed             |
| -------------- | -------------- | ------- | ----------------- |
| DEFAULT        | General use    | 30s     | Normal            |
| DEVELOPER_MODE | Full debugging | 30s     | Slow (debug logs) |
| REVIEWER_MODE  | Fast checks    | 10s     | Fast              |
| AUDIT_MODE     | Pre-submission | 30s     | Normal            |

---

## API Methods

### Constructor

```typescript
new ProtocolComplianceAssessor(config: AssessmentConfiguration)
```

### Main Method

```typescript
assess(context: AssessmentContext): Promise<ProtocolComplianceAssessment>
```

### Utility Method

```typescript
getTestCount(): number
```

---

## Context Structure

```typescript
{
  serverInfo?: {
    name: string;
    version?: string;
    metadata?: {
      transport?: "stdio" | "streamable-http" | "sse";
      protocolVersion?: string;
      oauth?: { enabled: boolean; ... };
      // ... other metadata
    };
  };

  tools: Tool[];

  serverCapabilities?: {
    tools?: boolean;
    resources?: boolean;
    prompts?: boolean;
  };

  callTool: (name: string, params: Record<string, unknown>)
    => Promise<CallToolResult>;

  // Optional for capability validation
  resources?: Resource[];
  prompts?: Prompt[];
  readResource?: (uri: string) => Promise<unknown>;
  getPrompt?: (name: string) => Promise<unknown>;
}
```

---

## Result Structure

```typescript
{
  // Scores and status
  complianceScore: number;         // 0-100
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  protocolVersion: string;         // Detected version

  // Detailed checks
  protocolChecks: {
    jsonRpcCompliance: ProtocolCheck;
    serverInfoValidity: ProtocolCheck;
    schemaCompliance: ProtocolCheck;
    errorResponseCompliance: ProtocolCheck;
    contentTypeSupport: ProtocolCheck;
    structuredOutputSupport: ProtocolCheck;
    capabilitiesCompliance: ProtocolCheck;
  };

  conformanceChecks: {
    errorResponseFormat: ProtocolCheck;
    contentTypeSupport: ProtocolCheck;
    initializationHandshake: ProtocolCheck;
  };

  // Guidance
  explanation: string;             // Human summary
  recommendations: string[];       // Action items
  metadataHints?: MetadataHints;  // Low-confidence hints

  // Test tracking
  testCount?: number;
}
```

---

## Common Patterns

### Pattern 1: Check if Compliant

```typescript
if (result.status === "PASS") {
  console.log("Server is protocol compliant!");
}
```

### Pattern 2: Get Issues

```typescript
Object.entries(result.protocolChecks).forEach(([name, check]) => {
  if (!check.passed) {
    console.log(`${name}: ${check.evidence}`);
    check.warnings?.forEach((w) => console.log(`  - ${w}`));
  }
});
```

### Pattern 3: Apply Recommendations

```typescript
result.recommendations.forEach((rec) => {
  console.log(`Action: ${rec}`);
});
```

### Pattern 4: Multi-server Comparison

```typescript
const results = await Promise.all([
  assessor.assess(context1),
  assessor.assess(context2),
  assessor.assess(context3),
]);

results.forEach((r, i) => {
  console.log(`Server ${i + 1}: ${r.complianceScore}% (${r.status})`);
});
```

### Pattern 5: Monitor Over Time

```typescript
const history = [];
for (let i = 0; i < 5; i++) {
  const result = await assessor.assess(context);
  history.push({
    timestamp: new Date(),
    score: result.complianceScore,
    status: result.status,
  });
}

const avgScore = history.reduce((s, r) => s + r.score, 0) / history.length;
console.log(`Average score: ${avgScore.toFixed(1)}%`);
```

---

## Migration Quick Guide

### From MCPSpecComplianceAssessor

```diff
- import { MCPSpecComplianceAssessor } from "...";
- const assessor = new MCPSpecComplianceAssessor(config);
+ import { ProtocolComplianceAssessor } from "...";
+ const assessor = new ProtocolComplianceAssessor(config);

  const result = await assessor.assess(context);

- console.log(result.transportCompliance);
+ console.log(result.metadataHints?.transportHints);
```

### From ProtocolConformanceAssessor

```diff
- import { ProtocolConformanceAssessor } from "...";
- const assessor = new ProtocolConformanceAssessor(config);
+ import { ProtocolComplianceAssessor } from "...";
+ const assessor = new ProtocolComplianceAssessor(config);

  const result = await assessor.assess(context);

- console.log(result.errorResponseFormatCheck);
+ console.log(result.conformanceChecks?.errorResponseFormat);
```

### Configuration Flag

```diff
  assessmentCategories: {
-   mcpSpecCompliance: true,
-   protocolConformance: true,
+   protocolCompliance: true,
  }
```

---

## Troubleshooting

### Issue: Score is Lower Than Expected

**Check:**

1. Is `serverInfo` complete with name and version?
2. Are tools responding correctly?
3. Check `result.recommendations` for specific issues

### Issue: Confidence is "Low"

**Meaning:** Feature detected from metadata only, not tested directly
**Action:** Implement and test the feature to increase confidence

### Issue: Conformance Checks Missing

**Check:**

- Ensure `protocolCompliance` is enabled in config
- Verify assessor is `ProtocolComplianceAssessor`, not old modules

### Issue: Schema Validation Failing

**Check:**

- Tool schemas should be valid JSON Schema
- Use Ajv to validate: `new Ajv().validateSchema(schema)`

### Issue: Timeout Errors

**Solution:**

- Increase `testTimeout` value
- Or set `skipBrokenTools: true` to skip unresponsive tools

---

## Performance Tips

| Scenario        | Recommendation                                  |
| --------------- | ----------------------------------------------- |
| Quick check     | Use REVIEWER_MODE_CONFIG, timeout 10s           |
| Full validation | Use AUDIT_MODE_CONFIG, timeout 30s              |
| Many servers    | Enable parallelTesting, reduce per-tool timeout |
| Debugging       | Use DEVELOPER_MODE_CONFIG, check logs           |
| CI/CD           | Use timeout 10-15s, fail on FAIL status only    |

---

## Valid Values Reference

### Content Types

```
"text"          → Plain text content
"image"         → Image data with mimeType
"audio"         → Audio data with mimeType
"resource"      → Resource with URI and mimeType
"resource_link" → Link to resource URI
```

### Assessment Status

```
"PASS"           → Compliant (score >= 90%)
"NEED_MORE_INFO" → Partially compliant (70-89%)
"FAIL"           → Non-compliant (score < 70%)
```

### Confidence Levels

```
"high"   → Directly tested, reliable
"medium" → Partial validation, some assumptions
"low"    → Metadata-based, requires manual verification
```

### Transport Types

```
"stdio"           → Standard input/output
"streamable-http" → HTTP with streaming
"sse"             → Server-Sent Events (deprecated)
```

---

## Test Count Meaning

```
Total = Spec Checks (7) + Conformance Checks (3) = 10 checks
```

Each check can detect multiple protocol violations, so a single failed check may result in multiple recommendations.

---

## Files & Imports

```typescript
// Main module
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

// Configuration
import {
  DEFAULT_ASSESSMENT_CONFIG,
  DEVELOPER_MODE_CONFIG,
  REVIEWER_MODE_CONFIG,
  AUDIT_MODE_CONFIG,
} from "@/lib/assessment/configTypes";

// Types
import type {
  ProtocolComplianceAssessment,
  ProtocolCheck,
  AssessmentContext,
  AssessmentConfiguration,
} from "@/lib/assessment";
```

---

## External Links

- [Full API Reference](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)
- [Migration Guide](./PROTOCOL_COMPLIANCE_MIGRATION.md)
- [OpenAPI Spec](./protocol-compliance-assessor.openapi.yaml)
- [Postman Collection](./protocol-compliance-assessor.postman_collection.json)
- [MCP Specification](https://modelcontextprotocol.io/specification/2025-06)

---

## Version Info

| Version | Date       | Changes                               |
| ------- | ---------- | ------------------------------------- |
| 1.25.2  | 2025-01-07 | Unified MCPSpec + ProtocolConformance |
| 1.25.1  | 2024-12-15 | Profile corrections                   |
| 1.24.0  | 2024-11-01 | Initial MCPSpecCompliance             |

---

## Support

- **Tests**: `npm test -- ProtocolComplianceAssessor`
- **Build**: `npm run build`
- **Issues**: [GitHub Issues](https://github.com/triepod-ai/inspector-assessment/issues)
