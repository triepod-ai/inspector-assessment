# ProtocolComplianceAssessor API Documentation

**Version**: 1.25.2
**Module**: `@/services/assessment/modules/ProtocolComplianceAssessor`
**Status**: Production Ready
**Last Updated**: 2025-01-07

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [API Reference](#api-reference)
4. [Types & Interfaces](#types--interfaces)
5. [Configuration](#configuration)
6. [Usage Examples](#usage-examples)
7. [Migration Guide](#migration-guide)
8. [Testing](#testing)

---

## Overview

The `ProtocolComplianceAssessor` is a unified module that validates MCP (Model Context Protocol) compliance across both specification and conformance dimensions. It merges functionality from:

- **MCPSpecComplianceAssessor** - Protocol specification validation
- **ProtocolConformanceAssessor** - Protocol conformance testing

### What Gets Checked

The assessor performs 8 protocol checks organized in two sections:

**Section 1: Protocol Specification Checks**

1. JSON-RPC 2.0 Compliance - Validates request/response structure
2. Server Info Validity - Validates initialization handshake metadata
3. Schema Compliance - Validates tool input schemas with AJV
4. Error Response Format - Validates error responses through actual tool calls
5. Content Type Support - Validates response content types (text, image, audio, resource)
6. Structured Output Support - Checks for outputSchema usage (MCP 2025-06-18 feature)
7. Capabilities Compliance - Validates declared vs actual capabilities

**Section 2: Conformance-Style Checks**

1. Error Response Format - Multi-tool testing with detailed validations
2. Content Type Support - Validates content structure in responses
3. Initialization Handshake - Validates server info and capabilities

### Return Values

All checks return:

- **Status**: `boolean` (passed/failed)
- **Confidence**: `"high" | "medium" | "low"`
- **Evidence**: string describing what was tested
- **Details**: Optional object with granular validation results

---

## Quick Start

### Basic Usage

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessment/configTypes";

// Create assessor instance
const config = {
  ...DEFAULT_ASSESSMENT_CONFIG,
  assessmentCategories: {
    ...DEFAULT_ASSESSMENT_CONFIG.assessmentCategories,
    protocolCompliance: true, // Enable protocol compliance assessment
  },
};
const assessor = new ProtocolComplianceAssessor(config);

// Run assessment
const result = await assessor.assess(context);

// Access results
console.log(result.complianceScore); // 0-100 score
console.log(result.status); // "PASS" | "FAIL" | "NEED_MORE_INFO"
console.log(result.protocolChecks); // 7 specification checks
console.log(result.conformanceChecks); // 3 conformance checks
console.log(result.explanation); // Human-readable summary
console.log(result.recommendations); // Array of improvement suggestions
```

### Minimal Configuration

For quick testing, use minimal config:

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  skipBrokenTools: false,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
    protocolCompliance: true, // Only check protocol
  },
});
```

---

## API Reference

### Class: ProtocolComplianceAssessor

#### Constructor

```typescript
constructor(config: AssessmentConfiguration)
```

Creates a new protocol compliance assessor.

**Parameters:**

- `config` (AssessmentConfiguration): Configuration object controlling test behavior

**Example:**

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 30000,
  skipBrokenTools: false,
  assessmentCategories: {
    protocolCompliance: true,
  },
});
```

#### `assess(context: AssessmentContext): Promise<ProtocolComplianceAssessment>`

Main entry point for protocol compliance assessment.

**Parameters:**

- `context` (AssessmentContext): Provides server info, tools, capabilities, and callTool function

**Returns:** Promise resolving to `ProtocolComplianceAssessment` object

**Key Context Properties:**

```typescript
interface AssessmentContext {
  serverInfo?: {
    name: string;
    version: string;
    metadata?: Record<string, unknown>;
  };
  tools: Tool[];
  serverCapabilities?: {
    tools?: boolean;
    resources?: boolean;
    prompts?: boolean;
  };
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CallToolResult>;
  resources?: Resource[];
  prompts?: Prompt[];
  // Optional for capability checking
  readResource?: (uri: string) => Promise<unknown>;
  getPrompt?: (name: string) => Promise<unknown>;
}
```

**Example:**

```typescript
const result = await assessor.assess({
  serverInfo: {
    name: "my-server",
    version: "1.0.0",
    metadata: {
      transport: "streamable-http",
      oauth: { enabled: true },
    },
  },
  tools: [
    {
      name: "calculator",
      description: "Simple calculator",
      inputSchema: {
        type: "object",
        properties: { operation: { type: "string" } },
      },
    },
  ],
  serverCapabilities: {
    tools: true,
  },
  callTool: async (name, params) => {
    // Call the actual MCP server
    return { content: [{ type: "text", text: "result" }] };
  },
});
```

#### `getTestCount(): number`

Returns the total number of protocol checks performed.

**Returns:** `number` - Total test count

**Example:**

```typescript
const result = await assessor.assess(context);
const testCount = assessor.getTestCount();
console.log(`Ran ${testCount} protocol compliance checks`);
```

---

## Types & Interfaces

### ProtocolComplianceAssessment

Main result type returned by `assess()` method.

```typescript
export interface ProtocolComplianceAssessment extends MCPSpecComplianceAssessment {
  // Unified assessment results
  protocolVersion: string;
  protocolChecks: ProtocolChecks;
  conformanceChecks?: {
    errorResponseFormat: ProtocolCheck;
    contentTypeSupport: ProtocolCheck;
    initializationHandshake: ProtocolCheck;
  };
  metadataHints?: MetadataHints;

  // Score and status
  complianceScore: number; // 0-100
  status: AssessmentStatus; // "PASS" | "FAIL" | "NEED_MORE_INFO"
  explanation: string;
  recommendations: string[];

  // Legacy fields (backward compatible, deprecated)
  transportCompliance: TransportComplianceMetrics;
  oauthImplementation?: OAuthComplianceMetrics;
  annotationSupport: AnnotationSupportMetrics;
  streamingSupport: StreamingSupportMetrics;
}

export type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO";
```

### ProtocolChecks

Object containing all 7 protocol specification checks.

```typescript
export interface ProtocolChecks {
  jsonRpcCompliance: ProtocolCheck;
  serverInfoValidity: ProtocolCheck;
  schemaCompliance: ProtocolCheck;
  errorResponseCompliance: ProtocolCheck;
  contentTypeSupport: ProtocolCheck;
  structuredOutputSupport: ProtocolCheck;
  capabilitiesCompliance: ProtocolCheck;
}
```

### ProtocolCheck

Individual protocol check result with standardized structure.

```typescript
export interface ProtocolCheck {
  passed: boolean;
  confidence: "high" | "medium" | "low";
  evidence: string; // What was tested
  rawResponse?: unknown; // Actual server response
  specReference?: string; // Link to MCP spec
  warnings?: string[]; // Non-critical issues
  details?: Record<string, unknown>; // Granular validation results
}
```

### ConformanceChecks

Optional object containing 3 conformance-style checks.

```typescript
export interface ConformanceChecks {
  errorResponseFormat: ProtocolCheck; // Error format validation
  contentTypeSupport: ProtocolCheck; // Content type validation
  initializationHandshake: ProtocolCheck; // Server info validation
}
```

### MetadataHints

Low-confidence metadata-based hints for features not tested directly.

```typescript
export interface MetadataHints {
  confidence: "low";
  requiresManualVerification: boolean;
  transportHints?: {
    detectedTransport: string;
    supportsStdio: boolean;
    supportsHTTP: boolean;
    supportsSSE: boolean;
    detectionMethod: "metadata" | "assumed";
  };
  oauthHints?: {
    hasOAuthConfig: boolean;
    supportsOAuth: boolean;
    supportsPKCE: boolean;
    resourceIndicators?: string[];
  };
  annotationHints?: {
    supportsReadOnlyHint: boolean;
    supportsDestructiveHint: boolean;
    supportsTitleAnnotation: boolean;
    customAnnotations?: string[];
  };
  streamingHints?: {
    supportsStreaming: boolean;
    streamingProtocol?: "http-streaming" | "sse" | "websocket";
  };
  manualVerificationSteps?: string[];
}
```

### Scoring Rules

```typescript
complianceScore = (passedChecks / totalChecks) * 100

Status determination:
- serverInfoValidity.passed === false  → status = "FAIL"
- complianceScore >= 90%               → status = "PASS"
- complianceScore >= 70%               → status = "NEED_MORE_INFO"
- complianceScore < 70%                → status = "FAIL"
```

---

## Configuration

### Configuration Interface

```typescript
export interface AssessmentConfiguration {
  // Test timeouts
  testTimeout: number; // ms per tool (default 30000)
  securityTestTimeout?: number; // ms for security tests (default 5000)
  delayBetweenTests?: number; // ms delay between tests (default 0)

  // Behavior flags
  skipBrokenTools: boolean;
  reviewerMode?: boolean;
  enableExtendedAssessment?: boolean;

  // MCP protocol version (for spec links)
  mcpProtocolVersion?: string; // default "2025-06"

  // Assessment categories (which assessors to run)
  assessmentCategories?: {
    protocolCompliance?: boolean; // Enable this assessor
    // Other categories...
  };
}
```

### Configuration Presets

Use predefined configurations for common scenarios:

```typescript
import {
  DEFAULT_ASSESSMENT_CONFIG,
  DEVELOPER_MODE_CONFIG,
  AUDIT_MODE_CONFIG,
} from "@/lib/assessment/configTypes";

// Quick testing (10s timeout, minimal checks)
const quickConfig = {
  ...DEFAULT_ASSESSMENT_CONFIG,
  testTimeout: 10000,
  assessmentCategories: {
    protocolCompliance: true,
  },
};

// Comprehensive testing (all checks enabled)
const devConfig = {
  ...DEVELOPER_MODE_CONFIG,
  assessmentCategories: {
    ...DEVELOPER_MODE_CONFIG.assessmentCategories,
    protocolCompliance: true,
  },
};

// Pre-submission audit (30s timeout, all categories enabled)
const auditConfig = {
  ...AUDIT_MODE_CONFIG,
  assessmentCategories: {
    ...AUDIT_MODE_CONFIG.assessmentCategories,
    protocolCompliance: true,
  },
};
```

---

## Usage Examples

### Example 1: Complete Assessment with Full Server Info

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 30000,
  skipBrokenTools: false,
  assessmentCategories: {
    protocolCompliance: true,
  },
});

const context = {
  serverInfo: {
    name: "advanced-calculator",
    version: "2.0.0",
    metadata: {
      transport: "streamable-http",
      protocolVersion: "2025-06-18",
      oauth: {
        enabled: true,
        supportsPKCE: true,
        scopes: ["read", "write"],
      },
      annotations: {
        supported: true,
        types: ["readOnly", "destructive"],
      },
      streaming: {
        supported: true,
        protocol: "http-streaming",
      },
    },
  },
  tools: [
    {
      name: "add",
      description: "Add two numbers",
      inputSchema: {
        type: "object",
        properties: {
          a: { type: "number" },
          b: { type: "number" },
        },
        required: ["a", "b"],
      },
      outputSchema: {
        type: "object",
        properties: {
          result: { type: "number" },
        },
      },
    },
    {
      name: "multiply",
      description: "Multiply two numbers",
      inputSchema: {
        type: "object",
        properties: {
          a: { type: "number" },
          b: { type: "number" },
        },
        required: ["a", "b"],
      },
      outputSchema: {
        type: "object",
        properties: {
          result: { type: "number" },
        },
      },
    },
  ],
  serverCapabilities: {
    tools: true,
    resources: false,
    prompts: false,
  },
  callTool: async (name, params) => {
    // Simulate tool execution
    if (name === "add") {
      const { a, b } = params as { a: number; b: number };
      return {
        content: [{ type: "text", text: JSON.stringify({ result: a + b }) }],
      };
    }
    return { content: [{ type: "text", text: "unknown tool" }] };
  },
};

const result = await assessor.assess(context);

// Analyze results
console.log(`Compliance Score: ${result.complianceScore}%`);
console.log(`Status: ${result.status}`);
console.log(`\nProtocol Checks:`);
Object.entries(result.protocolChecks).forEach(([name, check]) => {
  console.log(
    `  ${name}: ${check.passed ? "PASS" : "FAIL"} (${check.confidence})`,
  );
});

if (result.conformanceChecks) {
  console.log(`\nConformance Checks:`);
  Object.entries(result.conformanceChecks).forEach(([name, check]) => {
    console.log(`  ${name}: ${check.passed ? "PASS" : "FAIL"}`);
  });
}

console.log(`\nExplanation: ${result.explanation}`);
console.log(`\nRecommendations:`);
result.recommendations.forEach((rec) => console.log(`  - ${rec}`));
```

**Expected Output:**

```
Compliance Score: 95.7%
Status: PASS

Protocol Checks:
  jsonRpcCompliance: PASS (high)
  serverInfoValidity: PASS (high)
  schemaCompliance: PASS (high)
  errorResponseCompliance: PASS (high)
  contentTypeSupport: PASS (high)
  structuredOutputSupport: PASS (high)
  capabilitiesCompliance: PASS (high)

Conformance Checks:
  errorResponseFormat: PASS
  contentTypeSupport: PASS
  initializationHandshake: PASS

Explanation: Excellent MCP protocol compliance. Server meets all critical
requirements verified through protocol testing.

Recommendations:
  - Excellent MCP compliance! All protocol checks passed. Server is ready for
    directory submission.
```

### Example 2: Minimal Server (Edge Case)

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  assessmentCategories: {
    protocolCompliance: true,
  },
});

const context = {
  // Minimal server info (only name)
  serverInfo: {
    name: "minimal-server",
  },
  tools: [],
  callTool: async () => ({
    content: [{ type: "text", text: "ok" }],
  }),
};

const result = await assessor.assess(context);

console.log(`Compliance Score: ${result.complianceScore}%`);
console.log(`Status: ${result.status}`);
console.log(`Explanation: ${result.explanation}`);
```

### Example 3: Detecting Protocol Issues

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  assessmentCategories: {
    protocolCompliance: true,
  },
});

const context = {
  serverInfo: {
    name: "broken-server",
    version: "1.0.0",
  },
  tools: [
    {
      name: "broken_tool",
      description: "Tool with invalid schema",
      inputSchema: {
        type: "object",
        // Missing properties - invalid schema
      },
    },
  ],
  callTool: async (name) => {
    // Returns error response with isError flag
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: "Tool failed due to invalid input",
        },
      ],
    };
  },
};

const result = await assessor.assess(context);

if (!result.status === "PASS") {
  console.log("Issues detected:");
  result.recommendations.forEach((rec) => console.log(`  - ${rec}`));

  // Get detailed check results
  Object.entries(result.protocolChecks).forEach(([name, check]) => {
    if (!check.passed) {
      console.log(`\n${name} FAILED`);
      console.log(`  Evidence: ${check.evidence}`);
      if (check.warnings) {
        check.warnings.forEach((w) => console.log(`  Warning: ${w}`));
      }
    }
  });
}
```

### Example 4: Monitoring Compliance Over Time

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 30000,
  assessmentCategories: {
    protocolCompliance: true,
  },
});

// Run assessment multiple times
async function monitorCompliance(context, iterations = 5) {
  const results = [];

  for (let i = 0; i < iterations; i++) {
    console.log(`Iteration ${i + 1}/${iterations}...`);
    const result = await assessor.assess(context);
    results.push({
      timestamp: new Date(),
      score: result.complianceScore,
      status: result.status,
      testCount: assessor.getTestCount(),
    });
  }

  // Analyze trends
  console.log("\nCompliance History:");
  results.forEach((r, i) => {
    console.log(
      `  ${i + 1}. Score: ${r.score}% | Status: ${r.status} | Tests: ${r.testCount}`,
    );
  });

  const avgScore =
    results.reduce((sum, r) => sum + r.score, 0) / results.length;
  console.log(`\nAverage Compliance Score: ${avgScore.toFixed(1)}%`);
}

await monitorCompliance(context);
```

---

## Migration Guide

### From MCPSpecComplianceAssessor

**Old Code (Deprecated):**

```typescript
import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";

const assessor = new MCPSpecComplianceAssessor(config);
const result = await assessor.assess(context);
```

**New Code (Unified):**

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);

// Access legacy fields (still available for backward compatibility)
console.log(result.transportCompliance);
console.log(result.oauthImplementation);
console.log(result.annotationSupport);
console.log(result.streamingSupport);

// OR access new unified structure
console.log(result.protocolChecks);
console.log(result.conformanceChecks);
```

### From ProtocolConformanceAssessor

**Old Code (Deprecated):**

```typescript
import { ProtocolConformanceAssessor } from "@/services/assessment/modules/ProtocolConformanceAssessor";

const assessor = new ProtocolConformanceAssessor(config);
const result = await assessor.assess(context);
```

**New Code (Unified):**

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);

// Access conformance checks
console.log(result.conformanceChecks.errorResponseFormat);
console.log(result.conformanceChecks.contentTypeSupport);
console.log(result.conformanceChecks.initializationHandshake);
```

### Configuration Migration

**Old MCPSpecCompliance Flag:**

```typescript
assessmentCategories: {
  mcpSpecCompliance: true,  // DEPRECATED
}
```

**New Unified Flag:**

```typescript
assessmentCategories: {
  protocolCompliance: true,  // Use this instead
}
```

Both flags are supported during transition, but `protocolCompliance` is preferred.

---

## Testing

### Running Protocol Compliance Tests

```bash
# Run all protocol compliance tests
npm test -- ProtocolComplianceAssessor

# Run specific test suite
npm test -- ProtocolComplianceAssessor.test.ts

# Run with coverage
npm test -- ProtocolComplianceAssessor --coverage

# Watch mode for development
npm test -- ProtocolComplianceAssessor --watch
```

### Test Organization

The test suite is organized in three sections:

1. **MCP Spec Compliance Tests** - Ported from MCPSpecComplianceAssessor
   - Transport compliance detection
   - OAuth implementation validation
   - Annotation support detection
   - Streaming protocol support

2. **Protocol Conformance Tests** - Ported from ProtocolConformanceAssessor
   - Error response format validation
   - Content type support checking
   - Initialization handshake validation

3. **Unified Assessor Tests** - New combined functionality
   - Combines spec + conformance checks
   - Compliance score calculation
   - Test count tracking
   - Recommendation generation

### Example Test Case

```typescript
describe("ProtocolComplianceAssessor", () => {
  it("should assess full protocol compliance", async () => {
    const assessor = new ProtocolComplianceAssessor({
      testTimeout: 10000,
      assessmentCategories: {
        protocolCompliance: true,
      },
    });

    const context = createMockAssessmentContext();
    const result = await assessor.assess(context);

    expect(result).toBeDefined();
    expect(result.complianceScore).toBeGreaterThanOrEqual(0);
    expect(result.complianceScore).toBeLessThanOrEqual(100);
    expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(result.status);
    expect(result.protocolChecks).toBeDefined();
    expect(result.conformanceChecks).toBeDefined();
  });
});
```

---

## Common Issues & Troubleshooting

### Issue: "Schema compliance check failed"

**Cause:** Invalid JSON schema in tool's inputSchema

**Solution:**

```typescript
// Validate schema with AJV manually
import Ajv from "ajv";

const ajv = new Ajv({ allErrors: true });
const schema = tool.inputSchema;
const valid = ajv.validateSchema(schema);

if (!valid) {
  console.error("Schema errors:", ajv.errors);
  // Fix the schema
}
```

### Issue: "Content type validation warnings"

**Cause:** Tool returns unsupported content types

**Valid types:** `text`, `image`, `audio`, `resource`, `resource_link`

**Solution:**

```typescript
// Ensure all content items have valid type
const validTypes = ["text", "image", "audio", "resource", "resource_link"];
response.content.forEach((item) => {
  if (!validTypes.includes(item.type)) {
    console.error(`Invalid content type: ${item.type}`);
  }
});
```

### Issue: "Server info validity check failed"

**Cause:** Missing or malformed serverInfo

**Solution:**

```typescript
// Provide complete server info
const serverInfo = {
  name: "my-server", // Required
  version: "1.0.0", // Required
  metadata: {
    transport: "streamable-http", // Optional but recommended
    protocolVersion: "2025-06", // Optional but recommended
  },
};
```

---

## Related Documentation

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-06)
- [Assessment Module Guide](../ASSESSMENT_MODULE_DEVELOPER_GUIDE.md)
- [Scoring Algorithm](../SCORING_ALGORITHM_GUIDE.md)
- [Test Data Architecture](../TEST_DATA_ARCHITECTURE.md)

---

## Version History

| Version | Date       | Changes                                   |
| ------- | ---------- | ----------------------------------------- |
| 1.25.2  | 2025-01-07 | Unified MCPSpec and ProtocolConformance   |
| 1.25.1  | 2024-12-15 | Profile time estimate corrections         |
| 1.24.0  | 2024-11-01 | Initial MCPSpecComplianceAssessor release |

---

## License

MIT - See LICENSE file in repository
