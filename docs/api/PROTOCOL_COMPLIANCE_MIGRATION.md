# Protocol Compliance Assessor - Migration Guide

**Version**: 1.25.2
**Date**: 2025-01-07

## Overview

The `ProtocolComplianceAssessor` unifies two separate assessment modules into a single, coherent API:

- **MCPSpecComplianceAssessor** (deprecated) → Specification-focused checks
- **ProtocolConformanceAssessor** (deprecated) → Conformance-focused checks

This guide walks you through migrating from the deprecated modules to the unified assessor.

## Quick Reference Table

| Aspect      | Old                                                          | New                            |
| ----------- | ------------------------------------------------------------ | ------------------------------ |
| Module      | `MCPSpecComplianceAssessor` or `ProtocolConformanceAssessor` | `ProtocolComplianceAssessor`   |
| Config Flag | `mcpSpecCompliance` or `protocolConformance`                 | `protocolCompliance`           |
| Result Type | `MCPSpecComplianceAssessment` or `ProtocolConformanceResult` | `ProtocolComplianceAssessment` |
| Deprecation | Removed in v2.0.0                                            | Stable, recommended            |

---

## Phase 1: MCPSpecComplianceAssessor → ProtocolComplianceAssessor

### Old Code Pattern

```typescript
import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";

const assessor = new MCPSpecComplianceAssessor(config);
const result = await assessor.assess(context);

// Access results
console.log(result.transportCompliance);
console.log(result.oauthImplementation);
console.log(result.annotationSupport);
console.log(result.streamingSupport);
```

### Migration Steps

#### Step 1: Update Import

```diff
- import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";
+ import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

- const assessor = new MCPSpecComplianceAssessor(config);
+ const assessor = new ProtocolComplianceAssessor(config);
```

#### Step 2: Update Configuration Flag

```diff
  const config = {
    testTimeout: 30000,
    assessmentCategories: {
      functionality: true,
      security: true,
-     mcpSpecCompliance: true,
+     protocolCompliance: true,
    },
  };
```

#### Step 3: Update Result Access (Backward Compatible)

The new assessor maintains backward compatibility. Your existing code will still work:

```typescript
const result = await assessor.assess(context);

// Old patterns (still work!)
console.log(result.transportCompliance); // Still available
console.log(result.oauthImplementation); // Still available
console.log(result.annotationSupport); // Still available
console.log(result.streamingSupport); // Still available

// New unified patterns (preferred)
console.log(result.protocolChecks); // New: 7 spec checks
console.log(result.conformanceChecks); // New: 3 conformance checks
console.log(result.complianceScore); // New: 0-100 score
console.log(result.status); // New: PASS/FAIL/NEED_MORE_INFO
```

### Complete Migration Example

**Before:**

```typescript
import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessment/configTypes";

const config = {
  ...DEFAULT_ASSESSMENT_CONFIG,
  assessmentCategories: {
    ...DEFAULT_ASSESSMENT_CONFIG.assessmentCategories,
    mcpSpecCompliance: true,
  },
};

const assessor = new MCPSpecComplianceAssessor(config);
const result = await assessor.assess(context);

if (result.transportCompliance.supportsStreamableHTTP) {
  console.log("Server supports streamable HTTP");
}

if (result.oauthImplementation?.supportsOAuth) {
  console.log("Server implements OAuth");
}
```

**After:**

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessment/configTypes";

const config = {
  ...DEFAULT_ASSESSMENT_CONFIG,
  assessmentCategories: {
    ...DEFAULT_ASSESSMENT_CONFIG.assessmentCategories,
    protocolCompliance: true,
  },
};

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);

// New unified approach
if (result.status === "PASS") {
  console.log("Protocol compliance verified");
  console.log(`Compliance score: ${result.complianceScore}%`);
}

// Or access granular checks
if (result.metadataHints?.transportHints.supportsHTTP) {
  console.log("Server supports HTTP transport");
}

if (result.metadataHints?.oauthHints?.supportsOAuth) {
  console.log("Server implements OAuth");
}
```

---

## Phase 2: ProtocolConformanceAssessor → ProtocolComplianceAssessor

### Old Code Pattern

```typescript
import { ProtocolConformanceAssessor } from "@/services/assessment/modules/ProtocolConformanceAssessor";

const assessor = new ProtocolConformanceAssessor(config);
const result = await assessor.assess(context);

// Access results
console.log(result.errorResponseFormatCheck);
console.log(result.contentTypeSupportCheck);
console.log(result.initializationHandshakeCheck);
```

### Migration Steps

#### Step 1: Update Import

```diff
- import { ProtocolConformanceAssessor } from "@/services/assessment/modules/ProtocolConformanceAssessor";
+ import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

- const assessor = new ProtocolConformanceAssessor(config);
+ const assessor = new ProtocolComplianceAssessor(config);
```

#### Step 2: Update Configuration Flag

```diff
  const config = {
    testTimeout: 30000,
    assessmentCategories: {
      functionality: true,
      security: true,
-     protocolConformance: true,
+     protocolCompliance: true,
    },
  };
```

#### Step 3: Update Result Access

```typescript
const result = await assessor.assess(context);

// Old patterns (need updating)
// result.errorResponseFormatCheck
// result.contentTypeSupportCheck
// result.initializationHandshakeCheck

// New unified patterns
console.log(result.conformanceChecks.errorResponseFormat);
console.log(result.conformanceChecks.contentTypeSupport);
console.log(result.conformanceChecks.initializationHandshake);
```

### Complete Migration Example

**Before:**

```typescript
import { ProtocolConformanceAssessor } from "@/services/assessment/modules/ProtocolConformanceAssessor";

const assessor = new ProtocolConformanceAssessor(config);
const result = await assessor.assess(context);

if (result.errorResponseFormatCheck.passed) {
  console.log("Error response format is valid");
}

if (result.contentTypeSupportCheck.passed) {
  console.log("Content types are valid");
}

if (result.initializationHandshakeCheck.passed) {
  console.log("Initialization handshake is valid");
}
```

**After:**

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

const assessor = new ProtocolComplianceAssessor(config);
const result = await assessor.assess(context);

// New unified approach with conformance checks
if (result.conformanceChecks?.errorResponseFormat.passed) {
  console.log("Error response format is valid");
  console.log(
    `Evidence: ${result.conformanceChecks.errorResponseFormat.evidence}`,
  );
}

if (result.conformanceChecks?.contentTypeSupport.passed) {
  console.log("Content types are valid");
}

if (result.conformanceChecks?.initializationHandshake.passed) {
  console.log("Initialization handshake is valid");
}

// Or use the unified score/status
if (result.status === "PASS") {
  console.log(`All checks passed: ${result.complianceScore}%`);
}
```

---

## Configuration Migration Paths

### Path 1: Quick Migration (Minimal Changes)

For teams wanting minimal code changes, both old flags work during transition:

```typescript
const config = {
  testTimeout: 30000,
  assessmentCategories: {
    functionality: true,
    // Both old flags still work (will enable new unified assessor)
    mcpSpecCompliance: true, // Maps to protocolCompliance
    protocolConformance: true, // Maps to protocolCompliance
    protocolCompliance: true, // New unified flag (preferred)
  },
};
```

### Path 2: Full Migration (Recommended)

Update configuration to use new unified flag:

```typescript
const config = {
  testTimeout: 30000,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    // Remove deprecated flags
    // mcpSpecCompliance: false,     // Remove this
    // protocolConformance: false,   // Remove this
    // Use new unified flag
    protocolCompliance: true, // Use this
  },
};
```

### Path 3: Gradual Migration (For Large Codebases)

Stage 1: Accept both old and new flags

```typescript
// Year 1 - Both patterns work
const config = {
  assessmentCategories: {
    mcpSpecCompliance: true, // Still works
    protocolCompliance: true, // Also works
  },
};
```

Stage 2: Deprecation warnings in v1.26+

```typescript
// v1.26 - Deprecation warnings
// "Warning: mcpSpecCompliance is deprecated. Use protocolCompliance instead."
```

Stage 3: Removal in v2.0.0

```typescript
// v2.0.0 - Only new flag supported
const config = {
  assessmentCategories: {
    protocolCompliance: true, // Only option
  },
};
```

---

## Result Type Migration

### From MCPSpecComplianceAssessment

**Old Result Structure:**

```typescript
interface MCPSpecComplianceAssessment {
  transportCompliance: TransportComplianceMetrics;
  oauthImplementation?: OAuthComplianceMetrics;
  annotationSupport: AnnotationSupportMetrics;
  streamingSupport: StreamingSupportMetrics;
  status: AssessmentStatus;
  // Limited score information
}
```

**New Result Structure (Superset):**

```typescript
interface ProtocolComplianceAssessment extends MCPSpecComplianceAssessment {
  // New unified structure
  protocolVersion: string;
  protocolChecks: ProtocolChecks; // 7 detailed checks
  conformanceChecks: ConformanceChecks; // 3 detailed checks
  metadataHints: MetadataHints; // Low-confidence hints
  complianceScore: number; // 0-100
  explanation: string;
  recommendations: string[];

  // Legacy fields (still present for backward compatibility)
  transportCompliance: TransportComplianceMetrics;
  oauthImplementation?: OAuthComplianceMetrics;
  annotationSupport: AnnotationSupportMetrics;
  streamingSupport: StreamingSupportMetrics;
}
```

### From ProtocolConformanceResult

**Old Result Structure:**

```typescript
interface ProtocolConformanceResult {
  errorResponseFormatCheck: ProtocolCheck;
  contentTypeSupportCheck: ProtocolCheck;
  initializationHandshakeCheck: ProtocolCheck;
  status: AssessmentStatus;
  // Limited integration
}
```

**New Result Structure (Integrated):**

```typescript
interface ProtocolComplianceAssessment {
  // Contains conformance checks
  conformanceChecks: {
    errorResponseFormat: ProtocolCheck;
    contentTypeSupport: ProtocolCheck;
    initializationHandshake: ProtocolCheck;
  };

  // Plus 7 protocol specification checks
  protocolChecks: ProtocolChecks;

  // Plus unified scoring
  complianceScore: number;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

---

## Breaking Changes & Deprecations

### Deprecated Modules

```typescript
// DEPRECATED - Will be removed in v2.0.0
import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";
import { ProtocolConformanceAssessor } from "@/services/assessment/modules/ProtocolConformanceAssessor";

// RECOMMENDED - Use this instead
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";
```

### Deprecated Configuration Flags

```typescript
assessmentCategories: {
  // DEPRECATED - Will be removed in v2.0.0
  mcpSpecCompliance: true,      // Use protocolCompliance instead
  protocolConformance: true,    // Use protocolCompliance instead

  // RECOMMENDED - Use this
  protocolCompliance: true,
}
```

### Backward Compatibility

**Timeline:**

- **v1.25.2+**: Old modules still work, new unified module available
- **v1.26+**: Deprecation warnings when using old modules
- **v2.0.0**: Old modules removed, only unified module supported

**Backward Compatible:**

```typescript
// This still works in v1.25.2+
const result = await assessor.assess(context);
console.log(result.transportCompliance); // Old fields still exist
console.log(result.oauthImplementation); // Old fields still exist

// New preferred way
console.log(result.protocolChecks); // New structure
console.log(result.conformanceChecks); // New structure
```

---

## Testing Migration

### Old Test Pattern

```typescript
describe("MCPSpecComplianceAssessor", () => {
  it("should detect transport compliance", async () => {
    const assessor = new MCPSpecComplianceAssessor(config);
    const result = await assessor.assess(context);

    expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);
  });
});
```

### New Test Pattern

```typescript
describe("ProtocolComplianceAssessor", () => {
  it("should detect transport compliance", async () => {
    const assessor = new ProtocolComplianceAssessor(config);
    const result = await assessor.assess(context);

    // New way (preferred)
    expect(result.status).toBe("PASS");
    expect(result.complianceScore).toBeGreaterThanOrEqual(90);

    // Old way (still works)
    expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);

    // Granular checks
    expect(result.metadataHints?.transportHints.supportsHTTP).toBe(true);
  });
});
```

---

## Common Migration Issues

### Issue 1: Import Path Not Found

**Symptom:**

```
Cannot find module "@/services/assessment/modules/MCPSpecComplianceAssessor"
```

**Solution:**

```typescript
// Old path (removed)
import { MCPSpecComplianceAssessor } from "@/services/assessment/modules/MCPSpecComplianceAssessor";

// New path
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";
```

### Issue 2: Result Field Not Found

**Symptom:**

```
Cannot read property 'transportCompliance' of undefined
```

**Solution:**
Check that `protocolCompliance` flag is enabled in config:

```typescript
const config = {
  assessmentCategories: {
    protocolCompliance: true, // Must be enabled
  },
};
```

### Issue 3: Type Mismatch

**Symptom:**

```
Type 'ProtocolComplianceAssessment' is not assignable to type 'MCPSpecComplianceAssessment'
```

**Solution:**
Update type annotations:

```typescript
// Old
let result: MCPSpecComplianceAssessment;

// New
let result: ProtocolComplianceAssessment;
```

### Issue 4: Missing Conformance Checks

**Symptom:**

```
Property 'conformanceChecks' does not exist
```

**Solution:**
Check optional chaining in type-safe code:

```typescript
// Safe
if (result.conformanceChecks?.errorResponseFormat.passed) {
  // conformanceChecks is optional on old result types
}

// Or ensure assessor is new unified version
const assessor = new ProtocolComplianceAssessor(config);
// Result will always have conformanceChecks
```

---

## Validation Checklist

Use this checklist when migrating:

- [ ] Updated all imports from old modules to `ProtocolComplianceAssessor`
- [ ] Updated configuration flags from `mcpSpecCompliance`/`protocolConformance` to `protocolCompliance`
- [ ] Updated result access patterns to use `protocolChecks` and `conformanceChecks`
- [ ] Updated test assertions to match new result structure
- [ ] Verified backward compatibility with old code paths
- [ ] Tested with sample MCP servers
- [ ] Updated documentation and comments
- [ ] Ran full test suite: `npm test`
- [ ] Verified no import errors: `npm run build`

---

## Performance Considerations

The unified assessor performs more checks than either old module individually:

| Aspect        | MCPSpecCompliance | ProtocolConformance | Unified       |
| ------------- | ----------------- | ------------------- | ------------- |
| Checks        | 7 specification   | 3 conformance       | 10 total      |
| Avg Time      | ~2-3 seconds      | ~1-2 seconds        | ~3-4 seconds  |
| Network Calls | ~3-5 per tool     | ~3-5 per tool       | ~6-8 per tool |

**Optimization Tips:**

- Use `skipBrokenTools: true` to skip non-responsive tools
- Reduce `testTimeout` for faster feedback (minimum 5000ms)
- Use `selectedToolsForTesting` to test only critical tools

---

## Support & Resources

### Documentation

- [API Reference](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)
- [OpenAPI Specification](./protocol-compliance-assessor.openapi.yaml)
- [Configuration Reference](../lib/assessment/configTypes.ts)

### Testing

- Test suite: `npm test -- ProtocolComplianceAssessor`
- Test file: `client/src/services/assessment/modules/ProtocolComplianceAssessor.test.ts`

### GitHub

- [Upgrade Issue](https://github.com/triepod-ai/inspector-assessment/issues/25)
- [Project Status](../../PROJECT_STATUS.md)

---

## Migration Timeline

- **Now (v1.25.2)**: Unified assessor available, old modules still work
- **Q1 2025**: Deprecation warnings added to old modules
- **Q2 2025**: v1.26.0 with updated documentation
- **Q4 2025**: v2.0.0 with old modules removed

---

## Questions?

For migration questions:

1. Check [API Reference](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)
2. Review [test examples](../modules/ProtocolComplianceAssessor.test.ts)
3. See [usage examples in this guide](#usage-examples)
4. File an issue on GitHub
