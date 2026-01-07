# API Documentation Index

**Version**: 1.25.2
**Last Updated**: 2025-01-07

## Overview

This directory contains comprehensive API documentation for the MCP Inspector assessment modules. Start here to understand the available assessment capabilities and how to use them.

---

## ProtocolComplianceAssessor (Unified Module)

The main assessment module for validating MCP protocol compliance.

### Documentation Files

| File                                                                                                           | Purpose                                       | Audience                           |
| -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ---------------------------------- |
| [PROTOCOL_COMPLIANCE_ASSESSOR_API.md](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)                                   | Complete API reference with detailed examples | Developers implementing the module |
| [PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md)                             | Cheat sheet and quick patterns                | Developers using the module        |
| [PROTOCOL_COMPLIANCE_MIGRATION.md](./PROTOCOL_COMPLIANCE_MIGRATION.md)                                         | Migration from deprecated modules             | Teams upgrading from v1.24         |
| [protocol-compliance-assessor.openapi.yaml](./protocol-compliance-assessor.openapi.yaml)                       | OpenAPI 3.0 specification                     | API documentation tools, Postman   |
| [protocol-compliance-assessor.postman_collection.json](./protocol-compliance-assessor.postman_collection.json) | Postman collection for testing                | API testing and validation         |

---

## Quick Start

### For First-Time Users

1. Read [PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md) - 5 minute overview
2. Review usage examples in [PROTOCOL_COMPLIANCE_ASSESSOR_API.md](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#usage-examples)
3. Test with Postman collection: [protocol-compliance-assessor.postman_collection.json](./protocol-compliance-assessor.postman_collection.json)

### For Teams Migrating

1. Start with [PROTOCOL_COMPLIANCE_MIGRATION.md](./PROTOCOL_COMPLIANCE_MIGRATION.md)
2. Use migration checklist to update code
3. Verify with test examples in API reference
4. Run full test suite: `npm test -- ProtocolComplianceAssessor`

### For Integration

1. Review [OpenAPI specification](./protocol-compliance-assessor.openapi.yaml)
2. Use Postman collection for endpoint testing
3. Follow configuration examples in [PROTOCOL_COMPLIANCE_ASSESSOR_API.md](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#configuration)

---

## Module Overview

### ProtocolComplianceAssessor (v1.25.2)

**Purpose**: Unified validation of MCP protocol specification and conformance

**What It Does:**

- 7 protocol specification checks
- 3 protocol conformance checks
- Compliance scoring (0-100%)
- Actionable recommendations

**Key Features:**

- Direct tool invocation testing
- Multi-tool conformance validation
- Capability mismatch detection
- Low-confidence metadata hints

**Configuration:**

```typescript
assessmentCategories: {
  protocolCompliance: true,  // Enable this assessor
}
```

---

## All Checks Reference

### 7 Protocol Specification Checks

1. **JSON-RPC Compliance** - Request/response format validation
2. **Server Info Validity** - Name, version, metadata structure
3. **Schema Compliance** - Tool input schema validation with AJV
4. **Error Response Compliance** - Basic error format checking
5. **Structured Output Support** - outputSchema presence (MCP 2025-06+)
6. **Capabilities Compliance** - Declared vs actual capabilities
7. **Protocol-Level Tests** - General compliance validation

### 3 Protocol Conformance Checks

1. **Error Response Format** - Multi-tool error format validation
2. **Content Type Support** - Valid content types (text/image/audio/resource)
3. **Initialization Handshake** - Server info completeness

---

## Result Interpretation

### Status Meanings

```
PASS         → Score >= 90%, serverInfo valid
FAIL         → Score < 70% OR serverInfo invalid
NEED_MORE_INFO → 70% <= Score < 90%
```

### Score Guide

- **95-100%**: Excellent - Production ready
- **80-94%**: Good - Minor issues
- **70-79%**: Fair - Review recommended
- **Below 70%**: Poor - Critical fixes needed

### Confidence Levels

- **High**: Directly tested/validated
- **Medium**: Partial validation or metadata-based
- **Low**: Metadata-only hints (requires manual verification)

---

## Common Workflows

### Workflow 1: Quick Server Validation

```typescript
import { ProtocolComplianceAssessor } from "@/services/assessment/modules/ProtocolComplianceAssessor";

const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  assessmentCategories: { protocolCompliance: true },
});

const result = await assessor.assess(context);
console.log(`Status: ${result.status} (${result.complianceScore}%)`);
```

**See**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Example 1](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#example-1-complete-assessment-with-full-server-info)

### Workflow 2: Full Compliance Audit

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

**See**: [PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md - Templates](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md#quick-start-templates)

### Workflow 3: Issue Detection

```typescript
Object.entries(result.protocolChecks).forEach(([name, check]) => {
  if (!check.passed) {
    console.log(`Issue: ${name}`);
    console.log(`Evidence: ${check.evidence}`);
    check.warnings?.forEach((w) => console.log(`  - ${w}`));
  }
});

result.recommendations.forEach((rec) => {
  console.log(`Action: ${rec}`);
});
```

**See**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Example 3](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#example-3-detecting-protocol-issues)

---

## Configuration Presets

| Preset         | Timeout | Use Case       | Speed  |
| -------------- | ------- | -------------- | ------ |
| DEFAULT        | 30s     | General use    | Normal |
| DEVELOPER_MODE | 30s     | Full debugging | Slow   |
| REVIEWER_MODE  | 10s     | Fast checks    | Fast   |
| AUDIT_MODE     | 30s     | Pre-submission | Normal |

**See**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Configuration Presets](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#configuration-presets)

---

## Migration Path

### From Old Modules to Unified

| Old Module                  | New Module                 | Status                |
| --------------------------- | -------------------------- | --------------------- |
| MCPSpecComplianceAssessor   | ProtocolComplianceAssessor | Deprecated in v1.25.2 |
| ProtocolConformanceAssessor | ProtocolComplianceAssessor | Deprecated in v1.25.2 |

### Timeline

- **v1.25.2**: Unified assessor available, old modules still work
- **v1.26+**: Deprecation warnings added
- **v2.0.0**: Old modules removed

**Complete Migration Guide**: [PROTOCOL_COMPLIANCE_MIGRATION.md](./PROTOCOL_COMPLIANCE_MIGRATION.md)

---

## Testing

### Run Protocol Compliance Tests

```bash
# All tests
npm test -- ProtocolComplianceAssessor

# With coverage
npm test -- ProtocolComplianceAssessor --coverage

# Watch mode
npm test -- ProtocolComplianceAssessor --watch
```

### Test Organization

1. **MCP Spec Compliance Tests** - Transport, OAuth, Annotations, Streaming
2. **Protocol Conformance Tests** - Error format, Content types, Initialization
3. **Unified Assessor Tests** - Combined functionality, Scoring, Recommendations

**Test File**: `client/src/services/assessment/modules/ProtocolComplianceAssessor.test.ts`

---

## OpenAPI & Postman

### OpenAPI 3.0 Specification

- **File**: [protocol-compliance-assessor.openapi.yaml](./protocol-compliance-assessor.openapi.yaml)
- **Usage**: Import into Swagger UI, ReDoc, or API documentation tools
- **Contains**:
  - Request/response schemas
  - Example payloads (complete server, minimal server, error cases)
  - All endpoints and parameters

### Postman Collection

- **File**: [protocol-compliance-assessor.postman_collection.json](./protocol-compliance-assessor.postman_collection.json)
- **Import to Postman**: File → Import → Select JSON file
- **Contains**:
  - 4 ready-to-run request examples
  - Test assertions for each request
  - Environment variables (baseUrl)
  - Response examples

**Import Instructions**:

1. Open Postman
2. Click "Import" (top-left)
3. Select [protocol-compliance-assessor.postman_collection.json](./protocol-compliance-assessor.postman_collection.json)
4. Set `baseUrl` variable to `http://localhost:3000/api`
5. Run requests

---

## Type Reference

### Main Result Type

```typescript
export interface ProtocolComplianceAssessment {
  protocolVersion: string;
  complianceScore: number; // 0-100
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  explanation: string;
  recommendations: string[];

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

  metadataHints?: MetadataHints;
  testCount?: number;
}
```

**Full Type Reference**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Types](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#types--interfaces)

---

## Error Handling

### Common Issues & Solutions

| Issue                   | Solution                                                           |
| ----------------------- | ------------------------------------------------------------------ |
| Schema validation fails | Validate tool schemas with AJV                                     |
| Content type warnings   | Use only: text, image, audio, resource, resource_link              |
| Server info invalid     | Provide name (required), version (recommended)                     |
| Timeout errors          | Increase testTimeout or set skipBrokenTools: true                  |
| Low confidence          | Metadata-based detection; implement feature to get high confidence |

**Troubleshooting**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Troubleshooting](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#common-issues--troubleshooting)

---

## Code Examples

### Example 1: Basic Assessment

```typescript
const assessor = new ProtocolComplianceAssessor({
  testTimeout: 10000,
  assessmentCategories: { protocolCompliance: true },
});

const result = await assessor.assess(context);
if (result.status === "PASS") {
  console.log("Server is compliant!");
}
```

### Example 2: Get Issues

```typescript
const { protocolChecks, conformanceChecks } = result;

const failedChecks = [
  ...Object.entries(protocolChecks || {}),
  ...Object.entries(conformanceChecks || {}),
]
  .filter(([, check]) => !check.passed)
  .map(([name]) => name);

failedChecks.forEach((check) => console.log(`Fix: ${check}`));
```

### Example 3: Recommendations

```typescript
result.recommendations.forEach((rec, i) => {
  console.log(`${i + 1}. ${rec}`);
});
```

**More Examples**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md - Examples](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#usage-examples)

---

## Related Documentation

- [Assessment Catalog](../ASSESSMENT_CATALOG.md) - All assessment modules
- [Assessment Module Developer Guide](../ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom assessors
- [Scoring Algorithm](../SCORING_ALGORITHM_GUIDE.md) - Module scoring logic
- [Test Data Architecture](../TEST_DATA_ARCHITECTURE.md) - Test data generation
- [BASE_INSPECTOR_GUIDE.md](../BASE_INSPECTOR_GUIDE.md) - Original Inspector documentation

---

## Support & Feedback

### Getting Help

1. **Quick Answers**: [PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md)
2. **Detailed Info**: [PROTOCOL_COMPLIANCE_ASSESSOR_API.md](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)
3. **Migration**: [PROTOCOL_COMPLIANCE_MIGRATION.md](./PROTOCOL_COMPLIANCE_MIGRATION.md)
4. **Testing**: Run Postman collection or tests

### Reporting Issues

- GitHub: [triepod-ai/inspector-assessment/issues](https://github.com/triepod-ai/inspector-assessment/issues)
- Include:
  - MCP server version
  - Test configuration
  - Error message or unexpected result
  - Steps to reproduce

---

## Version Information

| Component                  | Version    | Status   |
| -------------------------- | ---------- | -------- |
| ProtocolComplianceAssessor | 1.25.2     | Stable   |
| MCP Spec Version           | 2025-06-18 | Latest   |
| Node Version               | >=22.7.5   | Required |
| npm Version                | 10.x       | Tested   |

**Last Updated**: 2025-01-07
**Package**: @bryan-thompson/inspector-assessment
**Repository**: https://github.com/triepod-ai/inspector-assessment
**License**: MIT

---

## Table of Contents (By Topic)

### Getting Started

- [Quick Reference](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md) - 5-minute overview
- [API Reference](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#quick-start) - Quick start section

### Deep Dive

- [Full API Reference](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md) - Complete documentation
- [Configuration Guide](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#configuration) - All options
- [Usage Examples](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#usage-examples) - 4 complete examples

### Upgrading

- [Migration Guide](./PROTOCOL_COMPLIANCE_MIGRATION.md) - Step-by-step upgrade
- [Configuration Migration](./PROTOCOL_COMPLIANCE_MIGRATION.md#configuration-migration-paths) - Config updates
- [Result Type Migration](./PROTOCOL_COMPLIANCE_MIGRATION.md#result-type-migration) - Type changes

### Testing & Integration

- [OpenAPI Spec](./protocol-compliance-assessor.openapi.yaml) - API contract
- [Postman Collection](./protocol-compliance-assessor.postman_collection.json) - Ready-to-use tests
- [Testing Guide](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#testing) - Running tests

### Reference

- [Quick Reference](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md) - Cheat sheet
- [Troubleshooting](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md#common-issues--troubleshooting) - Issue solutions
- [API Methods](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md#api-methods) - Method signatures

---

## File Structure

```
docs/api/
├── README.md                                   ← You are here
├── PROTOCOL_COMPLIANCE_ASSESSOR_API.md        ← Full API reference
├── PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md     ← Quick patterns
├── PROTOCOL_COMPLIANCE_MIGRATION.md           ← Upgrade guide
├── protocol-compliance-assessor.openapi.yaml  ← OpenAPI spec
└── protocol-compliance-assessor.postman_collection.json ← Postman tests
```

---

## Quick Navigation

- 📚 [Full Documentation](./PROTOCOL_COMPLIANCE_ASSESSOR_API.md)
- ⚡ [Quick Reference](./PROTOCOL_COMPLIANCE_QUICK_REFERENCE.md)
- 🔄 [Migration Guide](./PROTOCOL_COMPLIANCE_MIGRATION.md)
- 📋 [OpenAPI Spec](./protocol-compliance-assessor.openapi.yaml)
- 🧪 [Postman Collection](./protocol-compliance-assessor.postman_collection.json)
