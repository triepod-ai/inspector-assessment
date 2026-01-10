# Public API Surface

This document defines the stable public API surface for `@bryan-thompson/inspector-assessment`. Exports marked as public follow semantic versioning - breaking changes require a major version bump.

> **Related Documentation:**
>
> - [API Reference](API_REFERENCE.md) - Complete API documentation
> - [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Integration examples
> - [Type Reference](TYPE_REFERENCE.md) - TypeScript type definitions

---

## Stability Guarantee

- **Public APIs** (`@public`): Stable, follow semver. Breaking changes require major version bump.
- **Internal APIs** (`@internal`): Implementation details. May change without notice.
- **Deprecated APIs** (`@deprecated`): Still functional but scheduled for removal. Use recommended replacement.

---

## Quick Start

The fastest way to get started with the assessment engine.

### Basic Usage Pattern

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

// Create an orchestrator instance
const orchestrator = new AssessmentOrchestrator();

// Run assessment on a server
const result = await orchestrator.runFullAssessment({
  serverName: "my-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  transport: {
    type: "http",
    url: "http://localhost:3000/mcp",
  },
});

// Check results
console.log(`Status: ${result.overallStatus}`);
console.log(`Summary: ${result.summary}`);
```

### Using Configuration Presets

If you want different behavior, start with a preset configuration:

```typescript
import {
  AssessmentOrchestrator,
  AUDIT_MODE_CONFIG,
} from "@bryan-thompson/inspector-assessment/config";

// Use a preset configuration
const orchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);

// Rest of code same as above
const result = await orchestrator.runFullAssessment(context);
```

**Available Presets**:

| Preset                         | Use Case           | Speed   | Completeness     |
| ------------------------------ | ------------------ | ------- | ---------------- |
| `DEFAULT_ASSESSMENT_CONFIG`    | General purpose    | Fast    | Balanced         |
| `AUDIT_MODE_CONFIG`            | Thorough audit     | Slower  | Very high        |
| `DEVELOPER_MODE_CONFIG`        | Detailed debugging | Slower  | Very high + logs |
| `REVIEWER_MODE_CONFIG`         | Quick review       | Fastest | Minimal          |
| `CLAUDE_ENHANCED_AUDIT_CONFIG` | Semantic analysis  | Slower  | Highest + Claude |

See [Config (`./config`)](#config-config) for detailed descriptions.

### Next Steps

- **Configuring transports?** See [Transport Configuration](#transport-configuration)
- **Need specific types?** See [Types (`./types`)](#types-types)
- **Handling errors?** See [Error Handling](#error-handling)
- **Building custom modules?** See [Modules (`./modules`)](#modules-modules)

---

## Transport Configuration

Assessment can communicate with MCP servers via different transports. Choose based on your server's deployment model.

### HTTP Transport

Use when your MCP server is accessible via HTTP endpoint.

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

const orchestrator = new AssessmentOrchestrator();

const result = await orchestrator.runFullAssessment({
  serverName: "my-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  transport: {
    type: "http",
    url: "http://localhost:3000/mcp",
    headers: {
      Authorization: "Bearer token-if-required",
      "X-Custom-Header": "value",
    },
    timeout: 30000, // Optional: timeout in ms
  },
});
```

**Common Scenarios**: Remote servers, Docker containers, cloud-hosted MCP services, development servers.

### STDIO Transport

Use when you want to spawn a local subprocess and assess it via stdio.

```typescript
const result = await orchestrator.runFullAssessment({
  serverName: "local-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  transport: {
    type: "stdio",
    command: "python",
    args: ["/path/to/server.py"],
    env: {
      API_KEY: process.env.API_KEY,
      LOG_LEVEL: "debug",
    },
    timeout: 60000,
  },
});
```

**Common Scenarios**: Local development, testing unpublished servers, CI/CD pipelines with source code.

### SSE Transport

Use when your server uses Server-Sent Events for bidirectional communication.

```typescript
const result = await orchestrator.runFullAssessment({
  serverName: "sse-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  transport: {
    type: "sse",
    url: "http://localhost:3000/sse",
    headers: {
      Authorization: "Bearer token-if-required",
    },
    timeout: 30000,
  },
});
```

**Common Scenarios**: Web-based MCP servers, real-time monitoring, event-driven servers.

### Choosing a Transport

| Transport | Speed  | Complexity | Best For               |
| --------- | ------ | ---------- | ---------------------- |
| HTTP      | Fast   | Low        | Remote/cloud servers   |
| STDIO     | Fast   | Medium     | Local dev, CI/CD       |
| SSE       | Medium | High       | Real-time, web servers |

---

## Entry Points

### Root Entry (`.`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment"`

| Export                   | Type      | Description                               |
| ------------------------ | --------- | ----------------------------------------- |
| `AssessmentOrchestrator` | Class     | Main orchestrator for running assessments |
| `AssessmentContext`      | Interface | Context object for assessment input       |
| `MCPResource`            | Interface | MCP resource definition                   |
| `MCPResourceTemplate`    | Interface | MCP resource template definition          |
| `MCPPrompt`              | Interface | MCP prompt definition                     |
| `MCPServerCapabilities`  | Interface | Server capabilities object                |

**Example:**

```typescript
import {
  AssessmentOrchestrator,
  type AssessmentContext,
} from "@bryan-thompson/inspector-assessment";

const orchestrator = new AssessmentOrchestrator();
const result = await orchestrator.runFullAssessment(context);
```

---

### Types (`./types`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/types"`

Core assessment types organized in dependency tiers:

#### Tier 0 - Foundational Types

| Export                         | Type      | Description                            |
| ------------------------------ | --------- | -------------------------------------- |
| `AssessmentStatus`             | Type      | `"PASS" \| "FAIL" \| "NEED_MORE_INFO"` |
| `SecurityRiskLevel`            | Type      | `"LOW" \| "MEDIUM" \| "HIGH"`          |
| `AlignmentStatus`              | Type      | Tool annotation alignment status       |
| `InferenceConfidence`          | Type      | `"high" \| "medium" \| "low"`          |
| `AssessmentCategoryTier`       | Type      | `"core" \| "optional"`                 |
| `AssessmentCategoryMetadata`   | Interface | Module tier and description            |
| `AssessmentModuleName`         | Type      | Union of all module names              |
| `ASSESSMENT_CATEGORY_METADATA` | Constant  | Module metadata mapping                |

#### Tier 1 - Extended Types

| Export                     | Type      | Description                       |
| -------------------------- | --------- | --------------------------------- |
| `JSONSchema7`              | Interface | JSON Schema compatible interface  |
| `MCPContent`               | Interface | MCP content block interface       |
| `ServerInfo`               | Interface | Server information                |
| `PersistenceModel`         | Type      | Server persistence classification |
| `ServerPersistenceContext` | Interface | Persistence context for inference |

---

### Config (`./config`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/config"`

| Export                         | Type      | Description                    |
| ------------------------------ | --------- | ------------------------------ |
| `AssessmentConfiguration`      | Interface | Main configuration interface   |
| `ClaudeCodeConfig`             | Interface | Claude Code integration config |
| `HttpTransportConfig`          | Interface | HTTP transport configuration   |
| `LoggingConfig`                | Interface | Logging configuration          |
| `LogLevel`                     | Type      | Log level type                 |
| `DEFAULT_ASSESSMENT_CONFIG`    | Constant  | Default configuration preset   |
| `REVIEWER_MODE_CONFIG`         | Constant  | Fast review mode preset        |
| `DEVELOPER_MODE_CONFIG`        | Constant  | Comprehensive debug preset     |
| `AUDIT_MODE_CONFIG`            | Constant  | MCP Directory audit preset     |
| `CLAUDE_ENHANCED_AUDIT_CONFIG` | Constant  | Claude-enhanced audit preset   |
| `DEFAULT_LOGGING_CONFIG`       | Constant  | Default logging configuration  |

---

### Results (`./results`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/results"`

Assessment result types (same as `./types` resultTypes):

| Export                         | Type      | Description                        |
| ------------------------------ | --------- | ---------------------------------- |
| `MCPDirectoryAssessment`       | Interface | Complete assessment result         |
| `FunctionalityAssessment`      | Interface | Functionality module result        |
| `SecurityAssessment`           | Interface | Security module result             |
| `DocumentationAssessment`      | Interface | Documentation module result        |
| `ErrorHandlingAssessment`      | Interface | Error handling module result       |
| `UsabilityAssessment`          | Interface | Usability module result            |
| `AUPComplianceAssessment`      | Interface | AUP compliance result              |
| `ToolAnnotationAssessment`     | Interface | Tool annotation result             |
| `ProtocolComplianceAssessment` | Interface | Protocol compliance result         |
| `TemporalAssessment`           | Interface | Temporal/rug pull detection result |
| `ResourceAssessment`           | Interface | Resource security result           |
| `PromptAssessment`             | Interface | Prompt security result             |
| `CrossCapabilityAssessment`    | Interface | Cross-capability security result   |

---

### Progress (`./progress`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/progress"`

Real-time progress event types for JSONL streaming:

| Export                                | Type      | Description                       |
| ------------------------------------- | --------- | --------------------------------- |
| `ProgressCallback`                    | Interface | Callback for progress events      |
| `ProgressEvent`                       | Type      | Union of all progress event types |
| `ModuleStartedProgress`               | Interface | Module execution started          |
| `TestBatchProgress`                   | Interface | Test batch completed              |
| `ModuleCompleteProgress`              | Interface | Module execution completed        |
| `VulnerabilityFoundProgress`          | Interface | Security vulnerability detected   |
| `AnnotationMissingProgress`           | Interface | Tool missing annotations          |
| `AnnotationMisalignedProgress`        | Interface | Annotation mismatch detected      |
| `AnnotationReviewRecommendedProgress` | Interface | Manual review recommended         |
| `AnnotationPoisonedProgress`          | Interface | Description poisoning detected    |
| `AnnotationAlignedProgress`           | Interface | Annotation correctly aligned      |

---

### Modules (`./modules`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/modules"`

Assessment module classes for extensibility:

#### Base Class

| Export         | Type  | Description                  |
| -------------- | ----- | ---------------------------- |
| `BaseAssessor` | Class | Base class for all assessors |

#### Tier 1 - Core Security (Always Run)

| Export                       | Type  | Description                          |
| ---------------------------- | ----- | ------------------------------------ |
| `FunctionalityAssessor`      | Class | Tool functionality validation        |
| `SecurityAssessor`           | Class | Security vulnerability detection     |
| `TemporalAssessor`           | Class | Rug pull/temporal mutation detection |
| `ErrorHandlingAssessor`      | Class | Error handling compliance            |
| `ProtocolComplianceAssessor` | Class | MCP protocol compliance              |
| `AUPComplianceAssessor`      | Class | Acceptable use policy compliance     |

#### Tier 2 - Compliance

| Export                        | Type  | Description                  |
| ----------------------------- | ----- | ---------------------------- |
| `ToolAnnotationAssessor`      | Class | Tool annotation validation   |
| `ProhibitedLibrariesAssessor` | Class | Prohibited library detection |
| `ManifestValidationAssessor`  | Class | MCPB manifest validation     |
| `AuthenticationAssessor`      | Class | OAuth/auth evaluation        |

#### Tier 3 - Capability-Based

| Export                            | Type  | Description                  |
| --------------------------------- | ----- | ---------------------------- |
| `ResourceAssessor`                | Class | Resource security assessment |
| `PromptAssessor`                  | Class | Prompt security assessment   |
| `CrossCapabilitySecurityAssessor` | Class | Cross-capability security    |

#### Tier 4 - Extended

| Export                        | Type  | Description            |
| ----------------------------- | ----- | ---------------------- |
| `DeveloperExperienceAssessor` | Class | Documentation quality  |
| `PortabilityAssessor`         | Class | Portability checks     |
| `ExternalAPIScannerAssessor`  | Class | External API detection |

#### Deprecated (Backward Compatibility)

| Export                        | Status        | Replacement                   |
| ----------------------------- | ------------- | ----------------------------- |
| `DocumentationAssessor`       | `@deprecated` | `DeveloperExperienceAssessor` |
| `UsabilityAssessor`           | `@deprecated` | `DeveloperExperienceAssessor` |
| `MCPSpecComplianceAssessor`   | `@deprecated` | `ProtocolComplianceAssessor`  |
| `ProtocolConformanceAssessor` | `@deprecated` | `ProtocolComplianceAssessor`  |

---

### Security (`./security`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/security"`

Security testing utilities:

| Export                     | Type  | Description                                |
| -------------------------- | ----- | ------------------------------------------ |
| `SecurityPayloadTester`    | Class | Test tool responses to attack payloads     |
| `SecurityPayloadGenerator` | Class | Generate security test payloads            |
| `SecurityResponseAnalyzer` | Class | Analyze tool responses for vulnerabilities |
| `CrossToolStateTester`     | Class | Test cross-tool state manipulation         |
| `ChainExecutionTester`     | Class | Test tool chain execution attacks          |

---

### Annotations (`./annotations`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/annotations"`

Behavior inference and annotation utilities:

| Export                           | Type     | Description                          |
| -------------------------------- | -------- | ------------------------------------ |
| `inferBehavior`                  | Function | Infer tool behavior from description |
| `inferBehaviorEnhanced`          | Function | Enhanced behavior inference          |
| `detectArchitecture`             | Function | Detect server architecture patterns  |
| `hasDatabaseToolPatterns`        | Function | Check for database tool patterns     |
| `analyzeDescription`             | Function | Analyze tool description             |
| `analyzeInputSchema`             | Function | Analyze tool input schema            |
| `analyzeOutputSchema`            | Function | Analyze tool output schema           |
| `scanDescriptionForPoisoning`    | Function | Scan for description poisoning       |
| `DESCRIPTION_POISONING_PATTERNS` | Constant | Poisoning detection patterns         |

---

### Performance (`./performance`)

**Import:** `import { ... } from "@bryan-thompson/inspector-assessment/performance"`

Performance configuration:

| Export                       | Type      | Description                       |
| ---------------------------- | --------- | --------------------------------- |
| `PerformanceConfig`          | Interface | Performance tuning options        |
| `PERFORMANCE_PRESETS`        | Constant  | Performance preset configurations |
| `DEFAULT_PERFORMANCE_CONFIG` | Constant  | Default performance config        |
| `loadPerformanceConfig`      | Function  | Load config from file             |
| `validatePerformanceConfig`  | Function  | Validate config object            |
| `mergeWithDefaults`          | Function  | Merge with default config         |

---

## Internal APIs (Not Stable)

The following modules are internal implementation details and may change without notice:

| Module                | Location                   | Purpose                                  |
| --------------------- | -------------------------- | ---------------------------------------- |
| `orchestratorHelpers` | `services/assessment/`     | JSONL event emission, status calculation |
| `TestDataGenerator`   | `services/assessment/`     | Test parameter generation                |
| `ResponseValidator`   | `services/assessment/`     | Response validation logic                |
| `TestScenarioEngine`  | `services/assessment/`     | Multi-scenario testing                   |
| `EventBatcher`        | `services/assessment/lib/` | Event batching for progress              |
| `claudeCodeBridge`    | `services/assessment/lib/` | Claude Code CLI integration              |
| `errors`              | `services/assessment/lib/` | Error handling utilities                 |
| `timeoutUtils`        | `services/assessment/lib/` | Timeout management                       |
| CLI lib modules       | `cli/src/lib/`             | CLI internal utilities                   |

**Warning:** Do not import from these modules directly. Use the public entry points instead.

---

## Migration Notes

### Deprecated Exports

The following exports are deprecated and will be removed in v2.0.0:

| Deprecated                    | Replacement                   | Migration Guide                                |
| ----------------------------- | ----------------------------- | ---------------------------------------------- |
| `DocumentationAssessor`       | `DeveloperExperienceAssessor` | Use `assessmentCategories.developerExperience` |
| `UsabilityAssessor`           | `DeveloperExperienceAssessor` | Use `assessmentCategories.developerExperience` |
| `MCPSpecComplianceAssessor`   | `ProtocolComplianceAssessor`  | Use `assessmentCategories.protocolCompliance`  |
| `ProtocolConformanceAssessor` | `ProtocolComplianceAssessor`  | Use `assessmentCategories.protocolCompliance`  |
| `assess()` method             | `runFullAssessment()`         | Pass `AssessmentContext` object                |

### Configuration Changes

The following configuration flags are deprecated:

| Deprecated Flag                            | Replacement                               |
| ------------------------------------------ | ----------------------------------------- |
| `assessmentCategories.mcpSpecCompliance`   | `assessmentCategories.protocolCompliance` |
| `assessmentCategories.protocolConformance` | `assessmentCategories.protocolCompliance` |

---

## Migration Checklist: Preparing for v2.0.0

Target Release: **Q2 2026** (estimated June 2026)

Use this checklist to systematically update your code for v2.0.0 compatibility.

### Step 1: Find and Replace Deprecated Imports

Run these commands in your codebase:

```bash
# Find deprecated assessor imports
grep -r "DocumentationAssessor\|UsabilityAssessor" src/
grep -r "MCPSpecComplianceAssessor\|ProtocolConformanceAssessor" src/
```

- [ ] Replace `DocumentationAssessor` → `DeveloperExperienceAssessor`
- [ ] Replace `UsabilityAssessor` → `DeveloperExperienceAssessor`
- [ ] Replace `MCPSpecComplianceAssessor` → `ProtocolComplianceAssessor`
- [ ] Replace `ProtocolConformanceAssessor` → `ProtocolComplianceAssessor`

### Step 2: Update Legacy Method Calls

```typescript
// OLD (deprecated)
const results = await orchestrator.assess(
  serverName,
  tools,
  callTool,
  serverInfo,
  readme,
);

// NEW (required in v2.0.0)
const results = await orchestrator.runFullAssessment({
  serverName,
  tools,
  callTool,
  serverInfo,
  readmeContent: readme,
  config: orchestrator.getConfig(),
});
```

- [ ] Search for `.assess(` calls
- [ ] Replace with `.runFullAssessment()` using `AssessmentContext`

### Step 3: Update Configuration Flags

```typescript
// OLD
{
  assessmentCategories: {
    mcpSpecCompliance: true,
    protocolConformance: false,
  }
}

// NEW
{
  assessmentCategories: {
    protocolCompliance: true,  // Unified flag
  }
}
```

- [ ] Replace `assessmentCategories.mcpSpecCompliance` → `assessmentCategories.protocolCompliance`
- [ ] Replace `assessmentCategories.protocolConformance` → `assessmentCategories.protocolCompliance`

### Step 4: Enable Deprecation Warnings

```bash
# Run with deprecation warnings enabled
LOG_LEVEL=warn npm test
```

- [ ] Run tests with `LOG_LEVEL=warn`
- [ ] Fix any remaining deprecated API usage

### Deprecation Timeline

| Version   | Date         | Status      | Action                      |
| --------- | ------------ | ----------- | --------------------------- |
| 1.25.0    | Oct 2025     | Deprecated  | Warnings introduced         |
| 1.30.0    | Feb 2026     | Last chance | Final opportunity to update |
| **2.0.0** | **Jun 2026** | **REMOVED** | **Old APIs deleted**        |

For detailed migration examples, see [DEPRECATION_MIGRATION_EXAMPLES.md](DEPRECATION_MIGRATION_EXAMPLES.md).

---

## Version History

### 1.29.x

- Added `schemaVersion` to all JSONL events
- Added `BaseEvent` interface for event typing

### 1.27.x

- Added `configVersion` field to AssessmentConfiguration
- Schema version now tracked for migration support

### 1.25.x

- Unified `ProtocolComplianceAssessor` (merged MCPSpecCompliance + ProtocolConformance)
- Deprecated `DocumentationAssessor`, `UsabilityAssessor`, `MCPSpecComplianceAssessor`, `ProtocolConformanceAssessor`

---

## See Also

- [API Reference](API_REFERENCE.md) - Complete API documentation
- [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Step-by-step integration
- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Real-time progress events
- [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom modules
