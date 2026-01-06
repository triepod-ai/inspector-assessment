# API Reference

Complete API documentation for `@bryan-thompson/inspector-assessment` programmatic usage.

> **Related Documentation:**
>
> - [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Step-by-step integration examples
> - [Type Reference](TYPE_REFERENCE.md) - Complete TypeScript type definitions
> - [Integration Guide](INTEGRATION_GUIDE.md) - Practical patterns for multi-server, CI/CD
> - [Assessment Types Import Guide](ASSESSMENT_TYPES_IMPORT_GUIDE.md) - Modular imports and tree-shaking
> - [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Real-time progress events (13 types)

---

## Table of Contents

- [Overview](#overview)
- [AssessmentOrchestrator Class](#assessmentorchestrator-class)
  - [Constructor](#constructor)
  - [runFullAssessment()](#runfullassessment)
  - [assess() (Legacy)](#assess-legacy)
  - [Configuration Methods](#configuration-methods)
  - [Claude Code Integration](#claude-code-integration)
- [AssessmentContext Interface](#assessmentcontext-interface)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
  - [Transport Configuration](#transport-configuration)
- [AssessmentConfiguration Interface](#assessmentconfiguration-interface)
  - [Core Options](#core-options)
  - [Testing Options](#testing-options)
  - [Module Selection](#module-selection)
  - [Logging Configuration](#logging-configuration)
- [Configuration Presets](#configuration-presets)
- [MCPDirectoryAssessment Result](#mcpdirectoryassessment-result)
  - [Core Assessment Results](#core-assessment-results)
  - [Extended Assessment Results](#extended-assessment-results)
  - [Overall Assessment](#overall-assessment)
- [Error Handling](#error-handling)
- [JSONL Events Stream](#jsonl-events-stream)
- [Version Compatibility](#version-compatibility)

---

## Overview

The `@bryan-thompson/inspector-assessment` package provides programmatic access to MCP server assessment capabilities. The primary entry point is the `AssessmentOrchestrator` class.

```typescript
// Main entry point - AssessmentOrchestrator class AND AssessmentContext type
import {
  AssessmentOrchestrator,
  type AssessmentContext,
} from "@bryan-thompson/inspector-assessment";

// Other types from the types entry point
import type { MCPDirectoryAssessment } from "@bryan-thompson/inspector-assessment/types";

// Configuration presets from config entry point
import { AUDIT_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

**API Stability**: Public APIs documented here are stable. Breaking changes follow semver (major version bumps).

---

## AssessmentOrchestrator Class

The main class for running MCP server assessments.

### Constructor

```typescript
constructor(config?: Partial<AssessmentConfiguration>)
```

Creates a new AssessmentOrchestrator instance with the specified configuration.

**Parameters:**

| Parameter | Type                               | Default                     | Description                              |
| --------- | ---------------------------------- | --------------------------- | ---------------------------------------- |
| `config`  | `Partial<AssessmentConfiguration>` | `DEFAULT_ASSESSMENT_CONFIG` | Configuration options for the assessment |

**Example:**

```typescript
// Default configuration
const orchestrator = new AssessmentOrchestrator();

// Custom configuration
const orchestrator = new AssessmentOrchestrator({
  testTimeout: 60000,
  parallelTesting: true,
  enableExtendedAssessment: true,
});

// Using a preset
import { AUDIT_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
const orchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);
```

**Behavior:**

- Merges provided config with `DEFAULT_ASSESSMENT_CONFIG`
- Initializes Claude Code Bridge if `claudeCode.enabled` is true
- Creates assessor instances based on `assessmentCategories` configuration
- Skipped modules (via `assessmentCategories`) do not instantiate assessors

---

### runFullAssessment()

```typescript
async runFullAssessment(context: AssessmentContext): Promise<MCPDirectoryAssessment>
```

Runs a complete assessment on an MCP server.

**Parameters:**

| Parameter | Type                | Required | Description                           |
| --------- | ------------------- | -------- | ------------------------------------- |
| `context` | `AssessmentContext` | Yes      | Server connection and metadata config |

**Returns:** `Promise<MCPDirectoryAssessment>` - Complete assessment results

**Example:**

```typescript
const context: AssessmentContext = {
  serverName: "my-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  config: orchestrator.getConfig(),
};

const results = await orchestrator.runFullAssessment(context);

console.log(`Overall status: ${results.overallStatus}`);
console.log(`Tests run: ${results.totalTestsRun}`);
```

**Execution Order:**

1. **Phase 0 (Temporal)**: Temporal assessment runs first to capture clean baseline
2. **Phase 1 (Core)**: Core modules execute (parallel or sequential based on config)
3. **Phase 2 (Extended)**: Extended modules execute if enabled
4. **Phase 3 (Aggregation)**: Temporal findings integrated into security results
5. **Phase 4 (Finalization)**: Overall status, summary, and recommendations generated

**JSONL Events:**

During execution, progress events are emitted to stderr:

```jsonl
{"event":"module_started","module":"functionality","estimatedTests":50,"toolCount":5}
{"event":"module_complete","module":"functionality","status":"PASS","score":95,"duration":1234}
```

---

### assess() (Legacy)

```typescript
async assess(
  serverName: string,
  tools: Tool[],
  callTool: (name: string, params: Record<string, unknown>) => Promise<CompatibilityCallToolResult>,
  serverInfo?: unknown,
  readmeContent?: string,
  packageJson?: unknown
): Promise<MCPDirectoryAssessment>
```

**Deprecated**: Legacy method for backward compatibility. Use `runFullAssessment()` instead.

**Migration:**

```typescript
// Legacy (deprecated)
const results = await orchestrator.assess(
  serverName,
  tools,
  callTool,
  serverInfo,
  readme,
);

// Modern (recommended)
const results = await orchestrator.runFullAssessment({
  serverName,
  tools,
  callTool,
  serverInfo,
  readmeContent: readme,
  config: orchestrator.getConfig(),
});
```

---

### Configuration Methods

#### getConfig()

```typescript
getConfig(): AssessmentConfiguration
```

Returns the current assessment configuration.

**Example:**

```typescript
const config = orchestrator.getConfig();
console.log(`Test timeout: ${config.testTimeout}ms`);
```

---

#### updateConfig()

```typescript
updateConfig(config: Partial<AssessmentConfiguration>): void
```

Updates the assessment configuration. Changes apply to subsequent assessments.

**Example:**

```typescript
orchestrator.updateConfig({
  parallelTesting: true,
  maxParallelTests: 10,
});
```

---

### Claude Code Integration

#### enableClaudeCode()

```typescript
enableClaudeCode(config?: Partial<ClaudeCodeBridgeConfig>): void
```

Enables Claude Code integration programmatically after construction.

**Parameters:**

| Parameter | Type                              | Required | Description                 |
| --------- | --------------------------------- | -------- | --------------------------- |
| `config`  | `Partial<ClaudeCodeBridgeConfig>` | No       | Claude integration settings |

**Example:**

```typescript
orchestrator.enableClaudeCode({
  features: {
    intelligentTestGeneration: true,
    aupSemanticAnalysis: true,
    annotationInference: false,
    documentationQuality: true,
  },
  timeout: 90000,
});
```

---

#### isClaudeEnabled()

```typescript
isClaudeEnabled(): boolean
```

Returns whether Claude Code integration is enabled and available.

---

#### getClaudeBridge()

```typescript
getClaudeBridge(): ClaudeCodeBridge | undefined
```

Returns the Claude Code Bridge instance for external access, or undefined if not enabled.

---

## AssessmentContext Interface

The context object passed to `runFullAssessment()` containing server connection details and metadata.

### Required Fields

| Field        | Type                                                                                      | Description                       |
| ------------ | ----------------------------------------------------------------------------------------- | --------------------------------- |
| `serverName` | `string`                                                                                  | Identifier for the MCP server     |
| `tools`      | `Tool[]`                                                                                  | Array of tools from `tools/list`  |
| `callTool`   | `(name: string, params: Record<string, unknown>) => Promise<CompatibilityCallToolResult>` | Function to invoke tool execution |
| `config`     | `AssessmentConfiguration`                                                                 | Assessment configuration          |

> **Note**: `CompatibilityCallToolResult` is from `@modelcontextprotocol/sdk/types.js` with structure `{ content: any[]; isError?: boolean }`.

### Optional Fields

| Field                | Type                                         | Description                                |
| -------------------- | -------------------------------------------- | ------------------------------------------ |
| `readmeContent`      | `string`                                     | README.md content for documentation scan   |
| `packageJson`        | `unknown`                                    | package.json for dependency analysis       |
| `packageLock`        | `unknown`                                    | package-lock.json for deep analysis        |
| `privacyPolicy`      | `unknown`                                    | Privacy policy content                     |
| `serverInfo`         | `{ name: string; version?: string; ... }`    | Server metadata from initialization        |
| `sourceCodePath`     | `string`                                     | Path to source code for deep analysis      |
| `sourceCodeFiles`    | `Map<string, string>`                        | Pre-loaded source files (filename→content) |
| `manifestJson`       | `ManifestJsonSchema`                         | MCPB manifest for validation               |
| `manifestRaw`        | `string`                                     | Raw manifest.json content                  |
| `onProgress`         | `ProgressCallback`                           | Callback for real-time progress events     |
| `resources`          | `MCPResource[]`                              | MCP resources for extended assessment      |
| `resourceTemplates`  | `MCPResourceTemplate[]`                      | Resource templates                         |
| `prompts`            | `MCPPrompt[]`                                | MCP prompts for assessment                 |
| `serverCapabilities` | `MCPServerCapabilities`                      | Declared server capabilities               |
| `readResource`       | `(uri: string) => Promise<string>`           | Function to read resource content          |
| `getPrompt`          | `(name, args) => Promise<{ messages: ... }>` | Function to get prompt content             |
| `transportConfig`    | `{ type, url?, usesTLS?, oauthEnabled? }`    | Transport metadata for security assessment |
| `listTools`          | `() => Promise<Tool[]>`                      | Refresh tools for temporal detection       |

### Transport Configuration

```typescript
transportConfig?: {
  type: "stdio" | "sse" | "streamable-http";
  url?: string;
  usesTLS?: boolean;
  oauthEnabled?: boolean;
}
```

Provides transport metadata for security assessment:

- `stdio`: Local process communication
- `sse`: Server-Sent Events (legacy)
- `streamable-http`: HTTP with streaming support

---

## AssessmentConfiguration Interface

Complete configuration options for assessments.

### Core Options

| Option                     | Type      | Default     | Description                              |
| -------------------------- | --------- | ----------- | ---------------------------------------- |
| `testTimeout`              | `number`  | `30000`     | Per-tool test timeout in milliseconds    |
| `securityTestTimeout`      | `number`  | `5000`      | Security-specific timeout (faster)       |
| `delayBetweenTests`        | `number`  | `0`         | Delay between tests (rate limiting)      |
| `skipBrokenTools`          | `boolean` | `false`     | Skip tools that fail initial test        |
| `reviewerMode`             | `boolean` | `false`     | Optimized for fast human-assisted review |
| `enableExtendedAssessment` | `boolean` | `true`      | Enable extended assessment modules       |
| `parallelTesting`          | `boolean` | `false`     | Run tests in parallel                    |
| `maxParallelTests`         | `number`  | `5`         | Maximum concurrent tests                 |
| `mcpProtocolVersion`       | `string`  | `"2025-06"` | MCP protocol version                     |

### Testing Options

| Option                     | Type                                   | Default      | Description                              |
| -------------------------- | -------------------------------------- | ------------ | ---------------------------------------- |
| `scenariosPerTool`         | `number`                               | `5-20`       | Max test scenarios per tool              |
| `securityPatternsToTest`   | `number`                               | `8`          | Number of security patterns (3 or 8)     |
| `enableDomainTesting`      | `boolean`                              | `true`       | Enable all 8 backend security patterns   |
| `enableSourceCodeAnalysis` | `boolean`                              | `false`      | Enable source code deep analysis         |
| `patternConfigPath`        | `string`                               | `undefined`  | Custom annotation pattern JSON path      |
| `temporalInvocations`      | `number`                               | `25`         | Invocations per tool for rug pull detect |
| `selectedToolsForTesting`  | `string[]`                             | `undefined`  | Specific tools to test (undefined = all) |
| `documentationVerbosity`   | `"minimal" \| "standard" \| "verbose"` | `"standard"` | Documentation output detail level        |

### Module Selection

```typescript
assessmentCategories?: {
  // Core modules (enabled by default)
  functionality: boolean;      // Tool execution testing
  security: boolean;           // Prompt injection, vulnerability detection
  documentation: boolean;      // README, examples, API docs
  errorHandling: boolean;      // MCP error protocol compliance
  usability: boolean;          // Naming, descriptions, schemas

  // Extended modules (disabled by default)
  mcpSpecCompliance?: boolean; // MCP protocol compliance
  aupCompliance?: boolean;     // AUP 14 categories violation scanning
  toolAnnotations?: boolean;   // readOnlyHint/destructiveHint validation
  prohibitedLibraries?: boolean; // Financial/Media library detection
  manifestValidation?: boolean; // MCPB manifest.json compliance
  portability?: boolean;       // Hardcoded paths, platform code
  externalAPIScanner?: boolean; // External API detection
  authentication?: boolean;    // OAuth appropriateness
  temporal?: boolean;          // Rug pull detection
  resources?: boolean;         // Resource security assessment
  prompts?: boolean;           // Prompt AUP compliance
  crossCapability?: boolean;   // Cross-capability security
}
```

### Logging Configuration

```typescript
logging?: {
  level: "silent" | "error" | "warn" | "info" | "debug";
}
```

| Level    | Description               |
| -------- | ------------------------- |
| `silent` | No output                 |
| `error`  | Errors only               |
| `warn`   | Errors and warnings       |
| `info`   | Standard output (default) |
| `debug`  | Full diagnostic output    |

---

## Configuration Presets

Pre-configured settings for common use cases.

### DEFAULT_ASSESSMENT_CONFIG

Standard configuration for general assessments.

```typescript
import { DEFAULT_ASSESSMENT_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

- 30s timeout, no delay
- Core modules enabled
- Extended modules disabled by default

### REVIEWER_MODE_CONFIG

Optimized for fast MCP directory reviews.

```typescript
import { REVIEWER_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

- 10s timeout, parallel execution
- 3 security patterns (critical only)
- Extended modules disabled

### DEVELOPER_MODE_CONFIG

Comprehensive testing for development/debugging.

```typescript
import { DEVELOPER_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

- Debug logging enabled
- All extended modules enabled
- Sequential execution for easier debugging

### AUDIT_MODE_CONFIG

MCP Directory compliance auditing.

```typescript
import { AUDIT_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

- All assessment modules enabled
- Source code analysis enabled
- Parallel execution

### CLAUDE_ENHANCED_AUDIT_CONFIG

AI-enhanced audit with Claude Code integration.

```typescript
import { CLAUDE_ENHANCED_AUDIT_CONFIG } from "@bryan-thompson/inspector-assessment/config";
```

- Claude Code features enabled
- Sequential execution (avoids rate limiting)
- Full semantic analysis

---

## MCPDirectoryAssessment Result

The complete assessment result structure returned by `runFullAssessment()`.

### Core Assessment Results

| Field           | Type                      | Description                    |
| --------------- | ------------------------- | ------------------------------ |
| `functionality` | `FunctionalityAssessment` | Tool execution test results    |
| `security`      | `SecurityAssessment`      | Security vulnerability results |
| `documentation` | `DocumentationAssessment` | Documentation quality metrics  |
| `errorHandling` | `ErrorHandlingAssessment` | Error handling compliance      |
| `usability`     | `UsabilityAssessment`     | Usability analysis results     |

### Extended Assessment Results

| Field                 | Type                                 | Description                  |
| --------------------- | ------------------------------------ | ---------------------------- |
| `mcpSpecCompliance`   | `MCPSpecComplianceAssessment?`       | MCP protocol compliance      |
| `aupCompliance`       | `AUPComplianceAssessment?`           | AUP violation scan results   |
| `toolAnnotations`     | `ToolAnnotationAssessment?`          | Tool annotation validation   |
| `prohibitedLibraries` | `ProhibitedLibrariesAssessment?`     | Prohibited library detection |
| `manifestValidation`  | `ManifestValidationAssessment?`      | MCPB manifest validation     |
| `portability`         | `PortabilityAssessment?`             | Portability analysis         |
| `externalAPIScanner`  | `ExternalAPIScannerAssessment?`      | External API detection       |
| `temporal`            | `TemporalAssessment?`                | Rug pull detection results   |
| `resources`           | `ResourceAssessment?`                | Resource security results    |
| `prompts`             | `PromptAssessment?`                  | Prompt assessment results    |
| `crossCapability`     | `CrossCapabilitySecurityAssessment?` | Cross-capability security    |

### Overall Assessment

| Field             | Type               | Description                            |
| ----------------- | ------------------ | -------------------------------------- |
| `serverName`      | `string`           | Server identifier                      |
| `assessmentDate`  | `string`           | ISO 8601 timestamp                     |
| `assessorVersion` | `string`           | Assessment module version              |
| `overallStatus`   | `AssessmentStatus` | `"PASS"`, `"FAIL"`, `"NEED_MORE_INFO"` |
| `summary`         | `string`           | Human-readable summary                 |
| `recommendations` | `string[]`         | Prioritized improvement suggestions    |
| `executionTime`   | `number`           | Total execution time in ms             |
| `totalTestsRun`   | `number`           | Total tests executed                   |

---

## Error Handling

### Exception Types

The orchestrator may throw the following errors:

| Error Type     | Cause                            |
| -------------- | -------------------------------- |
| `Error`        | General assessment failures      |
| `TypeError`    | Invalid configuration or context |
| Network errors | Tool call failures, timeouts     |

### Error Recovery Pattern

```typescript
try {
  const results = await orchestrator.runFullAssessment(context);
} catch (error) {
  if (error instanceof Error) {
    console.error(`Assessment failed: ${error.message}`);

    // Check for partial results
    if ("partialResults" in error) {
      console.log("Partial results available");
    }
  }
}
```

### Tool Call Errors

Individual tool call errors are captured in results, not thrown:

```typescript
const results = await orchestrator.runFullAssessment(context);

// Check for broken tools
if (results.functionality.brokenTools.length > 0) {
  console.log("Broken tools:", results.functionality.brokenTools);
}

// Check individual test results
results.functionality.toolResults.forEach((result) => {
  if (result.status === "broken") {
    console.log(`${result.toolName}: ${result.error}`);
  }
});
```

---

## JSONL Events Stream

During assessment, progress events are emitted to stderr in JSONL format.

### Event Types

| Event                 | Description                       |
| --------------------- | --------------------------------- |
| `module_started`      | Module begins execution           |
| `test_batch`          | Batch of test results (real-time) |
| `module_complete`     | Module finishes with score        |
| `assessment_complete` | Final results available           |

> For the full list of 13 event types, see [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md).

### Capturing Events

```typescript
import { spawn } from "child_process";

const proc = spawn("npx", [
  "mcp-assess-full",
  "server",
  "--config",
  "config.json",
]);

proc.stderr.on("data", (data) => {
  const lines = data.toString().split("\n").filter(Boolean);
  lines.forEach((line) => {
    try {
      const event = JSON.parse(line);
      if (event.event === "module_complete") {
        console.log(`${event.module}: ${event.score}%`);
      }
    } catch {
      // Not JSON, regular log output
    }
  });
});
```

### Event Schema Reference

See [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) for complete event schemas.

---

## Version Compatibility

### Minimum Node.js Version

- Node.js 22.7.5 or higher required

### MCP SDK Compatibility

- `@modelcontextprotocol/sdk` 1.0.0+

### Breaking Changes Policy

- Major version: Breaking API changes
- Minor version: New features, backward compatible
- Patch version: Bug fixes, no API changes

### Deprecation Notices

| Deprecated        | Replacement           | Removal Version   |
| ----------------- | --------------------- | ----------------- |
| `assess()` method | `runFullAssessment()` | 2.0.0             |
| Assessment Tab UI | CLI commands          | Removed in 1.23.0 |

---

## See Also

- [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Practical examples
- [Type Reference](TYPE_REFERENCE.md) - Complete type definitions
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - All 16 assessment modules
- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Event stream documentation

---

**Version**: 1.23.2+
**Last Updated**: 2026-01-06
