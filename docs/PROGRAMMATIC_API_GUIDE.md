# Programmatic API Guide: @bryan-thompson/inspector-assessment

> **Version**: 1.23.2+
> **Last Updated**: 2026-01-04
>
> **Related Documentation:**
> [API Reference](API_REFERENCE.md) | [Type Reference](TYPE_REFERENCE.md) | [Integration Guide](INTEGRATION_GUIDE.md)

Step-by-step guide for using AssessmentOrchestrator programmatically. This is the primary way to integrate MCP server assessment into your own tools.

---

## Table of Contents

- [Overview](#overview)
- [When to Use Programmatic vs CLI](#when-to-use-programmatic-vs-cli)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Basic Usage Pattern](#basic-usage-pattern)
  - [Hello World Example](#hello-world-example)
- [AssessmentOrchestrator Class](#assessmentorchestrator-class)
  - [Constructor](#constructor)
  - [runFullAssessment()](#runfullassessment)
  - [Configuration Methods](#configuration-methods)
- [AssessmentContext Interface](#assessmentcontext-interface)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
- [Practical Examples](#practical-examples)
  - [Basic HTTP Assessment](#basic-http-assessment)
  - [Custom Configuration](#custom-configuration)
  - [Source Code Analysis](#source-code-analysis)
  - [Progress Monitoring](#progress-monitoring)
  - [Error Handling](#error-handling)
- [Configuration Patterns](#configuration-patterns)
- [Result Interpretation](#result-interpretation)
- [Related Documentation](#related-documentation)

---

## Overview

The programmatic API provides direct access to the MCP assessment engine used by the CLI tools (`mcp-assess-full`, `mcp-assess-security`). Use it when you need:

- **Fine-grained control** over assessment configuration
- **Integration** into larger workflows (CI/CD, auditing tools)
- **Custom result processing** beyond what the CLI provides
- **Multi-server orchestration** (like mcp-auditor)

### Key Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Integration Code                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               AssessmentOrchestrator                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              16 Assessment Modules                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │Functional│ │ Security │ │   Docs   │ │  Error   │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │Usability │ │   AUP    │ │Annotation│ │ Temporal │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │  │
│  │                    ... and more                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MCPDirectoryAssessment                        │
│                    (Structured Results)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## When to Use Programmatic vs CLI

| Use Case                       | Recommended  | Reason                  |
| ------------------------------ | ------------ | ----------------------- |
| One-off server testing         | CLI          | Simpler, no code needed |
| CI/CD pipeline                 | CLI          | Exit codes, JSON output |
| Multi-server audit tool        | Programmatic | Control, aggregation    |
| Custom report generation       | Programmatic | Full result access      |
| Integration into existing tool | Programmatic | Direct API access       |
| Quick vulnerability check      | CLI          | `mcp-assess-security`   |

---

## Getting Started

### Installation

```bash
npm install @bryan-thompson/inspector-assessment
```

### Basic Usage Pattern

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// 1. Import the orchestrator (main export)
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

// 2. Import configuration presets (optional)
import { DEVELOPER_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";

// 3. Create orchestrator with configuration
const orchestrator = new AssessmentOrchestrator(DEVELOPER_MODE_CONFIG);

// 4. Build assessment context (connect to MCP server)
const context = {
  serverName: "my-server",
  tools: await client.listTools(),
  callTool: async (name, params) =>
    client.callTool({ name, arguments: params }),
  config: DEVELOPER_MODE_CONFIG,
};

// 5. Run assessment
const result = await orchestrator.runFullAssessment(context);

// 6. Process results
console.log(`Status: ${result.overallStatus}`);
console.log(`Vulnerabilities: ${result.security.vulnerabilities.length}`);
```

### Hello World Example

Minimal working example for HTTP transport:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

async function assessServer(url: string, serverName: string) {
  // Connect to MCP server
  const transport = new StreamableHTTPClientTransport(new URL(url));
  const client = new Client({ name: "assessment-client", version: "1.0.0" });
  await client.connect(transport);

  // Get server capabilities
  const { tools } = await client.listTools();

  // Create orchestrator with default config
  const orchestrator = new AssessmentOrchestrator();

  // Run assessment
  const result = await orchestrator.runFullAssessment({
    serverName,
    tools,
    callTool: async (name, params) =>
      client.callTool({ name, arguments: params }),
    config: {},
  });

  // Cleanup
  await client.close();

  return result;
}

// Usage
const result = await assessServer("http://localhost:10900/mcp", "my-server");
console.log(`Overall: ${result.overallStatus}`);
```

---

## AssessmentOrchestrator Class

### Constructor

```typescript
constructor(config: Partial<AssessmentConfiguration> = {})
```

Creates an orchestrator with the specified configuration. Unspecified options use defaults from `DEFAULT_ASSESSMENT_CONFIG`.

**Parameters:**

- `config` - Partial configuration object (merged with defaults)

**Example:**

```typescript
// Use all defaults
const orchestrator = new AssessmentOrchestrator();

// Use a preset
const orchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);

// Custom configuration
const orchestrator = new AssessmentOrchestrator({
  testTimeout: 60000,
  parallelTesting: true,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
  },
});
```

### runFullAssessment()

```typescript
async runFullAssessment(context: AssessmentContext): Promise<MCPDirectoryAssessment>
```

Runs a complete assessment on an MCP server.

**Parameters:**

- `context` - Assessment context with server connection and configuration

**Returns:**

- `MCPDirectoryAssessment` - Complete assessment results

**Execution Flow:**

1. **Phase 0 (Temporal)**: Temporal assessment runs first for clean baseline
2. **Phase 1 (Core)**: Core modules (functionality, security, docs, errors, usability)
3. **Phase 2 (Extended)**: Extended modules execute if enabled
4. **Phase 3 (Aggregation)**: Temporal findings integrated into security results
5. **Phase 4 (Finalization)**: Overall status, summary, and recommendations

### Configuration Methods

#### enableClaudeCode()

Enable Claude Code integration after construction:

```typescript
orchestrator.enableClaudeCode({
  features: {
    intelligentTestGeneration: true,
    aupSemanticAnalysis: true,
    annotationInference: false,
    documentationQuality: false,
  },
  timeout: 60000,
});
```

#### isClaudeEnabled()

Check if Claude integration is active:

```typescript
if (orchestrator.isClaudeEnabled()) {
  console.log("Claude-enhanced analysis available");
}
```

#### getClaudeBridge()

Access the Claude bridge for advanced use:

```typescript
const bridge = orchestrator.getClaudeBridge();
if (bridge) {
  // Use bridge for custom analysis
}
```

---

## AssessmentContext Interface

### Required Fields

| Field        | Type                                                     | Description                                           |
| ------------ | -------------------------------------------------------- | ----------------------------------------------------- |
| `serverName` | `string`                                                 | Name for identification and reporting                 |
| `tools`      | `Tool[]`                                                 | Array of tools from `client.listTools()`              |
| `callTool`   | `(name, params) => Promise<CompatibilityCallToolResult>` | Function to call tools (MCP SDK standard return type) |
| `config`     | `AssessmentConfiguration`                                | Assessment configuration                              |

> **Note**: `CompatibilityCallToolResult` is imported from `@modelcontextprotocol/sdk/types.js` and contains `{ content: any[]; isError?: boolean }`.

### Optional Fields

| Field                | Type                                                 | Description                                     |
| -------------------- | ---------------------------------------------------- | ----------------------------------------------- |
| `readmeContent`      | `string`                                             | README content for documentation assessment     |
| `packageJson`        | `unknown`                                            | package.json for dependency analysis            |
| `packageLock`        | `unknown`                                            | package-lock.json for dependency analysis       |
| `privacyPolicy`      | `unknown`                                            | Privacy policy content for AUP compliance       |
| `serverInfo`         | `{ name: string; version?: string; metadata?: any }` | Server name/version info                        |
| `sourceCodePath`     | `string`                                             | Path for source code analysis                   |
| `sourceCodeFiles`    | `Map<string, string>`                                | Pre-loaded source files (filename → content)    |
| `manifestJson`       | `ManifestJsonSchema`                                 | MCPB manifest for validation                    |
| `manifestRaw`        | `string`                                             | Raw manifest.json content                       |
| `onProgress`         | `ProgressCallback`                                   | Real-time progress events callback              |
| `resources`          | `MCPResource[]`                                      | MCP resources to assess                         |
| `resourceTemplates`  | `MCPResourceTemplate[]`                              | Resource templates                              |
| `prompts`            | `MCPPrompt[]`                                        | MCP prompts to assess                           |
| `serverCapabilities` | `MCPServerCapabilities`                              | Server capabilities                             |
| `readResource`       | `(uri: string) => Promise<string>`                   | Function to read resources                      |
| `getPrompt`          | `(name, args) => Promise<{ messages: [...] }>`       | Function to get prompts                         |
| `transportConfig`    | `{ type, url?, usesTLS?, oauthEnabled? }`            | Transport details for security assessment       |
| `listTools`          | `() => Promise<Tool[]>`                              | Function to refresh tool list (temporal checks) |

---

## Practical Examples

### Basic HTTP Assessment

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";
import { DEFAULT_ASSESSMENT_CONFIG } from "@bryan-thompson/inspector-assessment/config";

async function runHttpAssessment(serverUrl: string) {
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
  const client = new Client({ name: "assessor", version: "1.0.0" });

  await client.connect(transport);
  const { tools } = await client.listTools();

  const orchestrator = new AssessmentOrchestrator(DEFAULT_ASSESSMENT_CONFIG);

  const result = await orchestrator.runFullAssessment({
    serverName: new URL(serverUrl).hostname,
    tools,
    callTool: async (name, params) =>
      client.callTool({ name, arguments: params }),
    config: DEFAULT_ASSESSMENT_CONFIG,
    transportConfig: {
      type: "streamable-http",
      url: serverUrl,
      usesTLS: serverUrl.startsWith("https"),
    },
  });

  await client.close();
  return result;
}
```

### Custom Configuration

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

// Security-focused assessment (v1.25.0+)
const securityConfig = {
  testTimeout: 15000,
  securityTestTimeout: 5000,
  parallelTesting: true,
  maxParallelTests: 10,
  securityPatternsToTest: 8,
  enableDomainTesting: true,
  assessmentCategories: {
    // Tier 1: Core Security
    functionality: true,
    security: true,
    errorHandling: true,
    protocolCompliance: true,
    temporal: true,
    aupCompliance: true,
    // Skip Tier 4 modules for speed
    developerExperience: false,
    // Include Tier 2 compliance checks
    toolAnnotations: true,
  },
};

const orchestrator = new AssessmentOrchestrator(securityConfig);
const result = await orchestrator.runFullAssessment(context);

// Check for critical issues
if (result.security.overallRiskLevel === "HIGH") {
  console.error("Critical vulnerabilities found!");
  process.exit(1);
}
```

### Source Code Analysis

```typescript
import * as fs from "fs";
import * as path from "path";
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";
import { AUDIT_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";

async function runWithSourceAnalysis(serverPath: string) {
  // Load source files
  const sourceFiles = new Map<string, string>();
  const srcDir = path.join(serverPath, "src");

  for (const file of fs.readdirSync(srcDir, { recursive: true })) {
    const filePath = path.join(srcDir, file.toString());
    if (fs.statSync(filePath).isFile()) {
      sourceFiles.set(file.toString(), fs.readFileSync(filePath, "utf-8"));
    }
  }

  // Load README
  const readmePath = path.join(serverPath, "README.md");
  const readmeContent = fs.existsSync(readmePath)
    ? fs.readFileSync(readmePath, "utf-8")
    : undefined;

  const orchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);

  const result = await orchestrator.runFullAssessment({
    ...context,
    sourceCodePath: srcDir,
    sourceCodeFiles: sourceFiles,
    readmeContent,
  });

  // Source analysis enables these modules
  console.log(
    `External APIs: ${result.externalAPIScanner?.detectedAPIs.length}`,
  );
  console.log(`Portability issues: ${result.portability?.issues.length}`);
  console.log(
    `Prohibited libraries: ${result.prohibitedLibraries?.matches.length}`,
  );
}
```

### Progress Monitoring

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";
import type { ProgressEvent } from "@bryan-thompson/inspector-assessment/progress";

function handleProgress(event: ProgressEvent): void {
  switch (event.type) {
    case "module_started":
      console.log(`Starting ${event.module}: ${event.estimatedTests} tests`);
      break;
    case "test_batch":
      const pct = Math.round((event.completed / event.total) * 100);
      console.log(
        `${event.module}: ${pct}% (${event.completed}/${event.total})`,
      );
      break;
    case "module_complete":
      console.log(
        `Completed ${event.module}: ${event.status} (${event.score}%)`,
      );
      break;
    case "vulnerability_found":
      console.warn(
        `VULN: ${event.tool} - ${event.pattern} (${event.riskLevel})`,
      );
      break;
  }
}

const orchestrator = new AssessmentOrchestrator();
const result = await orchestrator.runFullAssessment({
  ...context,
  onProgress: handleProgress,
});
```

### Error Handling

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

async function safeAssessment(context: AssessmentContext) {
  const orchestrator = new AssessmentOrchestrator({
    testTimeout: 30000,
    skipBrokenTools: true, // Continue if tools fail
  });

  try {
    const result = await orchestrator.runFullAssessment(context);

    // Check for partial failures
    if (result.functionality.brokenTools.length > 0) {
      console.warn(
        `Broken tools: ${result.functionality.brokenTools.join(", ")}`,
      );
    }

    return result;
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes("ECONNREFUSED")) {
        throw new Error(`Cannot connect to server: ${context.serverName}`);
      }
      if (error.message.includes("timeout")) {
        throw new Error(`Assessment timed out for: ${context.serverName}`);
      }
    }
    throw error;
  }
}
```

---

## Configuration Patterns

### Configuration Presets

```typescript
import {
  DEFAULT_ASSESSMENT_CONFIG, // Balanced defaults (5 core modules)
  REVIEWER_MODE_CONFIG, // Fast reviews (parallel, 3 patterns)
  DEVELOPER_MODE_CONFIG, // Debug mode (all modules, verbose)
  AUDIT_MODE_CONFIG, // Full compliance (all assessment modules)
  CLAUDE_ENHANCED_AUDIT_CONFIG, // Semantic analysis with Claude
} from "@bryan-thompson/inspector-assessment/config";
```

All presets include `configVersion: 2` for schema migration support (v1.27.0+). When spreading from a preset or creating a custom config, the version field is preserved automatically. See [Config Schema Versioning](DEPRECATION_GUIDE.md#config-schema-versioning) for details on required fields.

### Module Selection (v1.25.0+)

```typescript
// Enable modules by tier (v1.25.0+ naming)
const config = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    // Tier 1: Core Security (recommended always)
    functionality: true,
    security: true,
    errorHandling: true,
    protocolCompliance: true,
    temporal: true,
    aupCompliance: true,

    // Tier 2: Compliance (for MCP Directory submission)
    toolAnnotations: true,
    authentication: true,
    prohibitedLibraries: false, // Skip
    manifestValidation: false, // Skip (MCPB-specific)

    // Tier 3: Capability-Based (conditional)
    resources: true,
    prompts: true,
    crossCapability: true,

    // Tier 4: Extended (optional, comprehensive audits)
    developerExperience: true,
    portability: false, // Skip (MCPB-specific)
    externalAPIScanner: true,
  },
};

// Deprecated module names (v1.24 and earlier) are still supported
// but will show warnings. See migration section in API_REFERENCE.md
```

### Tool Selection

```typescript
// Test specific tools only
const config = {
  selectedToolsForTesting: ["tool_a", "tool_b", "tool_c"],
};

// Test all tools (default)
const config = {
  selectedToolsForTesting: undefined, // or omit the field
};
```

---

## Result Interpretation

### Overall Status

```typescript
const result = await orchestrator.runFullAssessment(context);

switch (result.overallStatus) {
  case "PASS":
    console.log("Server meets all requirements");
    break;
  case "FAIL":
    console.log("Critical issues found");
    console.log("Recommendations:", result.recommendations);
    break;
  case "NEED_MORE_INFO":
    console.log("Manual review required");
    break;
}
```

### Module-Specific Results

```typescript
// Security vulnerabilities
if (result.security.vulnerabilities.length > 0) {
  console.log("Vulnerabilities:");
  for (const vuln of result.security.vulnerabilities) {
    console.log(`  - ${vuln}`);
  }
}

// Broken tools
if (result.functionality.brokenTools.length > 0) {
  console.log("Broken tools:", result.functionality.brokenTools);
}

// AUP violations (if enabled)
if (result.aupCompliance?.violations.length > 0) {
  for (const v of result.aupCompliance.violations) {
    console.log(`AUP ${v.category}: ${v.matchedText} (${v.severity})`);
  }
}

// Annotation issues (if enabled)
if (result.toolAnnotations?.misalignedAnnotationsCount > 0) {
  console.log("Annotation misalignments found");
}
```

### Execution Metadata

```typescript
console.log(`Execution time: ${result.executionTime}ms`);
console.log(`Tests run: ${result.totalTestsRun}`);
console.log(`Protocol version: ${result.mcpProtocolVersion}`);
```

---

## Using Architecture Detection (Issue #57)

Detect server infrastructure characteristics programmatically.

### Basic Usage

```typescript
import { detectArchitecture } from "@bryan-thompson/inspector-assessment/annotations";

// Minimal context (tools only)
const analysis = detectArchitecture({ tools: serverTools });

console.log(`Server type: ${analysis.serverType}`); // local, hybrid, or remote
console.log(`Databases: ${analysis.databaseBackends.join(", ")}`);
console.log(`Network required: ${analysis.requiresNetworkAccess}`);
```

### With Package Dependencies (Higher Confidence)

```typescript
import { detectArchitecture } from "@bryan-thompson/inspector-assessment/annotations";

const analysis = detectArchitecture({
  tools: serverTools,
  packageJson: {
    dependencies: {
      "neo4j-driver": "^5.0.0",
      express: "^4.18.0",
    },
  },
  transportType: "http", // Known from connection
});

// High confidence results
if (analysis.databaseBackend === "neo4j") {
  console.log("Neo4j database detected - ensure database is accessible");
}

if (analysis.serverType === "remote") {
  console.warn("Remote server - data leaves local network");
}
```

### Checking for Database Operations

```typescript
import { hasDatabaseToolPatterns } from "@bryan-thompson/inspector-assessment/annotations";

// Quick check before full analysis
if (hasDatabaseToolPatterns(serverTools)) {
  const analysis = detectArchitecture({ tools: serverTools });
  console.log(`Database: ${analysis.databaseBackend}`);
}
```

---

## Using Behavior Inference (Issue #57)

Classify tool behavior (read-only, write, destructive) programmatically.

### Basic Single-Signal Inference

```typescript
import { inferBehavior } from "@bryan-thompson/inspector-assessment/annotations";

const result = inferBehavior("delete_user", "Permanently removes a user");

if (result.expectedDestructive) {
  console.warn(`Destructive tool: ${result.reason}`);
}

console.log(`Confidence: ${result.confidence}`); // high, medium, low
console.log(`Ambiguous: ${result.isAmbiguous}`);
```

### Enhanced Multi-Signal Inference

```typescript
import { inferBehaviorEnhanced } from "@bryan-thompson/inspector-assessment/annotations";

const result = inferBehaviorEnhanced(
  "list_users",
  "Returns a paginated list of all users",
  { type: "object", properties: { limit: { type: "number" } } }, // input schema
  { type: "array", items: { type: "object" } }, // output schema
);

// Access individual signals
console.log("Signals:");
if (result.signals.namePatternSignal) {
  console.log(`  Name: ${result.signals.namePatternSignal.confidence}%`);
}
if (result.signals.descriptionSignal) {
  console.log(`  Desc: ${result.signals.descriptionSignal.confidence}%`);
}
if (result.signals.inputSchemaSignal) {
  console.log(`  Input: ${result.signals.inputSchemaSignal.confidence}%`);
}

console.log(`Aggregated confidence: ${result.aggregatedConfidence}%`);
```

### Handling Ambiguous Results

```typescript
const result = inferBehaviorEnhanced(toolName, description, inputSchema);

if (result.isAmbiguous) {
  console.log("Ambiguous behavior - manual review recommended");
  console.log(`Reason: ${result.reason}`);

  // Show conflicting signals
  const signals = result.signals;
  if (
    signals.namePatternSignal?.expectedReadOnly &&
    signals.descriptionSignal?.expectedDestructive
  ) {
    console.log(
      "Conflict: Name suggests read-only, description suggests destructive",
    );
  }
}
```

---

## Using Performance Configuration (Issue #37)

Tune assessment execution parameters programmatically.

### Loading Configuration

```typescript
import {
  loadPerformanceConfig,
  validatePerformanceConfig,
  PERFORMANCE_PRESETS,
} from "@bryan-thompson/inspector-assessment/performance";

// Use defaults
const config = loadPerformanceConfig();

// Load from file
const customConfig = loadPerformanceConfig("/path/to/perf.json");

// Use a preset
const fastConfig = PERFORMANCE_PRESETS.fast;
```

### Validating Configuration

```typescript
import { validatePerformanceConfig } from "@bryan-thompson/inspector-assessment/performance";

const errors = validatePerformanceConfig({
  testTimeoutMs: 50, // Too low!
  functionalityBatchSize: 200, // Too high!
});

if (errors.length > 0) {
  console.error("Invalid configuration:");
  errors.forEach((e) => console.error(`  - ${e}`));
}
// Output:
// Invalid configuration:
//   - testTimeoutMs must be between 100 and 300000
//   - functionalityBatchSize must be between 1 and 100
```

### Creating Custom Configuration

```typescript
import { mergeWithDefaults } from "@bryan-thompson/inspector-assessment/performance";

// Only specify what you want to change
const config = mergeWithDefaults({
  testTimeoutMs: 30000, // Longer timeout for slow servers
  securityBatchSize: 20, // Larger batches for speed
});

// All other values use defaults
console.log(config.functionalityBatchSize); // 5 (default)
console.log(config.queueWarningThreshold); // 10000 (default)
```

### Environment-Specific Configurations

```typescript
// CI/CD Pipeline (fast)
const ciConfig = {
  functionalityBatchSize: 15,
  securityBatchSize: 25,
  testTimeoutMs: 3000,
  securityTestTimeoutMs: 3000,
};

// Large Tool Set (100+ tools)
const largeServerConfig = {
  functionalityBatchSize: 20,
  securityBatchSize: 50,
  queueWarningThreshold: 50000,
};

// High-Latency Network
const slowNetworkConfig = {
  batchFlushIntervalMs: 2000,
  testTimeoutMs: 30000,
  securityTestTimeoutMs: 30000,
};

// Resource-Constrained (512MB RAM)
const minimalConfig = {
  functionalityBatchSize: 2,
  securityBatchSize: 3,
  queueWarningThreshold: 3000,
  eventEmitterMaxListeners: 30,
};
```

---

## Related Documentation

- [TYPE_REFERENCE.md](TYPE_REFERENCE.md) - Complete TypeScript type reference
- [API_REFERENCE.md](API_REFERENCE.md) - Formal API documentation
- [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) - Building on top of assessment
- [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) - CLI usage guide
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- [JSONL_EVENTS_REFERENCE.md](JSONL_EVENTS_REFERENCE.md) - Real-time progress events (13 types)
- [ARCHITECTURE_DETECTION_GUIDE.md](ARCHITECTURE_DETECTION_GUIDE.md) - Server infrastructure analysis
- [BEHAVIOR_INFERENCE_GUIDE.md](BEHAVIOR_INFERENCE_GUIDE.md) - Tool behavior classification
- [PERFORMANCE_TUNING_GUIDE.md](PERFORMANCE_TUNING_GUIDE.md) - Execution parameter tuning

---

_Last updated: 2026-01-08 | Package version: 1.24.2_
