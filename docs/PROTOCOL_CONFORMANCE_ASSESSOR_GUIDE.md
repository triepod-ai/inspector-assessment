# Protocol Conformance Assessor Integration Guide

> **⚠️ DEPRECATED v1.25.2**: This module has been merged into the unified `ProtocolComplianceAssessor`. The standalone `ProtocolConformanceAssessor` remains exported for backwards compatibility but will be removed in v2.0.0.
>
> **Migration**: Use `ProtocolComplianceAssessor` from `./modules/ProtocolComplianceAssessor` for new code. See [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md#6-protocol-compliance-unified) for the unified module documentation.

**Version**: 1.0.0 (Deprecated)
**Status**: Deprecated - Use ProtocolComplianceAssessor
**Target Audience**: Assessment developers, integration engineers, auditors

---

## Overview

The **Protocol Conformance Assessor** (Module #18) validates MCP protocol-level compliance using conformance-inspired tests. It has been merged into ProtocolComplianceAssessor along with ErrorHandlingAssessor (Issue #188) to provide unified protocol validation.

### Key Characteristics

- **Test Count**: 3 protocol checks per assessment
- **Assessment Category**: Advanced compliance module
- **Module Key**: `protocolConformance`
- **Execution Mode**: Runs in parallel or sequential based on configuration
- **Event Emission**: Emits `module_started` and `module_complete` JSONL events

---

## Table of Contents

1. [Module Registration](#module-registration)
2. [Configuration](#configuration)
3. [Protocol Checks](#protocol-checks)
4. [Assessment Flow](#assessment-flow)
5. [JSONL Event Emission](#jsonl-event-emission)
6. [Data Structures & Types](#data-structures--types)
7. [Enabling/Disabling the Module](#enablingdisabling-the-module)
8. [Example Events](#example-events)
9. [Integration Points](#integration-points)

---

## Module Registration

### In AssessmentOrchestrator

The Protocol Conformance Assessor is registered and initialized in `AssessmentOrchestrator.ts`:

**Location**: `client/src/services/assessment/AssessmentOrchestrator.ts`

```typescript
// Import statement (line 44)
import { ProtocolConformanceAssessor } from "./modules/ProtocolConformanceAssessor";

// Instance property (line 359)
private protocolConformanceAssessor?: ProtocolConformanceAssessor;

// Initialization in constructor (lines 456-461)
if (this.config.enableExtendedAssessment) {
  if (this.config.assessmentCategories?.protocolConformance) {
    this.protocolConformanceAssessor = new ProtocolConformanceAssessor(
      this.config,
    );
  }
}
```

### In Module Index

The assessor is exported from the modules index:

**Location**: `client/src/services/assessment/modules/index.ts`

```typescript
// Protocol Conformance Assessor
export { ProtocolConformanceAssessor } from "./ProtocolConformanceAssessor";
```

---

## Configuration

### Assessment Categories Configuration

The module is controlled via the `assessmentCategories` configuration object:

```typescript
interface AssessmentCategories {
  // ... other categories ...
  protocolConformance?: boolean; // Enable/disable Protocol Conformance module
}
```

### Example Configuration

```typescript
const config: Partial<AssessmentConfiguration> = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true,
    protocolConformance: true, // Enable Protocol Conformance
    // ... other categories ...
  },
  testTimeout: 5000,
};
```

### CLI Configuration

Using the `--only-modules` flag:

```bash
# Run only Protocol Conformance assessment
mcp-assess-full --server my-server --config config.json --only-modules protocolConformance

# Run Protocol Conformance with other modules
mcp-assess-full --server my-server --only-modules functionality,errorHandling,protocolConformance
```

Using the `--skip-modules` flag:

```bash
# Run all modules except Protocol Conformance
mcp-assess-full --server my-server --config config.json --skip-modules protocolConformance
```

### MCP Specification Version Configuration

The Protocol Conformance Assessor can validate against different MCP specification versions via the `mcpProtocolVersion` configuration option.

**Configuration Example**:

```typescript
const config: Partial<AssessmentConfiguration> = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    protocolConformance: true,
  },
  mcpProtocolVersion: "2025-06-18", // Specify the MCP spec version
};
```

**Spec Version Behavior**:

| Scenario                        | Version Used      | Example URL                                                    |
| ------------------------------- | ----------------- | -------------------------------------------------------------- |
| `mcpProtocolVersion` configured | Configured value  | `https://modelcontextprotocol.io/specification/2025-06-18/...` |
| Not configured                  | Default "2025-06" | `https://modelcontextprotocol.io/specification/2025-06/...`    |

**Dynamic URL Construction** (v1.24.2+):

The assessor uses helper methods to construct spec URLs:

```typescript
// Internal helper methods
getSpecVersion()        → "2025-06" (default) or configured version
getSpecBaseUrl()        → "https://modelcontextprotocol.io/specification/{version}"
getSpecLifecycleUrl()   → "{baseUrl}/basic/lifecycle"
getSpecToolsUrl()       → "{baseUrl}/server/tools"
```

This allows validation against different MCP specification versions without code changes.

---

## Protocol Checks

The assessor performs **3 mandatory protocol checks**:

### 1. Error Response Format

**What it validates**: Error responses follow MCP protocol structure

**Criteria**:

- `isError` flag must be `true` when errors occur
- `content` must be an array
- Content items must have `type: "text"` or `type: "resource"`
- Error messages must be present in content array

**Test Method**: Call up to 3 representative tools with invalid parameters (`__test_invalid_param__: "should_cause_error"`)

**Multi-Tool Testing** (v1.24.2+):

To ensure consistent error handling across diverse tools, the assessor tests multiple tools:

- **Tool Selection Strategy**:
  - If 1-3 tools available: Tests all tools
  - If 4+ tools available: Tests 3 representative tools (first, middle, last)
  - Example: With 5 tools [A, B, C, D, E], tests A, C, E (indices 0, 2, 4)

- **Result Aggregation**:
  - All tested tools must pass for the check to pass
  - Evidence shows: `"Tested 3 tool(s): 3/3 passed error format validation"`
  - Per-tool results available in `details.toolResults`

**MCP Spec Reference**: Configurable via `config.mcpProtocolVersion` (see [MCP Specification Version Configuration](#mcp-specification-version-configuration))

**Confidence Levels**:

- **High**: All tested tools returned proper error responses with `isError: true`
- **Medium**: Some tools accepted invalid params without error, or mixed results
- **Low**: No tools available to test

**Example Pass Response**:

```json
{
  "isError": true,
  "content": [
    {
      "type": "text",
      "text": "Error: Invalid parameter provided"
    }
  ]
}
```

**Example Fail Response**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Error message"
    }
  ]
  // Missing: isError: true flag
}
```

---

### 2. Content Type Support

**What it validates**: Tool responses use only valid MCP content types

**Valid Content Types**:

- `text` - Plain text or structured text
- `image` - Image data (base64 encoded)
- `audio` - Audio data (base64 encoded)
- `resource` - Reference to external resource
- `resource_link` - Link to a resource (MCP v2025-06-18+)

**Test Method**: Call first tool with empty parameters (if no required params)

**MCP Spec Reference**: Configurable via `config.mcpProtocolVersion` (see [MCP Specification Version Configuration](#mcp-specification-version-configuration))

**Confidence Levels**:

- **High**: All content items use valid types
- **Medium**: Tool has required parameters, cannot easily test
- **Low**: Cannot test due to missing tools or required parameters

**Example Pass Response**:

```json
{
  "isError": false,
  "content": [
    {
      "type": "text",
      "text": "Success"
    },
    {
      "type": "image",
      "data": "base64encodeddata...",
      "mimeType": "image/png"
    }
  ]
}
```

**Example Fail Response**:

```json
{
  "isError": false,
  "content": [
    {
      "type": "invalid_type", // Not in valid list
      "data": "something"
    }
  ]
}
```

---

### 3. Initialization Handshake

**What it validates**: Server completed proper initialization with required metadata

**Validation Points**:

- **Required**: `serverInfo.name` must be non-empty string
- **Recommended**: `serverInfo.version` should be present
- **Recommended**: `serverCapabilities` should be declared

**Test Method**: Inspect `context.serverInfo` and `context.serverCapabilities` (no tool calls needed)

**MCP Spec Reference**: Configurable via `config.mcpProtocolVersion` (see [MCP Specification Version Configuration](#mcp-specification-version-configuration))

**Null-Safety Behavior** (v1.24.2+):

The assessor handles missing initialization data gracefully:

```typescript
// Validation treats null/undefined as missing
const validations = {
  hasServerInfo: serverInfo !== undefined && serverInfo !== null,
  hasServerName:
    typeof serverInfo?.name === "string" && serverInfo.name.length > 0,
  hasServerVersion:
    typeof serverInfo?.version === "string" && serverInfo.version.length > 0,
  hasCapabilities: serverCapabilities !== undefined,
};

// Minimum requirement: name must be present for pass
const hasMinimumInfo = validations.hasServerInfo && validations.hasServerName;
const passed = hasMinimumInfo; // Missing version/capabilities are warnings, not failures
```

**CLI Behavior**: When serverInfo is missing, the CLI logs a warning:

```
⚠️  Server did not provide serverInfo during initialization
```

**Confidence Levels**:

- **High**: All checks pass (name, version, capabilities present)
- **Medium**: Only minimum requirements met (name present, version/capabilities missing)
- **Low**: Unable to validate (serverInfo undefined)

**Example Pass Initialization**:

```json
{
  "serverInfo": {
    "name": "memory-mcp",
    "version": "1.0.0"
  },
  "serverCapabilities": {
    "tools": {}
  }
}
```

**Example Partial Pass (Medium Confidence)**:

```json
{
  "serverInfo": {
    "name": "memory-mcp"
    // Missing version
  },
  "serverCapabilities": {}
}
```

---

## Assessment Flow

### Module Instantiation

In `AssessmentOrchestrator.constructor()`:

1. Check if `config.enableExtendedAssessment` is true
2. Check if `config.assessmentCategories?.protocolConformance` is not false
3. Instantiate `ProtocolConformanceAssessor` with configuration

```typescript
if (this.config.enableExtendedAssessment) {
  if (this.config.assessmentCategories?.protocolConformance) {
    this.protocolConformanceAssessor = new ProtocolConformanceAssessor(
      this.config,
    );
  }
}
```

### Execution in Parallel Mode

In `AssessmentOrchestrator.runFullAssessment()` (parallel path, lines 854-867):

```typescript
// Protocol Conformance (3 checks: error format, content types, initialization)
if (this.protocolConformanceAssessor) {
  emitModuleStartedEvent("Protocol-Conformance", 3, toolCount);
  assessmentPromises.push(
    this.protocolConformanceAssessor.assess(context).then((r) => {
      emitModuleProgress(
        "Protocol-Conformance",
        r.status,
        r,
        this.protocolConformanceAssessor!.getTestCount(),
      );
      return (assessmentResults.protocolConformance = r);
    }),
  );
}

await Promise.all(assessmentPromises);
```

### Execution in Sequential Mode

In `AssessmentOrchestrator.runFullAssessment()` (sequential path, lines 1074-1084):

```typescript
// Protocol Conformance (3 checks: error format, content types, initialization)
if (this.protocolConformanceAssessor) {
  emitModuleStartedEvent("Protocol-Conformance", 3, toolCount);
  assessmentResults.protocolConformance =
    await this.protocolConformanceAssessor.assess(context);
  emitModuleProgress(
    "Protocol-Conformance",
    assessmentResults.protocolConformance.status,
    assessmentResults.protocolConformance,
    this.protocolConformanceAssessor.getTestCount(),
  );
}
```

### Assessment Context

The module receives an `AssessmentContext` containing:

```typescript
interface AssessmentContext {
  serverName: string;
  tools: Tool[];
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  serverInfo?: {
    name: string;
    version?: string;
    metadata?: unknown;
  };
  serverCapabilities?: MCPServerCapabilities;
  config: AssessmentConfiguration;
  // ... other fields ...
}
```

---

## JSONL Event Emission

The Protocol Conformance Assessor emits two JSONL events during execution:

### 1. `module_started` Event

**Emitted**: When module execution begins

**Location**: `AssessmentOrchestrator.runFullAssessment()` before calling assessor

**Event Structure**:

```json
{
  "event": "module_started",
  "module": "protocol_conformance",
  "estimatedTests": 3,
  "toolCount": 5,
  "version": "1.23.10"
}
```

**Field Descriptions**:

| Field            | Type   | Description                                                                                   |
| ---------------- | ------ | --------------------------------------------------------------------------------------------- |
| `event`          | string | Always `"module_started"`                                                                     |
| `module`         | string | Module key: `"protocol_conformance"` (normalized from "Protocol-Conformance")                 |
| `estimatedTests` | number | Always `3` (3 protocol checks)                                                                |
| `toolCount`      | number | Number of tools available for testing (may be subset if `selectedToolsForTesting` configured) |
| `version`        | string | Inspector version (e.g., `"1.23.10"`)                                                         |

**Event Emission Code** (AssessmentOrchestrator.ts, lines 77-95):

```typescript
function emitModuleStartedEvent(
  moduleName: string,
  estimatedTests: number,
  toolCount: number,
): void {
  const moduleKey = normalizeModuleKey(moduleName);
  moduleStartTimes.set(moduleKey, Date.now());

  console.error(
    JSON.stringify({
      event: "module_started",
      module: moduleKey,
      estimatedTests,
      toolCount,
      version: INSPECTOR_VERSION,
    }),
  );
}
```

**Normalization** (via `normalizeModuleKey()` from `@/lib/moduleScoring`):

- Input: `"Protocol-Conformance"`
- Process: `toLowerCase().replace(/ /g, "_")`
- Output: `"protocol_conformance"`

---

### 2. `module_complete` Event

**Emitted**: When module execution finishes

**Location**: `AssessmentOrchestrator.runFullAssessment()` after assessor completes

**Event Structure**:

```json
{
  "event": "module_complete",
  "module": "protocol_conformance",
  "status": "PASS",
  "score": 100.0,
  "testsRun": 3,
  "duration": 245,
  "version": "1.23.10"
}
```

**Field Descriptions**:

| Field      | Type   | Description                                                     |
| ---------- | ------ | --------------------------------------------------------------- |
| `event`    | string | Always `"module_complete"`                                      |
| `module`   | string | Module key: `"protocol_conformance"`                            |
| `status`   | string | Assessment status: `"PASS"`, `"FAIL"`, or `"NEED_MORE_INFO"`    |
| `score`    | number | Overall compliance score (0-100)                                |
| `testsRun` | number | Number of protocol checks executed (3)                          |
| `duration` | number | Time in milliseconds from `module_started` to `module_complete` |
| `version`  | string | Inspector version                                               |

**Status Determination**:

```typescript
private determineAssessmentStatus(
  score: number,
  checks: Record<string, ProtocolCheck>,
): AssessmentStatus {
  // Critical checks that must pass
  const criticalChecks = [
    checks.errorResponseFormat,
    checks.initializationHandshake,
  ];

  // If any critical check fails with high confidence, FAIL
  const criticalFailure = criticalChecks.some(
    (c) => !c.passed && c.confidence === "high",
  );

  if (criticalFailure) {
    return "FAIL";
  }

  // Score-based determination
  if (score >= 90) {
    return "PASS";
  } else if (score >= 70) {
    return "NEED_MORE_INFO";
  } else {
    return "FAIL";
  }
}
```

**Event Emission Code** (AssessmentOrchestrator.ts, lines 103-141):

```typescript
function emitModuleProgress(
  moduleName: string,
  status: string,
  result: any,
  testsRun: number = 0,
): void {
  const score = calculateModuleScore(result);

  // Don't emit events for skipped modules (null score means module wasn't run)
  if (score === null) return;

  const moduleKey = normalizeModuleKey(moduleName);

  // Calculate duration from module start time
  const startTime = moduleStartTimes.get(moduleKey);
  const duration = startTime ? Date.now() - startTime : 0;
  moduleStartTimes.delete(moduleKey);

  // Build and emit event
  const event: Record<string, unknown> = {
    event: "module_complete",
    module: moduleKey,
    status,
    score,
    testsRun,
    duration,
    version: INSPECTOR_VERSION,
  };

  console.error(JSON.stringify(event));
}
```

---

### Score Calculation

The module score is calculated by `calculateModuleScore()` from `@/lib/moduleScoring`:

```typescript
function calculateModuleScore(result: ProtocolConformanceAssessment): number {
  return result.score; // Returns 0-100
}
```

**Score Formula**:

```
score = (passedChecks / totalChecks) * 100
```

**Example Scores**:

- All 3 checks pass: `(3/3) * 100 = 100.0`
- 2 of 3 checks pass: `(2/3) * 100 = 66.67`
- 1 of 3 checks pass: `(1/3) * 100 = 33.33`
- 0 of 3 checks pass: `(0/3) * 100 = 0.0`

---

## Data Structures & Types

### ProtocolConformanceAssessment

**Location**: `client/src/lib/assessment/policyComplianceTypes.ts` (was `extendedTypes.ts` lines 570-592 before Issue #164 modularization)

```typescript
export interface ProtocolConformanceAssessment {
  /** Individual protocol checks */
  checks: {
    /** Validates error responses follow MCP format (isError flag, content array structure) */
    errorResponseFormat: ProtocolCheck;
    /** Validates content types are valid (text, image, audio, resource) */
    contentTypeSupport: ProtocolCheck;
    /** Validates server completed proper initialization handshake */
    initializationHandshake: ProtocolCheck;
    /** Optional: Validates progress notification format (if tools support progress) */
    progressNotifications?: ProtocolCheck;
    /** Optional: Validates log notification format (if tools support logging) */
    logNotifications?: ProtocolCheck;
  };
  /** Overall conformance score (0-100) */
  score: number;
  /** Assessment status based on score and critical check failures */
  status: AssessmentStatus;
  /** Human-readable explanation of the assessment result */
  explanation: string;
  /** Recommendations for improving protocol conformance */
  recommendations: string[];
}
```

### ProtocolCheck

**Location**: `client/src/lib/assessment/policyComplianceTypes.ts` (was `extendedTypes.ts` lines 550-563 before Issue #164 modularization)

```typescript
export interface ProtocolCheck {
  /** Whether the check passed */
  passed: boolean;
  /** Confidence level of the check result */
  confidence: "high" | "medium" | "low";
  /** Human-readable evidence of the check result */
  evidence: string;
  /** URL to the MCP specification section this check validates */
  specReference: string;
  /** Additional details about the check (e.g., raw responses, validation results) */
  details?: Record<string, unknown>;
  /** Warnings that don't fail the check but should be noted */
  warnings?: string[];
}
```

### AssessmentStatus

**Location**: `client/src/lib/assessment/coreTypes.ts`

```typescript
type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO" | "ERROR";
```

---

## Enabling/Disabling the Module

### Via AssessmentConfiguration

Enable the module:

```typescript
const config = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    protocolConformance: true, // Enable
  },
};
```

Disable the module:

```typescript
const config = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    protocolConformance: false, // Disable
  },
};
```

### Via CLI

Enable only Protocol Conformance:

```bash
mcp-assess-full --server my-server --config config.json \
  --only-modules protocolConformance
```

Disable Protocol Conformance (run all others):

```bash
mcp-assess-full --server my-server --config config.json \
  --skip-modules protocolConformance
```

### Via Preset Configurations

The module is enabled in these configuration presets:

1. **DEVELOPER_MODE_CONFIG** - Full assessment for developers
2. **AUDIT_MODE_CONFIG** - Comprehensive audit assessment
3. **CLAUDE_ENHANCED_AUDIT_CONFIG** - Audit with Claude Code integration

---

## Example Events

### Full Assessment Run (Parallel Mode)

```jsonl
{"event":"server_connected","serverName":"test-server","transport":"http","version":"1.23.10"}
{"event":"tools_discovery_complete","count":5,"version":"1.23.10"}
{"event":"modules_configured","module":"protocol_conformance","reason":"only-modules","version":"1.23.10"}
{"event":"module_started","module":"protocol_conformance","estimatedTests":3,"toolCount":5,"version":"1.23.10"}
{"event":"module_complete","module":"protocol_conformance","status":"PASS","score":100.0,"testsRun":3,"duration":245,"version":"1.23.10"}
{"event":"assessment_complete","overallStatus":"PASS","totalScore":87.5,"duration":5234,"version":"1.23.10"}
```

### Assessment with Failures

```jsonl
{"event":"server_connected","serverName":"bad-server","transport":"stdio","version":"1.23.10"}
{"event":"tools_discovery_complete","count":3,"version":"1.23.10"}
{"event":"module_started","module":"protocol_conformance","estimatedTests":3,"toolCount":3,"version":"1.23.10"}
{"event":"module_complete","module":"protocol_conformance","status":"FAIL","score":33.33,"testsRun":3,"duration":156,"version":"1.23.10"}
{"event":"assessment_complete","overallStatus":"FAIL","totalScore":42.1,"duration":3456,"version":"1.23.10"}
```

### Parsing Events in Code

```typescript
const events: ProtocolConformanceEvent[] = [];
const lines = eventStream.split("\n");

for (const line of lines) {
  if (!line.trim()) continue;

  const event = JSON.parse(line);

  if (
    event.event === "module_started" &&
    event.module === "protocol_conformance"
  ) {
    console.log(
      `Protocol Conformance: Estimated ${event.estimatedTests} checks`,
    );
  }

  if (
    event.event === "module_complete" &&
    event.module === "protocol_conformance"
  ) {
    console.log(
      `Protocol Conformance: ${event.status} (${event.score.toFixed(1)}%)`,
    );
    console.log(`Duration: ${event.duration}ms`);
  }
}
```

---

## Integration Points

### 1. Assessment Orchestration

**File**: `client/src/services/assessment/AssessmentOrchestrator.ts`

**Integration Points**:

- **Line 44**: Module import
- **Line 359**: Instance property declaration
- **Lines 456-461**: Module initialization
- **Lines 568-578**: Test count reset
- **Lines 853-867**: Parallel execution with event emission
- **Lines 1073-1084**: Sequential execution with event emission

### 2. Module Implementation

**File**: `client/src/services/assessment/modules/ProtocolConformanceAssessor.ts`

**Key Methods**:

- `assess(context: AssessmentContext)`: Main assessment entry point
- `checkErrorResponseFormat(context)`: Error response validation
- `checkContentTypeSupport(context)`: Content type validation
- `checkInitializationHandshake(context)`: Server metadata validation
- `determineAssessmentStatus(score, checks)`: Status calculation
- `generateExplanation(score, checks)`: Human-readable summary
- `generateRecommendations(checks)`: Improvement suggestions

### 3. Type Definitions

**File**: `client/src/lib/assessment/policyComplianceTypes.ts` (modularized from `extendedTypes.ts` in Issue #164)

**Types Exported**:

- `ProtocolCheck`
- `ProtocolConformanceAssessment`

**Backward Compatible Import**: `import type { ProtocolCheck } from "@/lib/assessment/extendedTypes"` still works via shim

### 4. Module Export

**File**: `client/src/services/assessment/modules/index.ts`

**Export**: Line 44

```typescript
export { ProtocolConformanceAssessor } from "./ProtocolConformanceAssessor";
```

### 5. Test Suite

**File**: `client/src/services/assessment/__tests__/ProtocolConformanceAssessor.test.ts`

**Coverage** (24 test cases total):

- Error Response Format (6 test cases) - Single tool validation
- Content Type Support (3 test cases) - Type validation
- Initialization Handshake (4 test cases) - Server metadata
- Overall Assessment (4 test cases) - Status and scoring
- Spec References (1 test case) - URL generation
- **Multi-Tool Error Format Testing (4 test cases)** - v1.24.2+ representative selection
- **Config-based Spec Version (2 test cases)** - v1.24.2+ dynamic URL generation

### 6. Assessment Catalog Documentation

**File**: `docs/ASSESSMENT_CATALOG.md`

**Documentation**: Lines 666-731

- Module purpose and relationship
- Test approach and checks
- Pass criteria
- Status determination logic
- Configuration presets

---

## Best Practices

### 1. Module Configuration

Always enable the module when:

- Running comprehensive compliance assessments
- Auditing production MCP servers
- Validating new server implementations
- Testing MCP specification compliance

Disable the module when:

- Running quick functionality checks only
- Testing specific modules in isolation
- Benchmarking performance (reduces overhead)

### 2. Event Handling

When consuming JSONL events:

```typescript
interface ProtocolConformanceEventListener {
  onModuleStarted(event: ModuleStartedEvent): void;
  onModuleComplete(event: ModuleCompleteEvent): void;
}

class AssessmentMonitor implements ProtocolConformanceEventListener {
  onModuleStarted(event: ModuleStartedEvent): void {
    if (event.module === "protocolConformance") {
      console.log(`Starting protocol checks: ${event.estimatedTests} checks`);
      // Start progress indicator
    }
  }

  onModuleComplete(event: ModuleCompleteEvent): void {
    if (event.module === "protocolConformance") {
      console.log(
        `Protocol checks complete: ${event.status} (${event.score}%)`,
      );
      // Update UI with results
    }
  }
}
```

### 3. Error Handling

The module gracefully handles:

- Missing tools (returns low confidence)
- Tools with required parameters (returns medium confidence)
- Tool execution timeouts (configurable via `testTimeout`)
- Exception throws instead of error responses (returns failure)

### 4. Performance Considerations

- **Fast checks**: Initialization handshake (no tool calls, ~5ms)
- **Medium speed**: Content type validation (1 tool call, ~100ms)
- **Varies**: Error format validation (1 tool call, depends on tool speed)

Total module duration typically: **100-500ms** for most servers

---

## Troubleshooting

### Module Not Running

**Symptom**: No `module_started` event for protocol conformance

**Causes**:

1. `enableExtendedAssessment` is false
2. `assessmentCategories.protocolConformance` is false
3. Module was explicitly skipped via `--skip-modules`

**Fix**: Enable in config:

```typescript
enableExtendedAssessment: true,
assessmentCategories: {
  protocolConformance: true,
}
```

### Score is 0%

**Symptom**: All checks failing

**Common Causes**:

- Server crashes on tool invocation
- Error responses missing `isError: true` flag
- Server info not populated during initialization
- Content using invalid types

**Check**:

```bash
cat /tmp/inspector-assessment-*.json | jq '.protocolConformance.checks'
```

### Medium Confidence Warnings

**Symptom**: Checks pass but with "medium" confidence

**Reasons**:

- Tool has required parameters (content type check skipped)
- Tool accepted invalid params without error (error format check)
- Server missing version or capabilities (initialization check)

**Action**: Review the details field for specific issues

---

## Related Documentation

- **[ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md#18-protocol-conformance-assessment)** - Module catalog entry
- **[JSONL_EVENTS_REFERENCE.md](JSONL_EVENTS_REFERENCE.md)** - Complete event reference
- **[CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md)** - CLI usage and configuration
- **[UPSTREAM_SYNC_WORKFLOW.md](UPSTREAM_SYNC_WORKFLOW.md)** - Integration with upstream MCP Inspector

---

**Last Updated**: 2026-01-06
**Inspector Version**: 1.23.10+
