# JSONL Events Reference

> **Part of the JSONL Events API documentation series:**
>
> - **Reference** (this document) - All 17 event types and schema definitions
> - [Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
> - [Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing

**Version**: 1.24.2
**Status**: Stable
**Target Audience**: MCP Auditor developers, assessment tool integrators, real-time progress consumers

---

## Overview

The MCP Inspector emits a comprehensive stream of structured JSONL (JSON Lines) events to stderr during assessment execution. This enables external tools (like MCP Auditor) to parse and display live progress, security findings, and annotation assessments in real-time without waiting for the full assessment to complete.

**Key Features:**

- **Real-time progress** with `test_batch` events during module execution
- **Instant security alerts** via `vulnerability_found` events
- **Annotation assessment** via four specialized annotation events
- **AUP enrichment** for Acceptable Use Policy violations (sampled, severity-prioritized)
- **Automatic version tracking** - all events include `version` field for compatibility checking
- **Schema versioning** - all events include `schemaVersion` field for schema evolution
- **EventBatcher** - controls progress event volume via intelligent batch size and time-based flushing

---

## Schema Versioning

All JSONL events include two versioning fields:

| Field           | Type    | Description                                                                                                      |
| --------------- | ------- | ---------------------------------------------------------------------------------------------------------------- |
| `version`       | string  | Inspector software version (e.g., "1.26.7"). Changes with each release.                                          |
| `schemaVersion` | integer | Event schema version (starts at 1). Only increments when event structure changes (fields added/removed/renamed). |

**Why two versions?**

- `version` tells consumers which Inspector build emitted the event
- `schemaVersion` tells consumers how to parse the event structure

**Schema Version History:**

| schemaVersion | Date       | Changes                                                                    |
| ------------- | ---------- | -------------------------------------------------------------------------- |
| 1             | 2026-01-10 | Initial schema version (Issue #108)                                        |
| 2             | 2026-01-12 | Added `testValidityWarning` field to TestValidityWarningEvent (Issue #134) |

**Consumer Guidance:**

```typescript
// Example: Check schema version before parsing
const event = JSON.parse(line);
if (event.schemaVersion === 1) {
  // Current schema - parse normally
} else if (event.schemaVersion > 1) {
  // Newer schema - may have additional fields, but should be backwards compatible
  console.warn(
    `Unknown schema version ${event.schemaVersion}, parsing with best effort`,
  );
}
```

---

## BaseEvent Interface

All 13 JSONL events extend a common `BaseEvent` interface that provides versioning fields:

```typescript
export interface BaseEvent {
  /** Inspector software version (e.g., "1.29.0") */
  version: string;
  /** Event schema version (integer, increment when structure changes) */
  schemaVersion: number;
}
```

**Single Source of Truth:**

The `SCHEMA_VERSION` constant (currently `2`) is defined in `/client/src/lib/moduleScoring.ts` and imported by:

- `scripts/lib/jsonl-events.ts` - CLI event emission
- `cli/src/lib/jsonl-events.ts` - CLI interface helpers
- `client/src/services/assessment/orchestratorHelpers.ts` - Assessment orchestration

This ensures all event emitters use the same schema version, enabling version bumping from a single location.

**All Event Interfaces Extend BaseEvent:**

- ServerConnectedEvent, ToolDiscoveredEvent, ToolsDiscoveryCompleteEvent
- AssessmentCompleteEvent, ModuleStartedEvent, TestBatchEvent
- ModuleCompleteEvent, VulnerabilityFoundEvent
- AnnotationMissingEvent, AnnotationMisalignedEvent
- AnnotationReviewRecommendedEvent, AnnotationAlignedEvent

---

## Zod Runtime Validation

The Inspector provides Zod schemas for runtime validation of JSONL events. This enables type-safe parsing of event streams in TypeScript consumers.

### Installation

The schemas are exported from the `@bryan-thompson/inspector-assessment` package:

```typescript
import {
  JSONLEventSchema,
  parseEvent,
  safeParseEvent,
  validateEvent,
  isEventType,
  parseEventLines,
  type JSONLEventParsed,
} from "@bryan-thompson/inspector-assessment/lib/assessment/jsonlEventSchemas";
```

### Quick Start

```typescript
// Parse a single event line
const line =
  '{"event":"server_connected","serverName":"my-server","transport":"http","version":"1.29.0","schemaVersion":1}';

// Safe parsing (recommended)
const result = safeParseEvent(line);
if (result.success) {
  const event = result.data;
  if (isEventType(event, "server_connected")) {
    console.log(`Connected to ${event.serverName} via ${event.transport}`);
  }
} else {
  console.error("Invalid event:", result.error.message);
}

// Throwing parse (for known-good input)
try {
  const event = parseEvent(line);
  console.log(event.event);
} catch (e) {
  console.error("Parse failed:", e);
}
```

### Available Schemas

| Schema                                   | Description                                    |
| ---------------------------------------- | ---------------------------------------------- |
| `BaseEventSchema`                        | Common version fields (version, schemaVersion) |
| `ServerConnectedEventSchema`             | Server connection event                        |
| `ToolDiscoveredEventSchema`              | Tool discovery event                           |
| `ToolsDiscoveryCompleteEventSchema`      | Discovery completion                           |
| `ModulesConfiguredEventSchema`           | Module configuration                           |
| `ModuleStartedEventSchema`               | Module start                                   |
| `TestBatchEventSchema`                   | Progress batch                                 |
| `ModuleCompleteEventSchema`              | Module completion (with AUP enrichment)        |
| `VulnerabilityFoundEventSchema`          | Security vulnerability                         |
| `AnnotationMissingEventSchema`           | Missing annotation                             |
| `AnnotationMisalignedEventSchema`        | Misaligned annotation                          |
| `AnnotationReviewRecommendedEventSchema` | Review recommendation                          |
| `AnnotationAlignedEventSchema`           | Aligned annotation                             |
| `AssessmentCompleteEventSchema`          | Assessment completion                          |
| `JSONLEventSchema`                       | Union of all event types                       |

### Helper Functions

| Function                   | Description                               |
| -------------------------- | ----------------------------------------- |
| `parseEvent(input)`        | Parse and validate, throws on error       |
| `safeParseEvent(input)`    | Parse and validate, returns result object |
| `validateEvent(input)`     | Returns array of error messages           |
| `isEventType(event, type)` | Type guard for specific event types       |
| `parseEventLines(lines)`   | Batch parse with line numbers             |

### Type Inference

Types are automatically inferred from schemas:

```typescript
import type { JSONLEventParsed } from "@bryan-thompson/inspector-assessment/lib/assessment/jsonlEventSchemas";

// JSONLEventParsed is the union type of all 13 events
function handleEvent(event: JSONLEventParsed) {
  switch (event.event) {
    case "server_connected":
      // event is narrowed to ServerConnectedEvent
      console.log(event.serverName);
      break;
    case "vulnerability_found":
      // event is narrowed to VulnerabilityFoundEvent
      console.log(event.riskLevel);
      break;
  }
}
```

### Batch Processing Example

```typescript
import { parseEventLines } from "@bryan-thompson/inspector-assessment/lib/assessment/jsonlEventSchemas";

// Process stderr output from assessment CLI
const lines = stderrOutput.split("\n").filter((line) => line.trim());
const results = parseEventLines(lines);

for (const { line, result } of results) {
  if (!result.success) {
    console.error(`Line ${line}: Parse error - ${result.error.message}`);
    continue;
  }
  // result.data is typed as JSONLEventParsed
  processEvent(result.data);
}
```

### Source Files

- **Schema definitions**: `client/src/lib/assessment/jsonlEventSchemas.ts`
- **Tests**: `client/src/lib/assessment/__tests__/jsonlEventSchemas.test.ts`
- **TypeScript interfaces**: `scripts/lib/jsonl-events.ts`

---

## Table of Contents

- [Overview](#overview)
- [Schema Versioning](#schema-versioning)
- [BaseEvent Interface](#baseevent-interface)
- [Event Timeline](#event-timeline)
- [Event Reference](#event-reference)
  - [1. server_connected](#1-server_connected)
  - [2. tool_discovered](#2-tool_discovered)
  - [3. tools_discovery_complete](#3-tools_discovery_complete)
  - [4. phase_started](#4-phase_started)
  - [5. phase_complete](#5-phase_complete)
  - [6. module_started](#6-module_started)
  - [7. test_batch](#7-test_batch)
  - [8. tool_test_complete](#8-tool_test_complete)
  - [9. validation_summary](#9-validation_summary)
  - [10. vulnerability_found](#10-vulnerability_found)
  - [11. annotation_missing](#11-annotation_missing)
  - [12. annotation_misaligned](#12-annotation_misaligned)
  - [13. annotation_review_recommended](#13-annotation_review_recommended)
  - [14. annotation_aligned](#14-annotation_aligned)
  - [15. modules_configured](#15-modules_configured)
  - [16. module_complete](#16-module_complete)
  - [17. assessment_complete](#17-assessment_complete)

---

## Event Timeline

Assessment events flow in this sequence:

```
server_connected                   (1 event)
  ↓
phase_started (phase="discovery")  (1 event)
  ↓
tool_discovered                    (N events, 1 per tool)
  ↓
tools_discovery_complete           (1 event)
  ↓
phase_complete (phase="discovery") (1 event)
  ↓
modules_configured                 (1 event, if --skip-modules or --only-modules used)
  ↓
phase_started (phase="assessment") (1 event)
  ↓
[For each module:]
  module_started                   (1 event)
    ↓
  [During execution:]
    test_batch*                    (M events, every 500ms or 10 tests)
    [For each tool:]
      tool_test_complete*          (per-tool summary after all tests)
      validation_summary*          (per-tool input validation metrics)
    vulnerability_found*           (real-time as detected)
    annotation_missing*            (real-time as detected)
    annotation_misaligned*         (real-time as detected)
    annotation_review_recommended* (real-time as detected)
    annotation_aligned*            (real-time as detected)
    ↓
  module_complete                  (1 event, with AUP enrichment if module=aup)
  ↓
phase_complete (phase="assessment")(1 event)
  ↓
assessment_complete                (1 event)
```

_\* = Optional, only emitted if conditions are met_

---

## Event Reference

### 1. `server_connected`

**When**: Immediately after establishing MCP connection

**Purpose**: Signals successful server connection, provides transport details

```json
{
  "event": "server_connected",
  "serverName": "memory-mcp",
  "transport": "http",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type                             | Required | Description                                   |
| --------------- | -------------------------------- | -------- | --------------------------------------------- |
| `serverName`    | string                           | Yes      | Name of MCP server being assessed             |
| `transport`     | `"stdio"` \| `"http"` \| `"sse"` | Yes      | Connection transport type                     |
| `version`       | string                           | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                          | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface ServerConnectedEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
  version: string;
  schemaVersion: number;
}
```

---

### 2. `tool_discovered`

**When**: For each tool found during discovery phase

**Purpose**: Reports tool metadata (name, description, parameters, annotations)

```json
{
  "event": "tool_discovered",
  "name": "add_memory",
  "description": "Store a memory in persistent storage",
  "params": [
    {
      "name": "content",
      "type": "string",
      "required": true,
      "description": "The memory content to store"
    }
  ],
  "annotations": {
    "readOnlyHint": false,
    "destructiveHint": false
  },
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Example without annotations:**

```json
{
  "event": "tool_discovered",
  "name": "legacy_tool",
  "description": "A legacy tool without annotations",
  "params": [],
  "annotations": null,
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type           | Required | Description                                             |
| --------------- | -------------- | -------- | ------------------------------------------------------- |
| `name`          | string         | Yes      | Tool name from MCP manifest                             |
| `description`   | string \| null | Yes      | Tool description or null if missing                     |
| `params`        | array          | Yes      | Extracted parameters from inputSchema                   |
| `annotations`   | object \| null | Yes      | Tool annotations or null if server doesn't provide them |
| `version`       | string         | Yes      | Inspector version (auto-added)                          |
| `schemaVersion` | integer        | Yes      | Event schema version (auto-added, current: 1)           |

**Param Object Fields:**

| Field         | Type    | Required | Description                                  |
| ------------- | ------- | -------- | -------------------------------------------- |
| `name`        | string  | Yes      | Parameter name from inputSchema.properties   |
| `type`        | string  | Yes      | Parameter type (e.g., "string", "object")    |
| `required`    | boolean | Yes      | Whether parameter is in inputSchema.required |
| `description` | string  | No       | Parameter description if provided            |

**Annotations Object Fields:**

| Field             | Type    | Required | Description                                                   |
| ----------------- | ------- | -------- | ------------------------------------------------------------- |
| `readOnlyHint`    | boolean | No       | If true, tool does not modify environment (default: false)    |
| `destructiveHint` | boolean | No       | If true, tool may perform destructive updates (default: true) |
| `idempotentHint`  | boolean | No       | If true, repeated identical calls have same effect            |
| `openWorldHint`   | boolean | No       | If true, tool may interact with external systems              |

**TypeScript Interface:**

```typescript
interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

interface ToolDiscoveredEvent {
  event: "tool_discovered";
  name: string;
  description: string | null;
  params: ToolParam[];
  annotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  } | null;
  version: string;
  schemaVersion: number;
}
```

---

### 3. `tools_discovery_complete`

**When**: After all tools have been enumerated

**Purpose**: Signals end of discovery phase, provides total tool count

```json
{
  "event": "tools_discovery_complete",
  "count": 17,
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type    | Required | Description                                   |
| --------------- | ------- | -------- | --------------------------------------------- |
| `count`         | number  | Yes      | Total number of tools discovered              |
| `version`       | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface ToolsDiscoveryCompleteEvent {
  event: "tools_discovery_complete";
  count: number;
  version: string;
  schemaVersion: number;
}
```

---

### 4. `phase_started`

**When**: At the beginning of each major assessment phase (discovery, assessment, analysis)

**Purpose**: Signals the start of a high-level assessment phase for progress tracking

```json
{
  "event": "phase_started",
  "phase": "discovery",
  "version": "1.24.2",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type    | Required | Description                                   |
| --------------- | ------- | -------- | --------------------------------------------- |
| `phase`         | string  | Yes      | Phase name (e.g., "discovery", "assessment")  |
| `version`       | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer | Yes      | Event schema version (auto-added, current: 1) |

**Common Phase Values:**

- `"discovery"` - Tool discovery phase
- `"assessment"` - Module execution phase
- `"analysis"` - Post-processing phase (if applicable)

**TypeScript Interface:**

```typescript
interface PhaseStartedEvent {
  event: "phase_started";
  phase: string;
  version: string;
  schemaVersion: number;
}
```

---

### 5. `phase_complete`

**When**: After each major assessment phase finishes

**Purpose**: Signals the completion of a high-level assessment phase with duration metrics

```json
{
  "event": "phase_complete",
  "phase": "discovery",
  "duration": 1234,
  "version": "1.24.2",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type    | Required | Description                                   |
| --------------- | ------- | -------- | --------------------------------------------- |
| `phase`         | string  | Yes      | Phase name (e.g., "discovery", "assessment")  |
| `duration`      | number  | Yes      | Phase execution time in milliseconds          |
| `version`       | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface PhaseCompleteEvent {
  event: "phase_complete";
  phase: string;
  duration: number;
  version: string;
  schemaVersion: number;
}
```

---

### 6. `module_started`

**When**: Before each assessment module begins execution

**Purpose**: Signals module start, provides test count estimate

```json
{
  "event": "module_started",
  "module": "security",
  "estimatedTests": 240,
  "toolCount": 17,
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field            | Type    | Required | Description                                   |
| ---------------- | ------- | -------- | --------------------------------------------- |
| `module`         | string  | Yes      | Module name in snake_case                     |
| `estimatedTests` | number  | Yes      | Estimated test count for module               |
| `toolCount`      | number  | Yes      | Number of tools to be tested                  |
| `version`        | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion`  | integer | Yes      | Event schema version (auto-added, current: 1) |

**Module Names:**

**Core modules (5):**

- `functionality` - Tool invocation and response handling
- `security` - Vulnerability detection and injection testing
- `documentation` - Description quality and completeness
- `error_handling` - MCP protocol compliance and error responses
- `usability` - Tool naming, parameter clarity

**Extended modules (6):**

- `mcp_spec` - MCP specification compliance
- `aup` - Acceptable Use Policy violations
- `annotations` - Tool annotation status (readOnlyHint, destructiveHint)
- `libraries` - Dependency security scanning
- `manifest` - Tool manifest validation
- `portability` - Cross-environment compatibility

**TypeScript Interface:**

```typescript
interface ModuleStartedEvent {
  event: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
  version: string;
  schemaVersion: number;
}
```

---

### 7. `test_batch`

**When**: During module execution, every 500ms or after 10 tests (whichever comes first)

**Purpose**: Real-time progress reporting with completion percentage

```json
{
  "event": "test_batch",
  "module": "security",
  "completed": 45,
  "total": 240,
  "batchSize": 10,
  "elapsed": 2450,
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type    | Required | Description                                   |
| --------------- | ------- | -------- | --------------------------------------------- |
| `module`        | string  | Yes      | Module name (normalized to snake_case)        |
| `completed`     | number  | Yes      | Number of tests completed so far              |
| `total`         | number  | Yes      | Total tests for module (may update)           |
| `batchSize`     | number  | Yes      | Number of tests in this batch                 |
| `elapsed`       | number  | Yes      | Milliseconds elapsed since module started     |
| `version`       | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer | Yes      | Event schema version (auto-added, current: 1) |

**Calculation Examples:**

```
Progress % = (completed / total) * 100
ETA ms = (elapsed / completed) * (total - completed)

Example: completed=45, total=240, elapsed=2450
  Progress = (45/240)*100 = 18.75%
  ETA = (2450/45) * (240-45) = 10,611 ms remaining
```

**TypeScript Interface:**

```typescript
interface TestBatchEvent {
  event: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
  version: string;
  schemaVersion: number;
}
```

---

### 8. `tool_test_complete`

**When**: After all tests for a single tool complete (per module)

**Purpose**: Provides per-tool summary for real-time progress in auditor UI

```json
{
  "event": "tool_test_complete",
  "tool": "add_memory",
  "module": "functionality",
  "scenariosPassed": 8,
  "scenariosExecuted": 10,
  "confidence": "high",
  "status": "PASS",
  "executionTime": 245,
  "version": "1.24.2",
  "schemaVersion": 1
}
```

**Fields:**

| Field               | Type                              | Required | Description                                   |
| ------------------- | --------------------------------- | -------- | --------------------------------------------- |
| `tool`              | string                            | Yes      | Tool name that was tested                     |
| `module`            | string                            | Yes      | Module name that performed the tests          |
| `scenariosPassed`   | number                            | Yes      | Number of test scenarios that passed          |
| `scenariosExecuted` | number                            | Yes      | Total number of test scenarios executed       |
| `confidence`        | `"high"` \| `"medium"` \| `"low"` | Yes      | Confidence level of the test results          |
| `status`            | `"PASS"` \| `"FAIL"` \| `"ERROR"` | Yes      | Overall status for this tool in this module   |
| `executionTime`     | number                            | Yes      | Time taken to test this tool (milliseconds)   |
| `version`           | string                            | Yes      | Inspector version (auto-added)                |
| `schemaVersion`     | integer                           | Yes      | Event schema version (auto-added, current: 1) |

**Status Values:**

- `"PASS"` - Tool passed all or most tests
- `"FAIL"` - Tool failed tests or exhibited problematic behavior
- `"ERROR"` - Tool encountered errors during testing (e.g., connection issues)

**TypeScript Interface:**

```typescript
interface ToolTestCompleteEvent {
  event: "tool_test_complete";
  tool: string;
  module: string;
  scenariosPassed: number;
  scenariosExecuted: number;
  confidence: "high" | "medium" | "low";
  status: "PASS" | "FAIL" | "ERROR";
  executionTime: number;
  version: string;
  schemaVersion: number;
}
```

---

### 9. `validation_summary`

**When**: After input validation testing completes for a tool

**Purpose**: Tracks how tools handle invalid inputs (wrong types, missing required params, etc.)

```json
{
  "event": "validation_summary",
  "tool": "add_memory",
  "wrongType": 2,
  "missingRequired": 1,
  "extraParams": 0,
  "nullValues": 1,
  "invalidValues": 3,
  "version": "1.24.2",
  "schemaVersion": 1
}
```

**Fields:**

| Field             | Type    | Required | Description                                            |
| ----------------- | ------- | -------- | ------------------------------------------------------ |
| `tool`            | string  | Yes      | Tool name that was tested                              |
| `wrongType`       | number  | Yes      | Count of wrong type parameter tests                    |
| `missingRequired` | number  | Yes      | Count of missing required parameter tests              |
| `extraParams`     | number  | Yes      | Count of extra/unexpected parameter tests              |
| `nullValues`      | number  | Yes      | Count of null value tests                              |
| `invalidValues`   | number  | Yes      | Count of invalid value tests (malformed, out of range) |
| `version`         | string  | Yes      | Inspector version (auto-added)                         |
| `schemaVersion`   | integer | Yes      | Event schema version (auto-added, current: 1)          |

**Usage:**

This event helps identify tools with poor input validation. High counts indicate the tool doesn't properly reject invalid inputs, which can lead to security issues or unexpected behavior.

**TypeScript Interface:**

```typescript
interface ValidationSummaryEvent {
  event: "validation_summary";
  tool: string;
  wrongType: number;
  missingRequired: number;
  extraParams: number;
  nullValues: number;
  invalidValues: number;
  version: string;
  schemaVersion: number;
}
```

---

### 10. `vulnerability_found`

**When**: Real-time during security assessment, as vulnerabilities are detected

**Purpose**: Instant security alert with pattern details and risk level

```json
{
  "event": "vulnerability_found",
  "version": "1.26.7",
  "schemaVersion": 1,
  "tool": "system_exec_tool",
  "pattern": "Command Injection",
  "confidence": "high",
  "evidence": "Tool accepts arbitrary shell commands and executes them without sanitization",
  "riskLevel": "HIGH",
  "requiresReview": true,
  "payload": "'; rm -rf / #"
}
```

**Fields:**

| Field            | Type                              | Required | Description                                       |
| ---------------- | --------------------------------- | -------- | ------------------------------------------------- |
| `tool`           | string                            | Yes      | Tool name where vulnerability was detected        |
| `pattern`        | string                            | Yes      | Attack pattern name (e.g., "Command Injection")   |
| `confidence`     | `"high"` \| `"medium"` \| `"low"` | Yes      | Detection confidence level                        |
| `evidence`       | string                            | Yes      | Explanation of why this is vulnerable             |
| `riskLevel`      | `"HIGH"` \| `"MEDIUM"` \| `"LOW"` | Yes      | Security risk severity                            |
| `requiresReview` | boolean                           | Yes      | Whether human review is recommended               |
| `payload`        | string                            | No       | The test payload that triggered the vulnerability |
| `version`        | string                            | Yes      | Inspector version (auto-added)                    |
| `schemaVersion`  | integer                           | Yes      | Event schema version (auto-added, current: 1)     |

**TypeScript Interface:**

```typescript
interface VulnerabilityFoundEvent {
  event: "vulnerability_found";
  version: string;
  schemaVersion: number;
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string;
}
```

---

### 11. `annotation_missing`

**When**: During annotations module assessment, when tool lacks required annotations

**Purpose**: Real-time alert that tool is missing safety annotations

```json
{
  "event": "annotation_missing",
  "tool": "file_write_tool",
  "title": "Write File",
  "description": "Write arbitrary content to filesystem",
  "parameters": [
    {
      "name": "path",
      "type": "string",
      "required": true,
      "description": "File path to write to"
    }
  ],
  "inferredBehavior": {
    "expectedReadOnly": false,
    "expectedDestructive": true,
    "reason": "Tool modifies filesystem with write_* pattern and content parameter"
  },
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field              | Type    | Required | Description                                   |
| ------------------ | ------- | -------- | --------------------------------------------- |
| `tool`             | string  | Yes      | Tool name                                     |
| `title`            | string  | No       | Tool title if available                       |
| `description`      | string  | No       | Tool description if available                 |
| `parameters`       | array   | Yes      | Tool parameters (ToolParam[])                 |
| `inferredBehavior` | object  | Yes      | Behavior inference from code analysis         |
| `version`          | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion`    | integer | Yes      | Event schema version (auto-added, current: 1) |

**InferredBehavior Fields:**

| Field                 | Type    | Description                                   |
| --------------------- | ------- | --------------------------------------------- |
| `expectedReadOnly`    | boolean | Expected read-only status based on tool name  |
| `expectedDestructive` | boolean | Expected destructive status based on patterns |
| `reason`              | string  | Human-readable explanation of inference       |

**TypeScript Interface:**

```typescript
interface InferredBehavior {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
}

interface AnnotationMissingEvent {
  event: "annotation_missing";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParam[];
  inferredBehavior: InferredBehavior;
  version: string;
  schemaVersion: number;
}
```

---

### 12. `annotation_misaligned`

**When**: During annotations module assessment, when annotations contradict inferred behavior

**Purpose**: Alert that tool's annotations don't match actual behavior

```json
{
  "event": "annotation_misaligned",
  "tool": "memory_delete_tool",
  "title": "Delete Memory",
  "description": "Remove a memory from storage",
  "parameters": [
    {
      "name": "id",
      "type": "string",
      "required": true,
      "description": "Memory ID to delete"
    }
  ],
  "field": "destructiveHint",
  "actual": false,
  "expected": true,
  "confidence": 0.95,
  "reason": "Tool name contains 'delete' and accepts ID parameter. Tool description mentions 'remove'. Inference confidence 95%.",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type                                    | Required | Description                                   |
| --------------- | --------------------------------------- | -------- | --------------------------------------------- |
| `tool`          | string                                  | Yes      | Tool name                                     |
| `title`         | string                                  | No       | Tool title if available                       |
| `description`   | string                                  | No       | Tool description if available                 |
| `parameters`    | array                                   | Yes      | Tool parameters (ToolParam[])                 |
| `field`         | `"readOnlyHint"` \| `"destructiveHint"` | Yes      | Which annotation field is misaligned          |
| `actual`        | boolean \| undefined                    | Yes      | Current annotation value (or undefined)       |
| `expected`      | boolean                                 | Yes      | Expected value based on behavior inference    |
| `confidence`    | number                                  | Yes      | Confidence of inference (0-1)                 |
| `reason`        | string                                  | Yes      | Explanation of the mismatch                   |
| `version`       | string                                  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                                 | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface AnnotationMisalignedEvent {
  event: "annotation_misaligned";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParam[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  expected: boolean;
  confidence: number;
  reason: string;
  version: string;
  schemaVersion: number;
}
```

---

### 13. `annotation_review_recommended`

**When**: During annotations module assessment, for ambiguous annotation patterns

**Purpose**: Flag patterns for human review (e.g., `store_*`, `cache_*`) where behavior varies

**Important**: This does NOT indicate a failure. It's a suggestion for human verification.

```json
{
  "event": "annotation_review_recommended",
  "tool": "cache_results",
  "title": "Cache Results",
  "description": "Store computation results in memory cache",
  "parameters": [
    {
      "name": "key",
      "type": "string",
      "required": true
    }
  ],
  "field": "destructiveHint",
  "actual": false,
  "inferred": true,
  "confidence": "medium",
  "isAmbiguous": true,
  "reason": "Pattern 'cache_*' is ambiguous. Could be read-only (cache lookup) or destructive (cache invalidation). Recommend human review of implementation.",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type                                    | Required | Description                                   |
| --------------- | --------------------------------------- | -------- | --------------------------------------------- |
| `tool`          | string                                  | Yes      | Tool name                                     |
| `title`         | string                                  | No       | Tool title if available                       |
| `description`   | string                                  | No       | Tool description if available                 |
| `parameters`    | array                                   | Yes      | Tool parameters (ToolParam[])                 |
| `field`         | `"readOnlyHint"` \| `"destructiveHint"` | Yes      | Which annotation field needs review           |
| `actual`        | boolean \| undefined                    | Yes      | Current annotation value (or undefined)       |
| `inferred`      | boolean                                 | Yes      | Inferred value (but marked as ambiguous)      |
| `confidence`    | `"high"` \| `"medium"` \| `"low"`       | Yes      | Confidence of inference                       |
| `isAmbiguous`   | boolean                                 | Yes      | Flag indicating ambiguous pattern detected    |
| `reason`        | string                                  | Yes      | Explanation and recommendation                |
| `version`       | string                                  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                                 | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface AnnotationReviewRecommendedEvent {
  event: "annotation_review_recommended";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParam[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  inferred: boolean;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
  reason: string;
  version: string;
  schemaVersion: number;
}
```

---

### 14. `annotation_aligned`

**When**: During annotations module assessment, when tool has annotations that match inferred behavior

**Purpose**: Real-time confirmation that tool has proper safety annotations

```json
{
  "event": "annotation_aligned",
  "tool": "reset_testbed_state",
  "confidence": "high",
  "annotations": {
    "readOnlyHint": false,
    "destructiveHint": true
  },
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type                              | Required | Description                                   |
| --------------- | --------------------------------- | -------- | --------------------------------------------- |
| `tool`          | string                            | Yes      | Tool name                                     |
| `confidence`    | `"high"` \| `"medium"` \| `"low"` | Yes      | Confidence of behavior inference              |
| `annotations`   | object                            | Yes      | The actual annotation values from the tool    |
| `version`       | string                            | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                           | Yes      | Event schema version (auto-added, current: 1) |

**Annotations Object Fields:**

| Field             | Type    | Required | Description                                                   |
| ----------------- | ------- | -------- | ------------------------------------------------------------- |
| `readOnlyHint`    | boolean | No       | If true, tool does not modify environment (default: false)    |
| `destructiveHint` | boolean | No       | If true, tool may perform destructive updates (default: true) |
| `idempotentHint`  | boolean | No       | If true, repeated identical calls have same effect            |
| `openWorldHint`   | boolean | No       | If true, tool may interact with external systems              |

**TypeScript Interface:**

```typescript
interface AnnotationAlignedEvent {
  event: "annotation_aligned";
  tool: string;
  confidence: "high" | "medium" | "low";
  annotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    openWorldHint?: boolean;
    idempotentHint?: boolean;
  };
  version: string;
  schemaVersion: number;
}
```

**Difference from other annotation events:**

| Event                           | Condition                                          |
| ------------------------------- | -------------------------------------------------- |
| `annotation_missing`            | Tool has NO annotations                            |
| `annotation_misaligned`         | Tool HAS annotations but they contradict inference |
| `annotation_aligned`            | Tool HAS annotations AND they match inference      |
| `annotation_review_recommended` | Ambiguous pattern detected, human review suggested |

---

### 15. `modules_configured`

**When**: After tools discovery, before module execution begins (only when `--skip-modules` or `--only-modules` flags are used)

**Purpose**: Informs consumers which assessment modules are enabled/skipped for accurate progress tracking

```json
{
  "event": "modules_configured",
  "enabled": ["functionality", "toolAnnotations"],
  "skipped": [
    "security",
    "aupCompliance",
    "documentation",
    "errorHandling",
    "usability",
    "mcpSpecCompliance",
    "prohibitedLibraries",
    "manifestValidation",
    "portability",
    "temporal",
    "resources",
    "prompts",
    "crossCapability"
  ],
  "reason": "only-modules",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type                                                | Required | Description                                   |
| --------------- | --------------------------------------------------- | -------- | --------------------------------------------- |
| `enabled`       | string[]                                            | Yes      | List of module names that will run            |
| `skipped`       | string[]                                            | Yes      | List of module names that are disabled        |
| `reason`        | `"skip-modules"` \| `"only-modules"` \| `"default"` | Yes      | Why modules were configured this way          |
| `version`       | string                                              | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                                             | Yes      | Event schema version (auto-added, current: 1) |

**Valid Module Names (18 total):**

- **Core (16):** `functionality`, `security`, `documentation`, `errorHandling`, `usability`, `mcpSpecCompliance`, `aupCompliance`, `toolAnnotations`, `prohibitedLibraries`, `externalAPIScanner`, `authentication`, `temporal`, `resources`, `prompts`, `crossCapability`, `protocolConformance`
- **Optional (2):** `manifestValidation`, `portability`

**Example Scenarios:**

**Default (all modules enabled):**

```json
{
  "event": "modules_configured",
  "enabled": [
    "functionality",
    "security",
    "documentation",
    "errorHandling",
    "usability",
    "mcpSpecCompliance",
    "aupCompliance",
    "toolAnnotations",
    "prohibitedLibraries",
    "manifestValidation",
    "portability",
    "temporal",
    "resources",
    "prompts",
    "crossCapability"
  ],
  "skipped": [],
  "reason": "default",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Using `--skip-modules security,aupCompliance`:**

```json
{
  "event": "modules_configured",
  "enabled": [
    "functionality",
    "documentation",
    "errorHandling",
    "usability",
    "mcpSpecCompliance",
    "toolAnnotations",
    "prohibitedLibraries",
    "manifestValidation",
    "portability",
    "temporal",
    "resources",
    "prompts",
    "crossCapability"
  ],
  "skipped": ["security", "aupCompliance"],
  "reason": "skip-modules",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Using `--only-modules functionality,toolAnnotations`:**

```json
{
  "event": "modules_configured",
  "enabled": ["functionality", "toolAnnotations"],
  "skipped": [
    "security",
    "documentation",
    "errorHandling",
    "usability",
    "mcpSpecCompliance",
    "aupCompliance",
    "prohibitedLibraries",
    "manifestValidation",
    "portability",
    "temporal",
    "resources",
    "prompts",
    "crossCapability"
  ],
  "reason": "only-modules",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**TypeScript Interface:**

```typescript
interface ModulesConfiguredEvent {
  event: "modules_configured";
  enabled: string[];
  skipped: string[];
  reason: "skip-modules" | "only-modules" | "default";
  version: string;
  schemaVersion: number;
}
```

**Integration Note:** This event is useful for MCP Auditor and other consumers to calculate accurate progress percentages. When modules are skipped, the total expected `module_started`/`module_complete` events will be fewer than the full module count.

---

### 16. `module_complete`

**When**: After each assessment module finishes execution

**Purpose**: Summary with status, score, and test count; includes AUP enrichment when module=aup

**Basic Format (all modules):**

```json
{
  "event": "module_complete",
  "module": "functionality",
  "status": "PASS",
  "score": 95,
  "testsRun": 234,
  "duration": 5234,
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**AUP Module Format (aup module only):**

```json
{
  "event": "module_complete",
  "module": "aup",
  "status": "FAIL",
  "score": 60,
  "testsRun": 15,
  "duration": 3500,
  "version": "1.26.7",
  "schemaVersion": 1,
  "violationsSample": [
    {
      "category": "B",
      "categoryName": "Child Safety",
      "severity": "CRITICAL",
      "matchedText": "generate_csam",
      "location": "tool_name",
      "confidence": "high"
    }
  ],
  "samplingNote": "Sampled 5 of 12 violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).",
  "violationMetrics": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 5,
    "byCategory": { "B": 2, "E": 5, "G": 5 }
  },
  "scannedLocations": {
    "toolNames": true,
    "toolDescriptions": true,
    "readme": true,
    "sourceCode": false
  },
  "highRiskDomains": ["weapons", "financial", "illegal"]
}
```

**Fields (All Modules):**

| Field           | Type                                       | Required | Description                                   |
| --------------- | ------------------------------------------ | -------- | --------------------------------------------- |
| `module`        | string                                     | Yes      | Module name (snake_case)                      |
| `status`        | `"PASS"` \| `"FAIL"` \| `"NEED_MORE_INFO"` | Yes      | Module result status                          |
| `score`         | number                                     | Yes      | Score 0-100                                   |
| `testsRun`      | number                                     | Yes      | Number of tests executed                      |
| `duration`      | number                                     | Yes      | Execution time in milliseconds                |
| `version`       | string                                     | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer                                    | Yes      | Event schema version (auto-added, current: 1) |

**Fields (AUP Module Only):**

| Field              | Type   | Required | Description                                                                          |
| ------------------ | ------ | -------- | ------------------------------------------------------------------------------------ |
| `violationsSample` | array  | Yes      | Up to 10 violations, priority-sampled by severity                                    |
| `samplingNote`     | string | Yes      | Description of sampling methodology                                                  |
| `violationMetrics` | object | Yes      | Quantitative metrics: total, critical, high, medium                                  |
| `scannedLocations` | object | Yes      | Boolean flags for each scanned location                                              |
| `highRiskDomains`  | array  | Yes      | Up to 10 detected high-risk domains                                                  |
| `toolInventory`    | array  | No       | **(Issue #194)** Up to 50 tools with inferred capabilities for Claude validation     |
| `patternCoverage`  | object | No       | **(Issue #194)** Metadata about AUP patterns checked (150+ patterns, categories A-N) |
| `flagsForReview`   | array  | No       | **(Issue #194)** Tools with sensitive capabilities flagged for review                |

**AUP Categories (A-N):**

- A: Illegal Activity
- B: Child Safety
- C: Harassment
- D: Hate Speech
- E: Fraud
- F: Sexual Content
- G: Malware/Spyware
- H: Physical Safety
- I: GPT-4 Class
- J: Economic Harm
- K: Medical
- L: High-Risk Government
- M: Tailored Advice
- N: Privacy Violations

**Score Calculation by Module Type:**

| Module           | Score Source                 | Formula                              |
| ---------------- | ---------------------------- | ------------------------------------ |
| `functionality`  | `coveragePercentage`         | Direct percentage of working tools   |
| `error_handling` | `metrics.mcpComplianceScore` | MCP compliance percentage            |
| `mcp_spec`       | `complianceScore`            | Direct compliance score              |
| `security`       | `vulnerabilities[]`          | `100 - (vulnCount * 10)`, min 0      |
| `aup`            | `violations[]`               | `100 - (violationCount * 10)`, min 0 |
| All others       | Status-based                 | PASS=100, FAIL=0, NEED_MORE_INFO=50  |

**TypeScript Interface:**

```typescript
interface AUPViolationSample {
  category: string;
  categoryName: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  matchedText: string;
  location: "tool_name" | "tool_description" | "readme" | "source_code";
  confidence: "high" | "medium" | "low";
}

interface AUPViolationMetrics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  byCategory: Record<string, number>;
}

// Issue #194: Tool context enrichment for Claude validation
interface ToolInventoryItem {
  name: string;
  description: string; // Truncated to 300 chars
  capabilities: ToolCapability[]; // Inferred from name/description
}

type ToolCapability =
  | "file_system" // File read/write operations
  | "network" // HTTP, API calls, sockets
  | "exec" // Command/process execution
  | "database" // Database queries/storage
  | "auth" // Authentication/credential handling
  | "crypto" // Cryptographic operations
  | "system" // System-level access
  | "unknown"; // Cannot determine

interface PatternCoverageInfo {
  totalPatterns: number; // Total AUP patterns checked (150+)
  categoriesCovered: string[]; // AUP categories A-N
  samplePatterns: string[]; // 3-5 sample patterns for transparency
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    flag: number;
  };
}

interface FlagForReview {
  toolName: string;
  reason: string; // e.g., "Command/code execution capabilities - high risk"
  capabilities: string[]; // Sensitive capabilities detected
  confidence: "low"; // Always low for capability-based flags
}

interface ModuleCompleteEvent {
  event: "module_complete";
  module: string;
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  score: number;
  testsRun: number;
  duration: number;
  version: string;
  schemaVersion: number;
  // AUP module only:
  violationsSample?: AUPViolationSample[];
  samplingNote?: string;
  violationMetrics?: AUPViolationMetrics;
  scannedLocations?: {
    toolNames: boolean;
    toolDescriptions: boolean;
    readme: boolean;
    sourceCode: boolean;
  };
  highRiskDomains?: string[];
  // Issue #194: Tool context enrichment
  toolInventory?: ToolInventoryItem[]; // Up to 50 tools
  patternCoverage?: PatternCoverageInfo;
  flagsForReview?: FlagForReview[];
}
```

---

### 17. `assessment_complete`

**When**: After all modules have completed and assessment finishes

**Purpose**: Final summary with overall status and total test count

```json
{
  "event": "assessment_complete",
  "overallStatus": "FAIL",
  "totalTests": 1440,
  "executionTime": 47823,
  "outputPath": "/tmp/inspector-full-assessment-memory-mcp.json",
  "version": "1.26.7",
  "schemaVersion": 1
}
```

**Fields:**

| Field           | Type    | Required | Description                                   |
| --------------- | ------- | -------- | --------------------------------------------- |
| `overallStatus` | string  | Yes      | `"PASS"` or `"FAIL"` (overall result)         |
| `totalTests`    | number  | Yes      | Sum of all tests across all modules           |
| `executionTime` | number  | Yes      | Total execution time in milliseconds          |
| `outputPath`    | string  | Yes      | Path to JSON results file for details         |
| `version`       | string  | Yes      | Inspector version (auto-added)                |
| `schemaVersion` | integer | Yes      | Event schema version (auto-added, current: 1) |

**TypeScript Interface:**

```typescript
interface AssessmentCompleteEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
  version: string;
  schemaVersion: number;
}
```

---

## Related Documentation

- [JSONL Events Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
- [JSONL Events Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - Complete assessment module reference

---

**Last Updated**: 2026-01-11
**Status**: Stable
