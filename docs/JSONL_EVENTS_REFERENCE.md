# JSONL Events Reference

> **Part of the JSONL Events API documentation series:**
>
> - **Reference** (this document) - All 13 event types and schema definitions
> - [Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
> - [Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing

**Version**: 1.23.8
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
- **EventBatcher** - controls progress event volume via intelligent batch size and time-based flushing

---

## Table of Contents

- [Overview](#overview)
- [Event Timeline](#event-timeline)
- [Event Reference](#event-reference)
  - [1. server_connected](#1-server_connected)
  - [2. tool_discovered](#2-tool_discovered)
  - [3. tools_discovery_complete](#3-tools_discovery_complete)
  - [4. module_started](#4-module_started)
  - [5. test_batch](#5-test_batch)
  - [6. vulnerability_found](#6-vulnerability_found)
  - [7. annotation_missing](#7-annotation_missing)
  - [8. annotation_misaligned](#8-annotation_misaligned)
  - [9. annotation_review_recommended](#9-annotation_review_recommended)
  - [10. annotation_aligned](#10-annotation_aligned)
  - [11. modules_configured](#11-modules_configured)
  - [12. module_complete](#12-module_complete)
  - [13. assessment_complete](#13-assessment_complete)

---

## Event Timeline

Assessment events flow in this sequence:

```
server_connected                   (1 event)
  ↓
tool_discovered                    (N events, 1 per tool)
  ↓
tools_discovery_complete           (1 event)
  ↓
modules_configured                 (1 event, if --skip-modules or --only-modules used)
  ↓
[For each module:]
  module_started                   (1 event)
    ↓
  [During execution:]
    test_batch*                    (M events, every 500ms or 10 tests)
    vulnerability_found*           (real-time as detected)
    annotation_missing*            (real-time as detected)
    annotation_misaligned*         (real-time as detected)
    annotation_review_recommended* (real-time as detected)
    annotation_aligned*            (real-time as detected)
    ↓
  module_complete                  (1 event, with AUP enrichment if module=aup)
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
  "version": "1.20.0"
}
```

**Fields:**

| Field        | Type                             | Required | Description                       |
| ------------ | -------------------------------- | -------- | --------------------------------- |
| `serverName` | string                           | Yes      | Name of MCP server being assessed |
| `transport`  | `"stdio"` \| `"http"` \| `"sse"` | Yes      | Connection transport type         |
| `version`    | string                           | Yes      | Inspector version (auto-added)    |

**TypeScript Interface:**

```typescript
interface ServerConnectedEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
  version: string;
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
  "version": "1.22.0"
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
  "version": "1.22.0"
}
```

**Fields:**

| Field         | Type           | Required | Description                                             |
| ------------- | -------------- | -------- | ------------------------------------------------------- |
| `name`        | string         | Yes      | Tool name from MCP manifest                             |
| `description` | string \| null | Yes      | Tool description or null if missing                     |
| `params`      | array          | Yes      | Extracted parameters from inputSchema                   |
| `annotations` | object \| null | Yes      | Tool annotations or null if server doesn't provide them |
| `version`     | string         | Yes      | Inspector version (auto-added)                          |

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
  "version": "1.20.0"
}
```

**Fields:**

| Field     | Type   | Required | Description                      |
| --------- | ------ | -------- | -------------------------------- |
| `count`   | number | Yes      | Total number of tools discovered |
| `version` | string | Yes      | Inspector version (auto-added)   |

**TypeScript Interface:**

```typescript
interface ToolsDiscoveryCompleteEvent {
  event: "tools_discovery_complete";
  count: number;
  version: string;
}
```

---

### 4. `module_started`

**When**: Before each assessment module begins execution

**Purpose**: Signals module start, provides test count estimate

```json
{
  "event": "module_started",
  "module": "security",
  "estimatedTests": 240,
  "toolCount": 17,
  "version": "1.20.0"
}
```

**Fields:**

| Field            | Type   | Required | Description                     |
| ---------------- | ------ | -------- | ------------------------------- |
| `module`         | string | Yes      | Module name in snake_case       |
| `estimatedTests` | number | Yes      | Estimated test count for module |
| `toolCount`      | number | Yes      | Number of tools to be tested    |
| `version`        | string | Yes      | Inspector version (auto-added)  |

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
}
```

---

### 5. `test_batch`

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
  "version": "1.20.0"
}
```

**Fields:**

| Field       | Type   | Required | Description                               |
| ----------- | ------ | -------- | ----------------------------------------- |
| `module`    | string | Yes      | Module name (normalized to snake_case)    |
| `completed` | number | Yes      | Number of tests completed so far          |
| `total`     | number | Yes      | Total tests for module (may update)       |
| `batchSize` | number | Yes      | Number of tests in this batch             |
| `elapsed`   | number | Yes      | Milliseconds elapsed since module started |
| `version`   | string | Yes      | Inspector version (auto-added)            |

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
}
```

---

### 6. `vulnerability_found`

**When**: Real-time during security assessment, as vulnerabilities are detected

**Purpose**: Instant security alert with pattern details and risk level

```json
{
  "event": "vulnerability_found",
  "version": "1.20.0",
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

**TypeScript Interface:**

```typescript
interface VulnerabilityFoundEvent {
  event: "vulnerability_found";
  version: string;
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

### 7. `annotation_missing`

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
  "version": "1.20.0"
}
```

**Fields:**

| Field              | Type   | Required | Description                           |
| ------------------ | ------ | -------- | ------------------------------------- |
| `tool`             | string | Yes      | Tool name                             |
| `title`            | string | No       | Tool title if available               |
| `description`      | string | No       | Tool description if available         |
| `parameters`       | array  | Yes      | Tool parameters (ToolParam[])         |
| `inferredBehavior` | object | Yes      | Behavior inference from code analysis |
| `version`          | string | Yes      | Inspector version (auto-added)        |

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
}
```

---

### 8. `annotation_misaligned`

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
  "version": "1.20.0"
}
```

**Fields:**

| Field         | Type                                    | Required | Description                                |
| ------------- | --------------------------------------- | -------- | ------------------------------------------ |
| `tool`        | string                                  | Yes      | Tool name                                  |
| `title`       | string                                  | No       | Tool title if available                    |
| `description` | string                                  | No       | Tool description if available              |
| `parameters`  | array                                   | Yes      | Tool parameters (ToolParam[])              |
| `field`       | `"readOnlyHint"` \| `"destructiveHint"` | Yes      | Which annotation field is misaligned       |
| `actual`      | boolean \| undefined                    | Yes      | Current annotation value (or undefined)    |
| `expected`    | boolean                                 | Yes      | Expected value based on behavior inference |
| `confidence`  | number                                  | Yes      | Confidence of inference (0-1)              |
| `reason`      | string                                  | Yes      | Explanation of the mismatch                |
| `version`     | string                                  | Yes      | Inspector version (auto-added)             |

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
}
```

---

### 9. `annotation_review_recommended`

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
  "version": "1.20.0"
}
```

**Fields:**

| Field         | Type                                    | Required | Description                                |
| ------------- | --------------------------------------- | -------- | ------------------------------------------ |
| `tool`        | string                                  | Yes      | Tool name                                  |
| `title`       | string                                  | No       | Tool title if available                    |
| `description` | string                                  | No       | Tool description if available              |
| `parameters`  | array                                   | Yes      | Tool parameters (ToolParam[])              |
| `field`       | `"readOnlyHint"` \| `"destructiveHint"` | Yes      | Which annotation field needs review        |
| `actual`      | boolean \| undefined                    | Yes      | Current annotation value (or undefined)    |
| `inferred`    | boolean                                 | Yes      | Inferred value (but marked as ambiguous)   |
| `confidence`  | `"high"` \| `"medium"` \| `"low"`       | Yes      | Confidence of inference                    |
| `isAmbiguous` | boolean                                 | Yes      | Flag indicating ambiguous pattern detected |
| `reason`      | string                                  | Yes      | Explanation and recommendation             |
| `version`     | string                                  | Yes      | Inspector version (auto-added)             |

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
}
```

---

### 10. `annotation_aligned`

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
  "version": "1.21.5"
}
```

**Fields:**

| Field         | Type                              | Required | Description                                |
| ------------- | --------------------------------- | -------- | ------------------------------------------ |
| `tool`        | string                            | Yes      | Tool name                                  |
| `confidence`  | `"high"` \| `"medium"` \| `"low"` | Yes      | Confidence of behavior inference           |
| `annotations` | object                            | Yes      | The actual annotation values from the tool |
| `version`     | string                            | Yes      | Inspector version (auto-added)             |

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

### 11. `modules_configured`

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
  "version": "1.22.0"
}
```

**Fields:**

| Field     | Type                                                | Required | Description                            |
| --------- | --------------------------------------------------- | -------- | -------------------------------------- |
| `enabled` | string[]                                            | Yes      | List of module names that will run     |
| `skipped` | string[]                                            | Yes      | List of module names that are disabled |
| `reason`  | `"skip-modules"` \| `"only-modules"` \| `"default"` | Yes      | Why modules were configured this way   |
| `version` | string                                              | Yes      | Inspector version (auto-added)         |

**Valid Module Names (17 total):**

- **Core (15):** `functionality`, `security`, `documentation`, `errorHandling`, `usability`, `mcpSpecCompliance`, `aupCompliance`, `toolAnnotations`, `prohibitedLibraries`, `externalAPIScanner`, `authentication`, `temporal`, `resources`, `prompts`, `crossCapability`
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
  "version": "1.22.0"
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
  "version": "1.22.0"
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
  "version": "1.22.0"
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
}
```

**Integration Note:** This event is useful for MCP Auditor and other consumers to calculate accurate progress percentages. When modules are skipped, the total expected `module_started`/`module_complete` events will be fewer than the full 17 modules.

---

### 12. `module_complete`

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
  "version": "1.20.0"
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
  "version": "1.20.0",
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

| Field      | Type                                       | Required | Description                    |
| ---------- | ------------------------------------------ | -------- | ------------------------------ |
| `module`   | string                                     | Yes      | Module name (snake_case)       |
| `status`   | `"PASS"` \| `"FAIL"` \| `"NEED_MORE_INFO"` | Yes      | Module result status           |
| `score`    | number                                     | Yes      | Score 0-100                    |
| `testsRun` | number                                     | Yes      | Number of tests executed       |
| `duration` | number                                     | Yes      | Execution time in milliseconds |
| `version`  | string                                     | Yes      | Inspector version (auto-added) |

**Fields (AUP Module Only):**

| Field              | Type   | Required | Description                                         |
| ------------------ | ------ | -------- | --------------------------------------------------- |
| `violationsSample` | array  | Yes      | Up to 10 violations, priority-sampled by severity   |
| `samplingNote`     | string | Yes      | Description of sampling methodology                 |
| `violationMetrics` | object | Yes      | Quantitative metrics: total, critical, high, medium |
| `scannedLocations` | object | Yes      | Boolean flags for each scanned location             |
| `highRiskDomains`  | array  | Yes      | Up to 10 detected high-risk domains                 |

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

interface ModuleCompleteEvent {
  event: "module_complete";
  module: string;
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  score: number;
  testsRun: number;
  duration: number;
  version: string;
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
}
```

---

### 13. `assessment_complete`

**When**: After all modules have completed and assessment finishes

**Purpose**: Final summary with overall status and total test count

```json
{
  "event": "assessment_complete",
  "overallStatus": "FAIL",
  "totalTests": 1440,
  "executionTime": 47823,
  "outputPath": "/tmp/inspector-full-assessment-memory-mcp.json",
  "version": "1.20.0"
}
```

**Fields:**

| Field           | Type   | Required | Description                           |
| --------------- | ------ | -------- | ------------------------------------- |
| `overallStatus` | string | Yes      | `"PASS"` or `"FAIL"` (overall result) |
| `totalTests`    | number | Yes      | Sum of all tests across all modules   |
| `executionTime` | number | Yes      | Total execution time in milliseconds  |
| `outputPath`    | string | Yes      | Path to JSON results file for details |
| `version`       | string | Yes      | Inspector version (auto-added)        |

**TypeScript Interface:**

```typescript
interface AssessmentCompleteEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
  version: string;
}
```

---

## Related Documentation

- [JSONL Events Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
- [JSONL Events Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - Complete assessment module reference

---

**Last Updated**: 2026-01-03
**Status**: Stable
