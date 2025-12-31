# JSONL Events API Reference

**Version**: 1.19.5
**Status**: Stable
**Target Audience**: MCP Auditor developers, assessment tool integrators, real-time progress consumers

---

## Overview

The MCP Inspector emits a comprehensive stream of structured JSONL (JSON Lines) events to stderr during assessment execution. This enables external tools (like MCP Auditor) to parse and display live progress, security findings, and annotation assessments in real-time without waiting for the full assessment to complete.

**Key Features:**

- **Real-time progress** with `test_batch` events during module execution
- **Instant security alerts** via `vulnerability_found` events
- **Annotation assessment** via three specialized annotation events
- **AUP enrichment** for Acceptable Use Policy violations (sampled, severity-prioritized)
- **Automatic version tracking** - all events include `version` field for compatibility checking
- **EventBatcher** - controls progress event volume via intelligent batch size and time-based flushing

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
[For each module:]
  module_started                   (1 event)
    ↓
  [During execution:]
    test_batch*                    (M events, every 500ms or 10 tests)
    vulnerability_found*           (real-time as detected)
    annotation_missing*            (real-time as detected)
    annotation_misaligned*         (real-time as detected)
    annotation_review_recommended* (real-time as detected)
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
  "version": "1.19.5"
}
```

**Fields:**

| Field        | Type                             | Required | Description                       |
| ------------ | -------------------------------- | -------- | --------------------------------- |
| `serverName` | string                           | Yes      | Name of MCP server being assessed |
| `transport`  | `"stdio"` \| `"http"` \| `"sse"` | Yes      | Connection transport type         |
| `version`    | string                           | Yes      | Inspector version (auto-added)    |

**Usage in MCP Auditor**:

```typescript
// Node.js/TypeScript
interface ServerConnectedEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
  version: string;
}

proc.stderr.on("data", (data) => {
  const lines = data
    .toString()
    .split("\n")
    .filter((l) => l.startsWith("{"));
  for (const line of lines) {
    const event = JSON.parse(line);
    if (event.event === "server_connected") {
      console.log(`Connected to ${event.serverName} via ${event.transport}`);
      // Update UI: show server name and connection status
    }
  }
});
```

---

### 2. `tool_discovered`

**When**: For each tool found during discovery phase

**Purpose**: Reports tool metadata (name, description, parameters)

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
  "version": "1.19.5"
}
```

**Fields:**

| Field         | Type           | Required | Description                           |
| ------------- | -------------- | -------- | ------------------------------------- |
| `name`        | string         | Yes      | Tool name from MCP manifest           |
| `description` | string \| null | Yes      | Tool description or null if missing   |
| `params`      | array          | Yes      | Extracted parameters from inputSchema |
| `version`     | string         | Yes      | Inspector version (auto-added)        |

**Param Object Fields:**

| Field         | Type    | Required | Description                                  |
| ------------- | ------- | -------- | -------------------------------------------- |
| `name`        | string  | Yes      | Parameter name from inputSchema.properties   |
| `type`        | string  | Yes      | Parameter type (e.g., "string", "object")    |
| `required`    | boolean | Yes      | Whether parameter is in inputSchema.required |
| `description` | string  | No       | Parameter description if provided            |

**Usage in MCP Auditor**:

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
  version: string;
}

// Build tools list as discovery progresses
const tools: Map<string, ToolDiscoveredEvent> = new Map();

if (event.event === "tool_discovered") {
  tools.set(event.name, event);
  // Update UI: add tool to tools list
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
  "version": "1.19.5"
}
```

**Fields:**

| Field     | Type   | Required | Description                      |
| --------- | ------ | -------- | -------------------------------- |
| `count`   | number | Yes      | Total number of tools discovered |
| `version` | string | Yes      | Inspector version (auto-added)   |

**Usage in MCP Auditor**:

```typescript
interface ToolsDiscoveryCompleteEvent {
  event: "tools_discovery_complete";
  count: number;
  version: string;
}

if (event.event === "tools_discovery_complete") {
  console.log(`Discovery complete: ${event.count} tools found`);
  // Update UI: show tool count, progress bar complete
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
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

```typescript
interface ModuleStartedEvent {
  event: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
  version: string;
}

const moduleProgress: Map<string, { started: Date; estimatedTests: number }> =
  new Map();

if (event.event === "module_started") {
  moduleProgress.set(event.module, {
    started: new Date(),
    estimatedTests: event.estimatedTests,
  });
  // Update UI: show current module, progress bar reset to 0%
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
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

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

// Update progress bar in real-time
if (event.event === "test_batch") {
  const percent = (event.completed / event.total) * 100;
  const elapsed = event.elapsed / 1000; // Convert to seconds
  const rate = event.completed / elapsed;
  const remaining = (event.total - event.completed) / rate;

  console.log(
    `${event.module}: ${percent.toFixed(1)}% (${event.completed}/${event.total})`,
  );
  console.log(
    `  Rate: ${rate.toFixed(1)} tests/sec, ETA: ${remaining.toFixed(1)}s`,
  );

  // Update UI: progress bar, estimated time remaining
}
```

---

### 6. `vulnerability_found`

**When**: Real-time during security assessment, as vulnerabilities are detected

**Purpose**: Instant security alert with pattern details and risk level

```json
{
  "event": "vulnerability_found",
  "version": "1.19.5",
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

**Usage in MCP Auditor**:

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

// Real-time security alert
if (event.event === "vulnerability_found") {
  const severity =
    event.riskLevel === "HIGH"
      ? "🔴 CRITICAL"
      : event.riskLevel === "MEDIUM"
        ? "🟠 WARNING"
        : "🟡 INFO";

  console.log(`${severity} [${event.tool}] ${event.pattern}`);
  console.log(`  Evidence: ${event.evidence}`);
  console.log(`  Payload: ${event.payload}`);

  // Update UI: show vulnerability in real-time list, update score
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
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

```typescript
interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

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

// Track annotation issues
if (event.event === "annotation_missing") {
  console.log(`Missing Annotation: ${event.tool}`);
  console.log(
    `  Expected: destructive=${event.inferredBehavior.expectedDestructive}`,
  );
  console.log(`  Reason: ${event.inferredBehavior.reason}`);

  // Update UI: flag tool as needing annotation
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
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

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

if (event.event === "annotation_misaligned") {
  const expected = event.expected ? "✓" : "✗";
  const actual =
    event.actual === undefined ? "undefined" : event.actual ? "✓" : "✗";

  console.log(`Misaligned: ${event.tool}.${event.field}`);
  console.log(`  Expected: ${expected}, Actual: ${actual}`);
  console.log(`  Confidence: ${(event.confidence * 100).toFixed(0)}%`);
  console.log(`  Reason: ${event.reason}`);

  // Update UI: show annotation mismatch with confidence level
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
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

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

if (event.event === "annotation_review_recommended") {
  console.log(`Review Recommended: ${event.tool}.${event.field}`);
  console.log(
    `  Inferred: ${event.inferred}, Current: ${event.actual ?? "undefined"}`,
  );
  console.log(`  Confidence: ${event.confidence}`);
  console.log(`  Reason: ${event.reason}`);

  // Update UI: show in yellow/caution color, NOT as error
  // These are suggestions, not failures
}
```

---

### 10. `module_complete`

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
  "version": "1.19.5"
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
  "version": "1.19.5",
  "violationsSample": [
    {
      "category": "B",
      "categoryName": "Child Safety",
      "severity": "CRITICAL",
      "matchedText": "generate_csam",
      "location": "tool_name",
      "confidence": "high"
    },
    {
      "category": "E",
      "categoryName": "Illegal Activity",
      "severity": "HIGH",
      "matchedText": "ransomware",
      "location": "tool_description",
      "confidence": "high"
    }
  ],
  "samplingNote": "Sampled 5 of 12 violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).",
  "violationMetrics": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 5,
    "byCategory": {
      "B": 2,
      "E": 5,
      "G": 5
    }
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
| `highRiskDomains`  | array  | Yes      | Up to 10 detected high-risk domains (e.g., weapons) |

**Violation Sample Fields:**

| Field          | Type                                                                   | Description                               |
| -------------- | ---------------------------------------------------------------------- | ----------------------------------------- |
| `category`     | string                                                                 | AUP category code (A-N, see below)        |
| `categoryName` | string                                                                 | Human-readable category name              |
| `severity`     | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"`                                 | Severity level for prioritization         |
| `matchedText`  | string                                                                 | Text snippet that triggered the violation |
| `location`     | `"tool_name"` \| `"tool_description"` \| `"readme"` \| `"source_code"` | Where violation was found                 |
| `confidence`   | `"high"` \| `"medium"` \| `"low"`                                      | Detection confidence                      |

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
| `functionality`  | `workingPercentage`          | Direct percentage of working tools   |
| `error_handling` | `metrics.mcpComplianceScore` | MCP compliance percentage            |
| `mcp_spec`       | `complianceScore`            | Direct compliance score              |
| `security`       | `vulnerabilities[]`          | `100 - (vulnCount * 10)`, min 0      |
| `aup`            | `violations[]`               | `100 - (violationCount * 10)`, min 0 |
| All others       | Status-based                 | PASS=100, FAIL=0, NEED_MORE_INFO=50  |

**Usage in MCP Auditor**:

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

interface AUPScannedLocations {
  toolNames: boolean;
  toolDescriptions: boolean;
  readme: boolean;
  sourceCode: boolean;
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
  scannedLocations?: AUPScannedLocations;
  highRiskDomains?: string[];
}

// Handle module completion
if (event.event === "module_complete") {
  const statusIcon =
    event.status === "PASS" ? "✓" : event.status === "FAIL" ? "✗" : "?";

  console.log(
    `${statusIcon} ${event.module}: ${event.status} (${event.score}%)`,
  );
  console.log(`  Tests: ${event.testsRun}, Duration: ${event.duration}ms`);

  // AUP-specific handling
  if (event.module === "aup" && event.violationsSample) {
    console.log(`  Violations: ${event.violationMetrics.total} total`);
    console.log(`    Critical: ${event.violationMetrics.critical}`);
    console.log(`    High: ${event.violationMetrics.high}`);
    console.log(`    Medium: ${event.violationMetrics.medium}`);
    console.log(`  Sampling: ${event.samplingNote}`);
    for (const v of event.violationsSample) {
      console.log(
        `    - [${v.severity}] ${v.categoryName}: "${v.matchedText}"`,
      );
    }
  }

  // Update UI: show module result, update overall score
}
```

---

### 11. `assessment_complete`

**When**: After all modules have completed and assessment finishes

**Purpose**: Final summary with overall status and total test count

```json
{
  "event": "assessment_complete",
  "overallStatus": "FAIL",
  "totalTests": 1440,
  "executionTime": 47823,
  "outputPath": "/tmp/inspector-full-assessment-memory-mcp.json",
  "version": "1.19.5"
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

**Usage in MCP Auditor**:

```typescript
interface AssessmentCompleteEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
  version: string;
}

if (event.event === "assessment_complete") {
  const status = event.overallStatus === "PASS" ? "✓ PASS" : "✗ FAIL";
  const seconds = (event.executionTime / 1000).toFixed(2);

  console.log(`\n${status} - ${event.totalTests} tests in ${seconds}s`);
  console.log(`Full results: ${event.outputPath}`);

  // Update UI: show final result, enable download button for JSON
  // Parse outputPath JSON for detailed breakdown
}
```

---

## EventBatcher: Progress Event Batching Algorithm

The EventBatcher class controls the volume of `test_batch` events using intelligent batching to avoid overwhelming consumers with too many events while maintaining responsive progress updates.

### Algorithm Overview

Events are emitted when **either** condition is met (whichever comes first):

1. **Batch size threshold**: 10 test results accumulated, OR
2. **Time interval threshold**: 500ms elapsed since last flush

### Implementation

```typescript
export class EventBatcher {
  private completed: number = 0;
  private batchBuffer: TestResult[] = [];
  private lastFlushTime: number;
  private flushIntervalMs: number = 500;
  private maxBatchSize: number = 10;

  /**
   * Add a test result. Flushes if conditions met.
   */
  addResult(result: TestResult): void {
    this.completed++;
    this.batchBuffer.push(result);

    const now = Date.now();
    const timeSinceLastFlush = now - this.lastFlushTime;

    // Flush if max batch size reached OR interval elapsed
    if (
      this.batchBuffer.length >= this.maxBatchSize ||
      timeSinceLastFlush >= this.flushIntervalMs
    ) {
      this.flush();
    } else if (!this.flushTimer) {
      // Schedule flush after remaining time
      this.flushTimer = setTimeout(
        () => this.flush(),
        this.flushIntervalMs - timeSinceLastFlush,
      );
    }
  }

  flush(): void {
    if (this.batchBuffer.length === 0) return;

    emitTestBatch(
      this.module,
      this.completed,
      this.total,
      this.batchBuffer.length,
      Date.now() - this.startTime,
    );

    this.batchBuffer = [];
    this.lastFlushTime = Date.now();
  }
}
```

### Configuration Parameters

| Parameter         | Default | Range    | Purpose                              |
| ----------------- | ------- | -------- | ------------------------------------ |
| `maxBatchSize`    | 10      | 1-100    | Tests per batch before forcing flush |
| `flushIntervalMs` | 500     | 100-5000 | Max time between batch events (ms)   |

### Behavior Examples

**Fast Module (many tests quickly):**

```
Test 1-10:  Accumulate in buffer
Test 10:    FLUSH (size=10) -> test_batch event
Test 11-20: Accumulate in new buffer
Test 20:    FLUSH (size=10) -> test_batch event
...
Result: Events roughly every 10 tests
```

**Slow Module (few tests):**

```
Test 1:     Accumulate, schedule 500ms timer
Test 2-4:   Accumulate in buffer (timer pending)
500ms:      FLUSH (size=3) -> test_batch event
Test 5:     Accumulate, schedule 500ms timer
500ms:      FLUSH (size=1) -> test_batch event
...
Result: Events roughly every 500ms
```

**Medium Pace:**

```
Test 1-5:   Accumulate in buffer (200ms elapsed)
Test 6:     Accumulate, timer continues (250ms total)
Test 7-10:  Accumulate (380ms elapsed)
500ms:      FLUSH (size=10) -> test_batch event
...
Result: Events based on whichever threshold hits first
```

### Tuning for Your Consumer

**For Real-time Dashboards** (update every 100-200ms):

```typescript
const batcher = new EventBatcher(
  "security",
  240,
  200, // flushIntervalMs: more frequent updates
  5, // maxBatchSize: smaller batches
);
```

**For Batch Processing** (less frequent updates):

```typescript
const batcher = new EventBatcher(
  "functionality",
  100,
  1000, // flushIntervalMs: every 1 second
  20, // maxBatchSize: larger batches
);
```

---

## AUP Enrichment: Violation Sampling Algorithm

When the `aup` module completes, the JSONL event includes a sampled subset of violations prioritized by severity. This allows Claude analysis and MCP Auditor to see the most critical issues without overwhelming detail.

### Sampling Strategy

**Objective:** Include up to 10 violations from all detected violations, with priority given to CRITICAL, then HIGH, then MEDIUM severity levels.

**Algorithm:**

```typescript
export function buildAUPEnrichment(
  aupResult: { violations?: Violation[] },
  maxSamples: number = 10
): AUPEnrichment {
  // 1. Calculate metrics on ALL violations
  const metrics: AUPViolationMetrics = {
    total: violations.length,
    critical: violations.filter(v => v.severity === "CRITICAL").length,
    high: violations.filter(v => v.severity === "HIGH").length,
    medium: violations.filter(v => v.severity === "MEDIUM").length,
    byCategory: {} // count by category code
  };

  // 2. Sample with severity prioritization
  const sampled: AUPViolationSample[] = [];
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM"];

  for (const severity of severityOrder) {
    if (sampled.length >= maxSamples) break;
    const bySeverity = violations.filter(v => v.severity === severity);
    for (const v of bySeverity) {
      if (sampled.length >= maxSamples) break;
      sampled.push({
        category: v.category,
        categoryName: v.categoryName,
        severity: v.severity,
        matchedText: v.matchedText,
        location: v.location,
        confidence: v.confidence
      });
    }
  }

  // 3. Build description of sampling
  let samplingNote = "";
  if (violations.length === 0) {
    samplingNote = "No violations detected.";
  } else if (violations.length <= maxSamples) {
    samplingNote = `All ${violations.length} violation(s) included.`;
  } else {
    samplingNote = `Sampled ${sampled.length} of ${violations.length} violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).`;
  }

  return { violationsSample: sampled, samplingNote, violationMetrics: metrics, ... };
}
```

### Real-World Example

**Input:** 12 total violations

```
CRITICAL (2):  csam_generator, generate_exploitation
HIGH (5):      ransomware, botnets, financial_fraud, darknet_marketplace, human_trafficking
MEDIUM (5):    weapons, exploits, illegal_substances, lockpicking, social_engineering
```

**Output (maxSamples=5):**

```json
{
  "violationsSample": [
    { "severity": "CRITICAL", "categoryName": "Child Safety", "matchedText": "csam_generator" },
    { "severity": "CRITICAL", "categoryName": "Child Safety", "matchedText": "generate_exploitation" },
    { "severity": "HIGH", "categoryName": "Malware", "matchedText": "ransomware" },
    { "severity": "HIGH", "categoryName": "Illegal Activity", "matchedText": "financial_fraud" },
    { "severity": "HIGH", "categoryName": "Illegal Activity", "matchedText": "darknet_marketplace" }
  ],
  "samplingNote": "Sampled 5 of 12 violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).",
  "violationMetrics": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 5,
    "byCategory": { "B": 2, "E": 2, "G": 2, ... }
  }
}
```

**Why Sampling?**

1. **Reduces JSONL event size** - 12 violations condensed to 5 with metrics
2. **Prioritizes human attention** - CRITICAL violations shown first
3. **Maintains decision quality** - Metrics show full picture (12 total), sample shows highlights
4. **Enables Claude analysis** - Small, curated dataset easier for language models to process

### Integration in MCP Auditor

```typescript
if (event.module === "aup" && event.violationMetrics) {
  // Show metrics prominently
  const risk =
    event.violationMetrics.critical > 0
      ? "CRITICAL"
      : event.violationMetrics.high > 0
        ? "HIGH"
        : "MEDIUM";

  console.log(`AUP Risk: ${risk}`);
  console.log(`Total violations: ${event.violationMetrics.total}`);
  console.log(`  Critical: ${event.violationMetrics.critical}`);
  console.log(`  High: ${event.violationMetrics.high}`);
  console.log(`  Medium: ${event.violationMetrics.medium}`);

  // Show sampled violations with sampling explanation
  console.log(`\nSample (${event.samplingNote}):`);
  for (const v of event.violationsSample) {
    console.log(
      `  [${v.severity}] ${v.categoryName}: "${v.matchedText}" (${v.location})`,
    );
  }
}
```

---

## Complete Assessment Lifecycle Example

### Shell Script Consumer

```bash
#!/bin/bash
# Listen to JSONL events and display real-time progress

npm run assess:full -- --server memory-mcp --config config.json 2>&1 | while IFS= read -r line; do
  if [[ ! $line =~ ^"{\"event\":" ]]; then
    continue
  fi

  event=$(echo "$line" | jq -r '.event')

  case "$event" in
    server_connected)
      serverName=$(echo "$line" | jq -r '.serverName')
      transport=$(echo "$line" | jq -r '.transport')
      echo "Connected to $serverName ($transport)"
      ;;

    tool_discovered)
      name=$(echo "$line" | jq -r '.name')
      params=$(echo "$line" | jq '.params | length')
      echo "  Found tool: $name ($params params)"
      ;;

    tools_discovery_complete)
      count=$(echo "$line" | jq -r '.count')
      echo "Discovery complete: $count tools"
      ;;

    module_started)
      module=$(echo "$line" | jq -r '.module')
      tests=$(echo "$line" | jq -r '.estimatedTests')
      echo "Starting $module ($tests tests)"
      ;;

    test_batch)
      module=$(echo "$line" | jq -r '.module')
      completed=$(echo "$line" | jq -r '.completed')
      total=$(echo "$line" | jq -r '.total')
      percent=$((completed * 100 / total))
      echo "  $module: $percent% ($completed/$total)"
      ;;

    vulnerability_found)
      tool=$(echo "$line" | jq -r '.tool')
      pattern=$(echo "$line" | jq -r '.pattern')
      risk=$(echo "$line" | jq -r '.riskLevel')
      echo "  SECURITY: [$risk] $tool - $pattern"
      ;;

    module_complete)
      module=$(echo "$line" | jq -r '.module')
      status=$(echo "$line" | jq -r '.status')
      score=$(echo "$line" | jq -r '.score')
      echo "$module: $status ($score%)"
      ;;

    assessment_complete)
      status=$(echo "$line" | jq -r '.overallStatus')
      tests=$(echo "$line" | jq -r '.totalTests')
      time=$(echo "$line" | jq -r '.executionTime')
      echo "COMPLETE: $status ($tests tests in ${time}ms)"
      ;;
  esac
done
```

### JavaScript/TypeScript Consumer (React Component)

```typescript
import { useEffect, useState } from "react";
import { spawn } from "child_process";

interface AssessmentEvent {
  event: string;
  version: string;
  [key: string]: unknown;
}

export function AssessmentProgress() {
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [progress, setProgress] = useState<Map<string, number>>(new Map());
  const [vulnerabilities, setVulnerabilities] = useState<unknown[]>([]);

  useEffect(() => {
    const proc = spawn("npm", [
      "run",
      "assess:full",
      "--",
      "--server",
      "memory-mcp",
      "--config",
      "config.json",
    ]);

    let buffer = "";

    proc.stderr.on("data", (data) => {
      buffer += data.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() || ""; // Keep incomplete line

      for (const line of lines) {
        if (!line.startsWith("{")) continue;

        try {
          const event = JSON.parse(line) as AssessmentEvent;
          setEvents((prev) => [...prev, event]);

          // Update progress based on event type
          if (event.event === "test_batch") {
            const moduleProgress = new Map(progress);
            const percent = (
              ((event.completed as number) / (event.total as number)) *
              100
            ).toFixed(0);
            moduleProgress.set(event.module as string, Number(percent));
            setProgress(moduleProgress);
          }

          if (event.event === "vulnerability_found") {
            setVulnerabilities((prev) => [...prev, event]);
          }
        } catch (e) {
          // Invalid JSON, ignore
        }
      }
    });

    return () => proc.kill();
  }, []);

  return (
    <div>
      <h2>Assessment Progress</h2>
      <div>
        {Array.from(progress.entries()).map(([module, percent]) => (
          <div key={module}>
            <label>{module}</label>
            <progress value={percent} max={100} />
            <span>{percent}%</span>
          </div>
        ))}
      </div>

      {vulnerabilities.length > 0 && (
        <div>
          <h3>Vulnerabilities Found</h3>
          <ul>
            {vulnerabilities.map((vuln, i) => (
              <li key={i}>
                [{(vuln as Record<string, unknown>).riskLevel}]{" "}
                {(vuln as Record<string, unknown>).tool}:
                {(vuln as Record<string, unknown>).pattern}
              </li>
            ))}
          </ul>
        </div>
      )}

      <details>
        <summary>Raw Events ({events.length})</summary>
        <pre>{JSON.stringify(events, null, 2)}</pre>
      </details>
    </div>
  );
}
```

### Python Consumer

```python
import subprocess
import json
import sys

def consume_assessment_events(server_name, config_path):
    """
    Stream JSONL events from assessment and process in real-time.
    """
    proc = subprocess.Popen(
        ["npm", "run", "assess:full", "--", "--server", server_name, "--config", config_path],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    events = []
    module_progress = {}
    vulnerabilities = []

    for line in proc.stderr:
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            event = json.loads(line)
            events.append(event)

            # Handle different event types
            if event["event"] == "server_connected":
                print(f"Connected to {event['serverName']} via {event['transport']}")

            elif event["event"] == "tool_discovered":
                print(f"  Found: {event['name']} ({len(event['params'])} params)")

            elif event["event"] == "module_started":
                print(f"Starting {event['module']} ({event['estimatedTests']} tests)")

            elif event["event"] == "test_batch":
                percent = (event["completed"] / event["total"]) * 100
                module_progress[event["module"]] = percent
                print(f"  {event['module']}: {percent:.1f}% ({event['completed']}/{event['total']})")

            elif event["event"] == "vulnerability_found":
                vulnerabilities.append(event)
                print(f"  SECURITY [{event['riskLevel']}] {event['tool']}: {event['pattern']}")

            elif event["event"] == "module_complete":
                status_icon = "✓" if event["status"] == "PASS" else "✗"
                print(f"{status_icon} {event['module']}: {event['status']} ({event['score']}%)")

                if event["module"] == "aup" and "violationMetrics" in event:
                    metrics = event["violationMetrics"]
                    print(f"    Total: {metrics['total']}, Critical: {metrics['critical']}, High: {metrics['high']}")

            elif event["event"] == "assessment_complete":
                print(f"\nDONE: {event['overallStatus']} ({event['totalTests']} tests in {event['executionTime']}ms)")
                print(f"Results: {event['outputPath']}")

        except json.JSONDecodeError:
            pass

    return {
        "events": events,
        "progress": module_progress,
        "vulnerabilities": vulnerabilities
    }


if __name__ == "__main__":
    result = consume_assessment_events("memory-mcp", "config.json")
    print(f"\nProcessed {len(result['events'])} events")
```

---

## Integration Checklist for MCP Auditor

Use this checklist when integrating JSONL events into MCP Auditor:

### Phase 1: Connection & Discovery

- [ ] Listen to stderr for JSONL events
- [ ] Parse `server_connected` to show server name and transport
- [ ] Accumulate `tool_discovered` events in a list
- [ ] When `tools_discovery_complete` arrives, show total tool count

### Phase 2: Real-Time Progress

- [ ] For each `module_started`, initialize progress bar (0%)
- [ ] As `test_batch` events arrive, update progress = (completed / total) \* 100
- [ ] Display current module name, test counts, elapsed time
- [ ] Show estimated time remaining based on completion rate

### Phase 3: Security Alerts

- [ ] When `vulnerability_found` arrives, add to alert list
- [ ] Display tool name, pattern, risk level, and evidence
- [ ] Sort by `riskLevel` (HIGH > MEDIUM > LOW) in UI
- [ ] Show payload if provided for debugging

### Phase 4: Annotation Assessment

- [ ] Accumulate `annotation_missing`, `annotation_misaligned`, `annotation_review_recommended`
- [ ] Display missing annotations as failures
- [ ] Display misaligned annotations with confidence levels
- [ ] Display review-recommended items in yellow/caution color (NOT red)
- [ ] Show inferred behavior and reasoning

### Phase 5: Module Completion

- [ ] When `module_complete` arrives, update module result
- [ ] Display status (PASS/FAIL/NEED_MORE_INFO), score, test count, duration
- [ ] For `aup` module, show violation metrics prominently
- [ ] Display sampled violations with sampling note
- [ ] Show scanned locations (toolNames, descriptions, readme, sourceCode)

### Phase 6: Final Summary

- [ ] When `assessment_complete` arrives, show overall status
- [ ] Display total tests and total time
- [ ] Calculate and show overall score (average or weighted)
- [ ] Provide button to download/view full JSON results from outputPath

---

## API Stability & Versioning

**Current Version:** 1.19.5

**Stability Guarantees:**

- ✓ All events include `version` field for forward compatibility
- ✓ New event types will be added, never removed
- ✓ Existing fields will not change type or meaning
- ✓ New fields may be added (optional, safe to ignore)

**Version Checking in Consumer:**

```typescript
const event = JSON.parse(jsonlLine);
const [major, minor, patch] = event.version.split(".").map(Number);

if (major > 1) {
  console.warn("Newer inspector version, some fields may not be supported");
}

// Safe to ignore new fields
const { event: eventType, version, ...eventData } = event;
```

---

## Error Handling & Edge Cases

### Handling Connection Failures

```typescript
if (event.event === "server_connected") {
  // Successfully connected
} else if (event.event === "assessment_complete") {
  // Check overallStatus
  if (event.overallStatus === "FAIL") {
    // Assessment ran but found issues
  }
} else if (process.exitCode !== 0) {
  // Process exited with error, no assessment_complete event
}
```

### Handling Large Event Streams

For assessments with 1000+ tools:

- `tool_discovered` events may number in thousands
- Consider batching UI updates (not per event, but per 100)
- `test_batch` events can arrive 10-50+ per module

**Optimization:**

```typescript
const toolBatch: ToolDiscoveredEvent[] = [];
const BATCH_SIZE = 100;

for (const event of eventStream) {
  if (event.event === "tool_discovered") {
    toolBatch.push(event);
    if (toolBatch.length >= BATCH_SIZE) {
      updateUIBatch(toolBatch);
      toolBatch = [];
    }
  }
}
```

### Handling Missing AUP Enrichment

```typescript
if (event.event === "module_complete" && event.module === "aup") {
  if (event.violationMetrics) {
    // Full enrichment available
    processAUPData(event);
  } else {
    // No violations detected (all checks passed)
    console.log("No AUP violations");
  }
}
```

---

## Performance Metrics

**Typical Event Volumes (per 20-tool assessment):**

| Event Type                 | Count    | Notes                                      |
| -------------------------- | -------- | ------------------------------------------ |
| `server_connected`         | 1        | Once per assessment                        |
| `tool_discovered`          | 20       | One per tool                               |
| `tools_discovery_complete` | 1        | Once after discovery                       |
| `module_started`           | 11       | Once per module (5 core + 6 extended)      |
| `test_batch`               | 200-500  | Every 10 tests or 500ms (varies by module) |
| `vulnerability_found`      | 0-50     | Only if vulnerabilities detected           |
| `annotation_*`             | 0-100    | Only if annotation issues detected         |
| `module_complete`          | 11       | One per module                             |
| `assessment_complete`      | 1        | Once at end                                |
| **Total JSONL lines**      | ~500-700 | Depends on findings                        |

**Bandwidth & Storage:**

- Average event size: 300-500 bytes
- Total output per assessment: 150-350 KB
- Recommended buffer for pipe: 64 KB (handles bursts)
- Safe to capture to file for analysis

---

## Testing Your Integration

### Unit Test Example

```typescript
import { emitJSONL, emitServerConnected, emitTestBatch } from "./jsonl-events";

describe("MCP Auditor JSONL Integration", () => {
  let capturedOutput: string[] = [];
  const originalError = console.error;

  beforeEach(() => {
    capturedOutput = [];
    console.error = (msg) => capturedOutput.push(msg);
  });

  afterEach(() => {
    console.error = originalError;
  });

  it("should parse events from JSONL output", () => {
    emitServerConnected("test-server", "http");
    emitTestBatch("functionality", 45, 240, 10, 2450);

    const events = capturedOutput.map((line) => JSON.parse(line));

    expect(events[0].event).toBe("server_connected");
    expect(events[1].event).toBe("test_batch");
    expect(events[1].completed).toBe(45);
    expect(events[1].total).toBe(240);
  });

  it("should include version in all events", () => {
    emitServerConnected("test", "http");

    const event = JSON.parse(capturedOutput[0]);
    expect(event.version).toBeDefined();
    expect(event.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
```

### Integration Test Example

```typescript
import { spawn } from "child_process";

test("should emit complete event sequence", async () => {
  const events: Record<string, unknown>[] = [];

  return new Promise((resolve, reject) => {
    const proc = spawn("npm", [
      "run",
      "assess:full",
      "--",
      "--server",
      "test",
      "--config",
      "test.json",
    ]);

    proc.stderr.on("data", (data) => {
      const lines = data
        .toString()
        .split("\n")
        .filter((l) => l.startsWith("{"));
      for (const line of lines) {
        events.push(JSON.parse(line));
      }
    });

    proc.on("close", (code) => {
      // Verify event sequence
      expect(events[0].event).toBe("server_connected");
      expect(events[1].event).toBe("tool_discovered");
      expect(events.some((e) => e.event === "module_complete")).toBe(true);
      expect(events[events.length - 1].event).toBe("assessment_complete");

      resolve(undefined);
    });

    setTimeout(() => reject(new Error("Timeout")), 120000);
  });
});
```

---

## FAQ

**Q: Can I filter events by type?**

A: Yes, filter on the `event` field before processing.

```bash
npm run assess:full ... 2>&1 | grep '"event":"vulnerability_found"' | jq '.'
```

**Q: How do I get the full AUP violation list (not just sample)?**

A: Parse the full JSON results file specified in `outputPath` from `assessment_complete` event.

**Q: Why are some events missing from my output?**

A: `test_batch`, `vulnerability_found`, and annotation events are conditional. They only appear if their conditions are met. `test_batch` requires many tests; `vulnerability_found` requires actual vulnerabilities to exist.

**Q: Can I replay events for testing?**

A: Yes, save stderr to a file and replay:

```bash
# Capture
npm run assess:full ... 2>events.jsonl

# Replay
cat events.jsonl | grep '^{' | while read line; do
  # Process $line
done
```

**Q: What happens if event parsing fails?**

A: Always wrap JSON.parse in try/catch. Non-event lines will fail parsing safely.

```typescript
try {
  const event = JSON.parse(line);
  // Process
} catch (e) {
  // Ignore non-JSON lines
}
```

---

## See Also

- [REAL_TIME_PROGRESS_OUTPUT.md](REAL_TIME_PROGRESS_OUTPUT.md) - Legacy progress format documentation
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- [README.md](../README.md#4-context-aware-security-assessment-with-zero-false-positives) - Security assessment overview
- `/scripts/lib/jsonl-events.ts` - Event emission implementation
- `/scripts/__tests__/jsonl-events.test.ts` - Comprehensive event tests

---

**Last Updated**: 2025-12-31
**Status**: Stable
**Maintainer**: MCP Inspector Team
