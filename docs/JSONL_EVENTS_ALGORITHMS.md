# JSONL Events Algorithms

> **Part of the JSONL Events API documentation series:**
>
> - [Reference](JSONL_EVENTS_REFERENCE.md) - All 13 event types and schema definitions
> - **Algorithms** (this document) - EventBatcher and AUP enrichment algorithms
> - [Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing

## Overview

This document covers the internal algorithms that control JSONL event generation:

1. **EventBatcher** - Intelligent batching for `test_batch` events
2. **AUP Enrichment** - Severity-prioritized violation sampling

---

## Table of Contents

- [Overview](#overview)
- [1. EventBatcher: Progress Event Batching](#1-eventbatcher-progress-event-batching)
  - [Algorithm Overview](#algorithm-overview)
  - [Implementation](#implementation)
  - [Configuration Parameters](#configuration-parameters)
  - [Behavior Examples](#behavior-examples)
  - [Tuning for Your Consumer](#tuning-for-your-consumer)
- [2. AUP Enrichment: Violation Sampling](#2-aup-enrichment-violation-sampling)
  - [Sampling Strategy](#sampling-strategy)
  - [Algorithm Implementation](#algorithm-implementation)
  - [Real-World Example](#real-world-example)
  - [Why Sampling?](#why-sampling)
  - [Integration in MCP Auditor](#integration-in-mcp-auditor)

---

## 1. EventBatcher: Progress Event Batching

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

## 2. AUP Enrichment: Violation Sampling & Tool Context

When the `aup` module completes, the JSONL event includes:

1. **Violation sampling** - Severity-prioritized subset of detected violations
2. **Tool inventory** (Issue #194) - Server tools with inferred capabilities for Claude validation
3. **Pattern coverage** - Metadata about AUP patterns checked
4. **Review flags** - Tools with sensitive capabilities requiring human review

This enrichment allows Claude analysis and MCP Auditor to see the most critical issues without overwhelming detail, while providing context about the server's tooling for more accurate validation.

### Sampling Strategy

**Objective:** Include up to 10 violations from all detected violations, with priority given to CRITICAL, then HIGH, then MEDIUM severity levels.

### Algorithm Implementation

```typescript
export function buildAUPEnrichment(
  aupResult: {
    violations?: Violation[];
    enrichmentData?: {
      // Issue #194: Tool context for Claude
      toolInventory?: ToolInventoryItem[];
      patternCoverage?: PatternCoverageInfo;
      flagsForReview?: FlagForReview[];
    };
  },
  maxSamples: number = 10,
): AUPEnrichment {
  // 1. Calculate metrics on ALL violations
  const metrics: AUPViolationMetrics = {
    total: violations.length,
    critical: violations.filter((v) => v.severity === "CRITICAL").length,
    high: violations.filter((v) => v.severity === "HIGH").length,
    medium: violations.filter((v) => v.severity === "MEDIUM").length,
    byCategory: {}, // count by category code
  };

  // 2. Sample with severity prioritization
  const sampled: AUPViolationSample[] = [];
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM"];

  for (const severity of severityOrder) {
    if (sampled.length >= maxSamples) break;
    const bySeverity = violations.filter((v) => v.severity === severity);
    for (const v of bySeverity) {
      if (sampled.length >= maxSamples) break;
      sampled.push({
        category: v.category,
        categoryName: v.categoryName,
        severity: v.severity,
        matchedText: v.matchedText,
        location: v.location,
        confidence: v.confidence,
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

  // 4. Issue #194: Include tool inventory and context for Claude validation
  const enrichmentData = aupResult.enrichmentData;

  return {
    violationsSample: sampled,
    samplingNote,
    violationMetrics: metrics,
    // Tool context (up to 50 tools for token efficiency)
    toolInventory: enrichmentData?.toolInventory?.slice(0, 50),
    patternCoverage: enrichmentData?.patternCoverage,
    flagsForReview: enrichmentData?.flagsForReview,
  };
}
```

### Tool Context Enrichment Fields (Issue #194)

The enrichment data includes three new fields to help Claude understand server capabilities:

| Field             | Type                | Purpose                                                                                 |
| ----------------- | ------------------- | --------------------------------------------------------------------------------------- |
| `toolInventory`   | ToolInventoryItem[] | Tools with names, descriptions, and inferred capabilities (max 50)                      |
| `patternCoverage` | PatternCoverageInfo | Metadata about AUP patterns checked (150+ patterns across categories A-N)               |
| `flagsForReview`  | FlagForReview[]     | Tools with sensitive capabilities (exec, auth, system, crypto) flagged for human review |

**ToolInventoryItem structure:**

```typescript
{
  name: string;                    // Tool name
  description: string;             // Truncated description (max 300 chars)
  capabilities: ToolCapability[];  // Inferred: file_system, network, exec, database, auth, crypto, system, unknown
}
```

**Capability Inference:** Based on keyword analysis of tool names and descriptions. Examples:

- `execute_shell`, `run_command` → `exec`
- `read_file`, `write_file` → `file_system`
- `fetch_api`, `http_request` → `network`
- `store_credential`, `authenticate` → `auth`

**FlagForReview structure:**

```typescript
{
  toolName: string;          // Tool flagged
  reason: string;            // Why flagged (e.g., "Command/code execution capabilities - high risk")
  capabilities: string[];    // Sensitive capabilities detected
  confidence: "low";         // Always low for capability-based flags (vs violation-based)
}
```

**PatternCoverageInfo structure:**

```typescript
{
  totalPatterns: number;             // Total AUP patterns checked (150+)
  categoriesCovered: AUPCategory[];  // Categories A-N checked
  samplePatterns: string[];          // 3-5 sample patterns for transparency
  severityBreakdown: {               // Pattern count by severity
    critical: number;
    high: number;
    medium: number;
    flag: number;
  };
}
```

### Real-World Example

**Input:**

- 12 total violations
- 5 tools (3 with sensitive capabilities)
- 150 AUP patterns checked

```
Violations:
CRITICAL (2):  csam_generator, generate_exploitation
HIGH (5):      ransomware, botnets, financial_fraud, darknet_marketplace, human_trafficking
MEDIUM (5):    weapons, exploits, illegal_substances, lockpicking, social_engineering

Tools:
- read_database (file_system, database)
- execute_command (exec) ← flagged
- fetch_api (network)
- authenticate_user (auth) ← flagged
- calculate_total (unknown)
```

**Output (maxSamples=5):**

```json
{
  "violationsSample": [
    {
      "severity": "CRITICAL",
      "categoryName": "Child Safety",
      "matchedText": "csam_generator"
    },
    {
      "severity": "CRITICAL",
      "categoryName": "Child Safety",
      "matchedText": "generate_exploitation"
    },
    {
      "severity": "HIGH",
      "categoryName": "Malware",
      "matchedText": "ransomware"
    },
    {
      "severity": "HIGH",
      "categoryName": "Illegal Activity",
      "matchedText": "financial_fraud"
    },
    {
      "severity": "HIGH",
      "categoryName": "Illegal Activity",
      "matchedText": "darknet_marketplace"
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
  "toolInventory": [
    {
      "name": "read_database",
      "description": "Reads from database",
      "capabilities": ["file_system", "database"]
    },
    {
      "name": "execute_command",
      "description": "Executes shell commands",
      "capabilities": ["exec"]
    },
    {
      "name": "fetch_api",
      "description": "Fetches data from API",
      "capabilities": ["network"]
    },
    {
      "name": "authenticate_user",
      "description": "Authenticates user",
      "capabilities": ["auth"]
    },
    {
      "name": "calculate_total",
      "description": "Calculates sum",
      "capabilities": ["unknown"]
    }
  ],
  "patternCoverage": {
    "totalPatterns": 150,
    "categoriesCovered": [
      "A",
      "B",
      "C",
      "D",
      "E",
      "F",
      "G",
      "H",
      "I",
      "J",
      "K",
      "L",
      "M",
      "N"
    ],
    "samplePatterns": [
      "CRITICAL: /csam|child.?porn/i (Child Safety)",
      "HIGH: /malware|ransomware/i (Malware)",
      "MEDIUM: /weapon|explosive/i (Illegal Activity)"
    ],
    "severityBreakdown": {
      "critical": 20,
      "high": 50,
      "medium": 60,
      "flag": 20
    }
  },
  "flagsForReview": [
    {
      "toolName": "execute_command",
      "reason": "Command/code execution capabilities - high risk",
      "capabilities": ["exec"],
      "confidence": "low"
    },
    {
      "toolName": "authenticate_user",
      "reason": "Authentication/credential handling - review security",
      "capabilities": ["auth"],
      "confidence": "low"
    }
  ]
}
```

### Why Enrichment?

1. **Reduces JSONL event size** - 12 violations condensed to 5 with metrics
2. **Prioritizes human attention** - CRITICAL violations shown first
3. **Maintains decision quality** - Metrics show full picture (12 total), sample shows highlights
4. **Enables Claude analysis** - Small, curated dataset easier for language models to process
5. **Provides tool context** (Issue #194) - Tool inventory helps Claude understand server capabilities for accurate validation
6. **Flags sensitive tools** - Highlights tools with exec/auth/system capabilities even without violations
7. **Explains detection coverage** - Pattern coverage shows what was checked for transparency

**Token Efficiency:**

- Tool inventory limited to 50 tools (prioritizes first 50)
- Tool descriptions truncated to 300 chars
- High-risk domains limited to 10
- Violation samples limited to 10 (severity-prioritized)
- Total enrichment typically <3000 tokens for 50-tool servers

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

  // Issue #194: Show tool context for Claude validation
  if (event.toolInventory) {
    console.log(`\nTool Context (${event.toolInventory.length} tools):`);
    const sensitiveTools = event.toolInventory.filter((t) =>
      t.capabilities.some((c) =>
        ["exec", "auth", "system", "crypto"].includes(c),
      ),
    );
    console.log(`  Sensitive capabilities: ${sensitiveTools.length} tools`);

    // Show capability breakdown
    const capCounts = {};
    for (const tool of event.toolInventory) {
      for (const cap of tool.capabilities) {
        capCounts[cap] = (capCounts[cap] || 0) + 1;
      }
    }
    console.log(`  Capability breakdown:`, capCounts);
  }

  // Show flags for review
  if (event.flagsForReview && event.flagsForReview.length > 0) {
    console.log(`\nTools Flagged for Review (${event.flagsForReview.length}):`);
    for (const flag of event.flagsForReview) {
      console.log(`  ${flag.toolName}: ${flag.reason}`);
      console.log(`    Capabilities: ${flag.capabilities.join(", ")}`);
    }
  }

  // Show pattern coverage
  if (event.patternCoverage) {
    console.log(`\nPattern Coverage:`);
    console.log(
      `  Total patterns checked: ${event.patternCoverage.totalPatterns}`,
    );
    console.log(
      `  Categories: ${event.patternCoverage.categoriesCovered.join(", ")}`,
    );
    console.log(
      `  Severity: ${event.patternCoverage.severityBreakdown.critical}C / ${event.patternCoverage.severityBreakdown.high}H / ${event.patternCoverage.severityBreakdown.medium}M`,
    );
  }
}
```

---

## Summary

| Algorithm      | Purpose                                         | Key Parameters                                              |
| -------------- | ----------------------------------------------- | ----------------------------------------------------------- |
| EventBatcher   | Control `test_batch` event frequency            | `maxBatchSize` (10), `flushIntervalMs` (500)                |
| AUP Enrichment | Prioritize and sample violations + tool context | `maxSamples` (10), `maxInventoryItems` (50), severity order |

**AUP Enrichment Components (Issue #194):**

- **Violation sampling** - Severity-prioritized subset (CRITICAL > HIGH > MEDIUM)
- **Tool inventory** - Server tools with inferred capabilities for Claude validation
- **Pattern coverage** - Metadata about detection patterns (150+ patterns, categories A-N)
- **Review flags** - Tools with sensitive capabilities (exec, auth, system, crypto)

Both algorithms balance information density with consumer usability - enough data for real-time feedback without overwhelming the stream.

---

## Related Documentation

- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Event types and schema
- [JSONL Events Integration](JSONL_EVENTS_INTEGRATION.md) - Consumer implementation examples
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Module-specific details
