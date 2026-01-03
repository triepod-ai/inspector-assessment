# JSONL Events Algorithms

> **Part of the JSONL Events API documentation series:**
>
> - [Reference](JSONL_EVENTS_REFERENCE.md) - All 12 event types and schema definitions
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

## 2. AUP Enrichment: Violation Sampling

When the `aup` module completes, the JSONL event includes a sampled subset of violations prioritized by severity. This allows Claude analysis and MCP Auditor to see the most critical issues without overwhelming detail.

### Sampling Strategy

**Objective:** Include up to 10 violations from all detected violations, with priority given to CRITICAL, then HIGH, then MEDIUM severity levels.

### Algorithm Implementation

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

### Why Sampling?

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

## Summary

| Algorithm      | Purpose                              | Key Parameters                               |
| -------------- | ------------------------------------ | -------------------------------------------- |
| EventBatcher   | Control `test_batch` event frequency | `maxBatchSize` (10), `flushIntervalMs` (500) |
| AUP Enrichment | Prioritize and sample violations     | `maxSamples` (10), severity order            |

Both algorithms balance information density with consumer usability - enough data for real-time feedback without overwhelming the stream.

---

## Related Documentation

- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Event types and schema
- [JSONL Events Integration](JSONL_EVENTS_INTEGRATION.md) - Consumer implementation examples
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Module-specific details
