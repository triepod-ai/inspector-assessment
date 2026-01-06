# JSONL Events Integration Guide

> **Part of the JSONL Events API documentation series:**
>
> - [Reference](JSONL_EVENTS_REFERENCE.md) - All 13 event types and schema definitions
> - [Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
> - **Integration** (this document) - Lifecycle examples, integration checklist, testing

## Overview

This guide provides practical implementation examples and testing patterns for consuming JSONL events from MCP Inspector assessments. It covers shell scripts, TypeScript/React, Python consumers, and includes a complete integration checklist.

---

## Table of Contents

- [Overview](#overview)
- [1. Complete Assessment Lifecycle Example](#1-complete-assessment-lifecycle-example)
  - [Shell Script Consumer](#shell-script-consumer)
  - [TypeScript/React Consumer](#typescriptreact-consumer)
  - [Python Consumer](#python-consumer)
- [2. Integration Checklist for MCP Auditor](#2-integration-checklist-for-mcp-auditor)
- [3. API Stability & Versioning](#3-api-stability--versioning)
- [4. Error Handling & Edge Cases](#4-error-handling--edge-cases)
- [5. Performance Metrics](#5-performance-metrics)
- [6. Testing Your Integration](#6-testing-your-integration)
- [7. FAQ](#7-faq)

---

## 1. Complete Assessment Lifecycle Example

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

    annotation_missing)
      tool=$(echo "$line" | jq -r '.tool')
      echo "  ANNOTATION: $tool missing annotations"
      ;;

    annotation_misaligned)
      tool=$(echo "$line" | jq -r '.tool')
      field=$(echo "$line" | jq -r '.field')
      echo "  ANNOTATION: $tool - $field misaligned"
      ;;

    annotation_aligned)
      tool=$(echo "$line" | jq -r '.tool')
      confidence=$(echo "$line" | jq -r '.confidence')
      echo "  ANNOTATION: $tool aligned ($confidence confidence)"
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

### TypeScript/React Consumer

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

## 2. Integration Checklist for MCP Auditor

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

## 3. API Stability & Versioning

**Current Version:** 1.20.0

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

## 4. Error Handling & Edge Cases

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

## 5. Performance Metrics

**Typical Event Volumes (per 20-tool assessment):**

| Event Type                 | Count    | Notes                                      |
| -------------------------- | -------- | ------------------------------------------ |
| `server_connected`         | 1        | Once per assessment                        |
| `tool_discovered`          | 20       | One per tool                               |
| `tools_discovery_complete` | 1        | Once after discovery                       |
| `module_started`           | 17       | Once per module (15 core + 2 optional)     |
| `test_batch`               | 200-500  | Every 10 tests or 500ms (varies by module) |
| `vulnerability_found`      | 0-50     | Only if vulnerabilities detected           |
| `annotation_*`             | 0-100    | Only if annotation issues detected         |
| `module_complete`          | 17       | One per module                             |
| `assessment_complete`      | 1        | Once at end                                |
| **Total JSONL lines**      | ~500-700 | Depends on findings                        |

**Bandwidth & Storage:**

- Average event size: 300-500 bytes
- Total output per assessment: 150-350 KB
- Recommended buffer for pipe: 64 KB (handles bursts)
- Safe to capture to file for analysis

---

## 6. Testing Your Integration

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

## 7. FAQ

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

- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - All 13 event types and schemas
- [JSONL Events Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP sampling
- [REAL_TIME_PROGRESS_OUTPUT.md](REAL_TIME_PROGRESS_OUTPUT.md) - Legacy progress format documentation
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- `/scripts/lib/jsonl-events.ts` - Event emission implementation
- `/scripts/__tests__/jsonl-events.test.ts` - Comprehensive event tests

---

**Last Updated**: 2025-12-31
**Status**: Stable
**Maintainer**: MCP Inspector Team
