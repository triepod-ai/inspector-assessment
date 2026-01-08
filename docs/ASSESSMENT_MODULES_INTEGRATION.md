# Assessment Modules Integration Guide

**Practical integration patterns and real-world examples for MCP Inspector assessment modules.**

This document provides step-by-step integration guides, real-world examples, and troubleshooting for developers integrating security testing and annotation modules.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Security Testing Integration](#security-testing-integration)
3. [Annotation Assessment Integration](#annotation-assessment-integration)
4. [Complete Assessment Workflow](#complete-assessment-workflow)
5. [Error Handling Strategies](#error-handling-strategies)
6. [Performance Optimization](#performance-optimization)
7. [Troubleshooting Guide](#troubleshooting-guide)

---

## Quick Start

### Minimal Security Test Example (5 minutes)

```typescript
import {
  SecurityPayloadTester,
  type PayloadTestConfig,
} from "@/services/assessment/modules/securityTests";

async function quickSecurityTest() {
  // 1. Setup logger
  const logger = {
    log: console.log,
    logError: (msg, err) => console.error(msg, err),
  };

  // 2. Setup timeout handler
  const executeWithTimeout = async (promise, timeout) => {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), timeout),
      ),
    ]);
  };

  // 3. Create tester
  const config: PayloadTestConfig = {
    enableDomainTesting: false, // Basic mode = faster
    maxParallelTests: 5,
    securityTestTimeout: 5000,
  };

  const tester = new SecurityPayloadTester(config, logger, executeWithTimeout);

  // 4. Run basic tests
  const results = await tester.runBasicSecurityTests(
    tools,
    callTool,
    (event) => {
      if (event.type === "test_batch") {
        console.log(
          `Progress: ${event.completed}/${event.total} (${event.elapsed}ms)`,
        );
      }
    },
  );

  // 5. Process results
  const vulnerabilities = results.filter((r) => r.vulnerable);
  console.log(`Found ${vulnerabilities.length} vulnerabilities`);
}
```

### Minimal Annotation Test Example (3 minutes)

```typescript
import {
  scanDescriptionForPoisoning,
  detectAnnotationDeception,
  inferBehavior,
} from "@/services/assessment/modules/annotations";

function quickAnnotationTest(tool) {
  // 1. Scan description
  const poisoning = scanDescriptionForPoisoning(tool);
  if (poisoning.detected) {
    console.log(`⚠ Poisoning detected: ${poisoning.riskLevel}`);
  }

  // 2. Check deception
  const deception = detectAnnotationDeception(tool.name, {
    readOnlyHint: tool.readOnlyHint,
    destructiveHint: tool.destructiveHint,
  });
  if (deception) {
    console.log(`🚨 Deception: ${deception.reason}`);
  }

  // 3. Infer behavior
  const behavior = inferBehavior(tool.name, tool.description);
  console.log(`Expected behavior: ${behavior.reason}`);
}
```

---

## Security Testing Integration

### Step 1: Setup Test Infrastructure

Create a test runner wrapper to manage the lifecycle:

```typescript
// lib/testRunner.ts
import {
  SecurityPayloadTester,
  type PayloadTestConfig,
  type TestLogger,
} from "@/services/assessment/modules/securityTests";

export class SecurityTestRunner {
  private tester: SecurityPayloadTester;

  constructor(config?: Partial<PayloadTestConfig>) {
    const mergedConfig: PayloadTestConfig = {
      enableDomainTesting: config?.enableDomainTesting ?? false,
      maxParallelTests: config?.maxParallelTests ?? 5,
      securityTestTimeout: config?.securityTestTimeout ?? 5000,
      ...config,
    };

    const logger = this.createLogger();
    const executeWithTimeout = this.createTimeoutExecutor();

    this.tester = new SecurityPayloadTester(
      mergedConfig,
      logger,
      executeWithTimeout,
    );
  }

  private createLogger(): TestLogger {
    return {
      log: (msg) => console.log(`[Security Test] ${msg}`),
      logError: (msg, err) =>
        console.error(`[Security Test Error] ${msg}`, err),
    };
  }

  private createTimeoutExecutor() {
    return async <T>(promise: Promise<T>, timeout: number): Promise<T> => {
      const timeoutPromise = new Promise<T>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Test timeout after ${timeout}ms`)),
          timeout,
        ),
      );

      return Promise.race([promise, timeoutPromise]);
    };
  }

  async run(tools, callTool, options = {}) {
    if (options.advanced) {
      return this.tester.runUniversalSecurityTests(
        tools,
        callTool,
        options.onProgress,
      );
    } else {
      return this.tester.runBasicSecurityTests(
        tools,
        callTool,
        options.onProgress,
      );
    }
  }
}
```

### Step 2: Configure Test Parameters

```typescript
// config/securityTestConfig.ts
import type { PayloadTestConfig } from "@/services/assessment/modules/securityTests";

export const SECURITY_TEST_CONFIGS = {
  // Fast pre-flight check
  preflightCheck: {
    enableDomainTesting: false,
    maxParallelTests: 10,
    securityTestTimeout: 3000,
  } as PayloadTestConfig,

  // Standard assessment
  standard: {
    enableDomainTesting: true,
    maxParallelTests: 5,
    securityTestTimeout: 5000,
  } as PayloadTestConfig,

  // Comprehensive + slow tools
  comprehensive: {
    enableDomainTesting: true,
    maxParallelTests: 3,
    securityTestTimeout: 10000,
  } as PayloadTestConfig,

  // CI/CD pipeline
  ciCd: {
    enableDomainTesting: false,
    maxParallelTests: 8,
    securityTestTimeout: 4000,
  } as PayloadTestConfig,
};
```

### Step 3: Implement Progress Tracking

```typescript
// lib/progressTracker.ts
import type { ProgressCallback } from "@/services/assessment/modules/securityTests";

export class SecurityTestProgressTracker {
  private startTime = Date.now();
  private lastUpdate = 0;
  private updateInterval = 500; // ms

  track(onUI?: (progress: any) => void): ProgressCallback {
    return (event) => {
      const now = Date.now();

      // Throttle updates to UI
      if (now - this.lastUpdate < this.updateInterval) {
        return;
      }

      this.lastUpdate = now;

      if (event.type === "test_batch") {
        const progress = {
          completed: event.completed,
          total: event.total,
          percentage: Math.round((event.completed / event.total) * 100),
          elapsed: event.elapsed,
          estimatedRemaining: this.estimateRemaining(
            event.completed,
            event.total,
            event.elapsed,
          ),
          testRate: (event.completed / (event.elapsed / 1000)).toFixed(1),
        };

        onUI?.(progress);
        console.log(
          `[${progress.percentage}%] ${progress.completed}/${progress.total} (${progress.testRate} tests/sec)`,
        );
      } else if (event.type === "vulnerability_found") {
        console.log(
          `[VULN] ${event.tool}: ${event.pattern} (${event.confidence})`,
        );
        onUI?.({
          type: "vulnerability",
          tool: event.tool,
          pattern: event.pattern,
          confidence: event.confidence,
        });
      }
    };
  }

  private estimateRemaining(
    completed: number,
    total: number,
    elapsed: number,
  ): number {
    if (completed === 0) return 0;
    const rate = completed / elapsed;
    const remaining = total - completed;
    return Math.round(remaining / rate);
  }
}
```

### Step 4: Handle Results

```typescript
// lib/resultProcessor.ts
import type { SecurityTestResult } from "@/lib/assessment/resultTypes";

export class SecurityResultProcessor {
  process(results: SecurityTestResult[]) {
    return {
      summary: this.summarize(results),
      vulnerabilities: this.extractVulnerabilities(results),
      byTool: this.groupByTool(results),
      byPattern: this.groupByPattern(results),
      statistics: this.calculateStats(results),
    };
  }

  private summarize(results: SecurityTestResult[]) {
    const vulns = results.filter((r) => r.vulnerable);
    const critical = vulns.filter((v) => v.riskLevel === "CRITICAL");
    const high = vulns.filter((v) => v.riskLevel === "HIGH");

    return {
      totalTests: results.length,
      vulnerabilities: vulns.length,
      critical: critical.length,
      high: high.length,
      passRate: (
        ((results.length - vulns.length) / results.length) *
        100
      ).toFixed(2),
    };
  }

  private extractVulnerabilities(results: SecurityTestResult[]) {
    return results
      .filter((r) => r.vulnerable && !r.connectionError)
      .map((v) => ({
        tool: v.toolName,
        pattern: v.testName,
        payload: v.payload,
        evidence: v.evidence,
        confidence: v.confidence,
        requiresReview: v.requiresManualReview,
      }))
      .sort((a, b) => {
        // Sort by confidence
        const confidenceOrder = { high: 0, medium: 1, low: 2 };
        return (
          confidenceOrder[a.confidence as any] -
          confidenceOrder[b.confidence as any]
        );
      });
  }

  private groupByTool(results: SecurityTestResult[]) {
    const grouped: Record<string, SecurityTestResult[]> = {};
    for (const result of results) {
      if (!grouped[result.toolName]) {
        grouped[result.toolName] = [];
      }
      grouped[result.toolName].push(result);
    }

    return Object.entries(grouped).map(([tool, results]) => ({
      tool,
      totalTests: results.length,
      vulnerabilities: results.filter((r) => r.vulnerable).length,
      results: results
        .filter((r) => r.vulnerable)
        .map((r) => ({ pattern: r.testName, confidence: r.confidence })),
    }));
  }

  private groupByPattern(results: SecurityTestResult[]) {
    const grouped: Record<string, number> = {};
    for (const result of results.filter((r) => r.vulnerable)) {
      grouped[result.testName] = (grouped[result.testName] || 0) + 1;
    }

    return Object.entries(grouped)
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count);
  }

  private calculateStats(results: SecurityTestResult[]) {
    const vulns = results.filter((r) => r.vulnerable);

    return {
      avgTestsPerTool: (
        results.length / new Set(results.map((r) => r.toolName)).size
      ).toFixed(1),
      vulnerabilityRate: ((vulns.length / results.length) * 100).toFixed(2),
      highConfidenceRate: (
        (vulns.filter((v) => v.confidence === "high").length / vulns.length) *
        100
      ).toFixed(2),
      connectionErrors: results.filter((r) => r.connectionError).length,
    };
  }
}
```

### Complete Security Testing Workflow

```typescript
// services/securityAssessmentService.ts
import { SecurityTestRunner } from "@/lib/testRunner";
import { SecurityTestProgressTracker } from "@/lib/progressTracker";
import { SecurityResultProcessor } from "@/lib/resultProcessor";
import { SECURITY_TEST_CONFIGS } from "@/config/securityTestConfig";

export class SecurityAssessmentService {
  async assessTools(
    tools,
    callTool,
    options: {
      mode?: "preflight" | "standard" | "comprehensive";
      onProgress?: (progress: any) => void;
    } = {},
  ) {
    const mode = options.mode ?? "standard";
    const config = SECURITY_TEST_CONFIGS[mode];

    // Setup
    const runner = new SecurityTestRunner(config);
    const tracker = new SecurityTestProgressTracker();
    const processor = new SecurityResultProcessor();

    // Run tests
    const results = await runner.run(tools, callTool, {
      advanced: config.enableDomainTesting,
      onProgress: tracker.track(options.onProgress),
    });

    // Process results
    return processor.process(results);
  }
}
```

---

## Annotation Assessment Integration

### Step 1: Build Assessment Factory

```typescript
// lib/annotationAssessor.ts
import {
  scanDescriptionForPoisoning,
  detectAnnotationDeception,
  inferBehavior,
  type BehaviorInferenceResult,
  type PoisoningScanResult,
  type DeceptionResult,
} from "@/services/assessment/modules/annotations";

export interface ToolAnnotationAssessment {
  toolName: string;
  poisoning: PoisoningScanResult;
  deception: DeceptionResult | null;
  behavior: BehaviorInferenceResult;
  annotations: {
    declared: { readOnlyHint?: boolean; destructiveHint?: boolean };
    inferred: { expectedReadOnly: boolean; expectedDestructive: boolean };
    conflicts: {
      readOnlyMismatch: boolean;
      destructiveMismatch: boolean;
      mismatchConfidence: "high" | "medium" | "low";
    };
  };
}

export function assessToolAnnotations(tool): ToolAnnotationAssessment {
  // Scan for poisoning
  const poisoning = scanDescriptionForPoisoning(tool);

  // Check for deception
  const deception = detectAnnotationDeception(tool.name, {
    readOnlyHint: tool.readOnlyHint,
    destructiveHint: tool.destructiveHint,
  });

  // Infer expected behavior
  const behavior = inferBehavior(tool.name, tool.description);

  // Check for conflicts
  const readOnlyMismatch =
    tool.readOnlyHint !== behavior.expectedReadOnly &&
    behavior.confidence === "high";

  const destructiveMismatch =
    tool.destructiveHint !== behavior.expectedDestructive &&
    behavior.confidence === "high";

  return {
    toolName: tool.name,
    poisoning,
    deception,
    behavior,
    annotations: {
      declared: {
        readOnlyHint: tool.readOnlyHint,
        destructiveHint: tool.destructiveHint,
      },
      inferred: {
        expectedReadOnly: behavior.expectedReadOnly,
        expectedDestructive: behavior.expectedDestructive,
      },
      conflicts: {
        readOnlyMismatch,
        destructiveMismatch,
        mismatchConfidence: behavior.confidence,
      },
    },
  };
}
```

### Step 2: Build Severity Scoring

```typescript
// lib/annotationSeverity.ts
import type { ToolAnnotationAssessment } from "./annotationAssessor";

export interface AnnotationSeverityScore {
  tool: string;
  issues: Array<{
    type: "poisoning" | "deception" | "annotation_mismatch";
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    description: string;
  }>;
  overallSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  score: number; // 0-100, 100 is worst
  requiresAction: boolean;
}

export function scoreAnnotationSeverity(
  assessment: ToolAnnotationAssessment,
): AnnotationSeverityScore {
  const issues = [];

  // Score poisoning
  if (assessment.poisoning.detected) {
    if (assessment.poisoning.riskLevel === "HIGH") {
      issues.push({
        type: "poisoning" as const,
        severity: "CRITICAL" as const,
        description: `Description contains ${assessment.poisoning.patterns.length} HIGH-severity poisoning patterns`,
      });
    } else if (assessment.poisoning.riskLevel === "MEDIUM") {
      issues.push({
        type: "poisoning" as const,
        severity: "HIGH" as const,
        description: `Description contains ${assessment.poisoning.patterns.length} MEDIUM-severity patterns`,
      });
    }
  }

  // Score deception
  if (assessment.deception) {
    issues.push({
      type: "deception" as const,
      severity: "HIGH" as const,
      description: assessment.deception.reason,
    });
  }

  // Score annotation mismatches
  if (assessment.annotations.conflicts.readOnlyMismatch) {
    issues.push({
      type: "annotation_mismatch" as const,
      severity: "HIGH" as const,
      description: `readOnlyHint=${assessment.annotations.declared.readOnlyHint} but tool name suggests ${assessment.behavior.reason}`,
    });
  }

  if (assessment.annotations.conflicts.destructiveMismatch) {
    issues.push({
      type: "annotation_mismatch" as const,
      severity: "HIGH" as const,
      description: `destructiveHint=${assessment.annotations.declared.destructiveHint} but tool name suggests ${assessment.behavior.reason}`,
    });
  }

  // Calculate severity
  const severityOrder = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
  let maxSeverity = 0;
  for (const issue of issues) {
    maxSeverity = Math.max(maxSeverity, severityOrder[issue.severity]);
  }

  const severityMap = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

  // Score: more issues + higher severity = higher score
  const score = Math.min(100, issues.length * 20 + maxSeverity * 15);

  return {
    tool: assessment.toolName,
    issues,
    overallSeverity: severityMap[maxSeverity],
    score,
    requiresAction: maxSeverity >= 2, // HIGH or CRITICAL
  };
}
```

### Step 3: Batch Assessment

```typescript
// lib/batchAnnotationAssessment.ts
import {
  assessToolAnnotations,
  type ToolAnnotationAssessment,
} from "./annotationAssessor";
import {
  scoreAnnotationSeverity,
  type AnnotationSeverityScore,
} from "./annotationSeverity";

export interface BatchAnnotationResults {
  totalTools: number;
  assessments: ToolAnnotationAssessment[];
  scores: AnnotationSeverityScore[];
  summary: {
    poisoningDetected: number;
    deceptionDetected: number;
    mismatchesDetected: number;
    criticalIssues: number;
    highIssues: number;
  };
}

export function assessToolAnnotationsBatch(
  tools: any[],
): BatchAnnotationResults {
  const assessments = tools.map((tool) => assessToolAnnotations(tool));
  const scores = assessments.map((a) => scoreAnnotationSeverity(a));

  return {
    totalTools: tools.length,
    assessments,
    scores,
    summary: {
      poisoningDetected: assessments.filter((a) => a.poisoning.detected).length,
      deceptionDetected: assessments.filter((a) => a.deception !== null).length,
      mismatchesDetected: assessments.filter(
        (a) =>
          a.annotations.conflicts.readOnlyMismatch ||
          a.annotations.conflicts.destructiveMismatch,
      ).length,
      criticalIssues: scores.filter((s) => s.overallSeverity === "CRITICAL")
        .length,
      highIssues: scores.filter((s) =>
        ["CRITICAL", "HIGH"].includes(s.overallSeverity),
      ).length,
    },
  };
}
```

---

## Complete Assessment Workflow

### Full Assessment Service

```typescript
// services/fullAssessmentService.ts
import { SecurityAssessmentService } from "./securityAssessmentService";
import { assessToolAnnotationsBatch } from "@/lib/batchAnnotationAssessment";

export interface FullAssessmentResults {
  server: string;
  timestamp: Date;
  security: {
    summary: any;
    vulnerabilities: any[];
  };
  annotations: {
    summary: any;
    criticalIssues: any[];
  };
  combined: {
    vulnerableTools: string[];
    toolsWithAnnotationIssues: string[];
    intersectionTools: string[];
  };
}

export class FullAssessmentService {
  async assessServer(
    serverName: string,
    tools,
    callTool,
    options: {
      securityMode?: "preflight" | "standard" | "comprehensive";
      onProgress?: (event: any) => void;
    } = {},
  ): Promise<FullAssessmentResults> {
    // Run security assessment
    const securityService = new SecurityAssessmentService();
    const securityResults = await securityService.assessTools(tools, callTool, {
      mode: options.securityMode ?? "standard",
      onProgress: (progress) => {
        options.onProgress?.({
          phase: "security",
          ...progress,
        });
      },
    });

    // Run annotation assessment
    const annotationResults = assessToolAnnotationsBatch(tools);

    // Combine results
    const vulnerableTools = new Set(
      securityResults.vulnerabilities.map((v) => v.tool),
    );
    const toolsWithIssues = new Set(
      annotationResults.scores
        .filter((s) => s.requiresAction)
        .map((s) => s.tool),
    );

    const intersection = [...vulnerableTools].filter((tool) =>
      toolsWithIssues.has(tool),
    );

    return {
      server: serverName,
      timestamp: new Date(),
      security: {
        summary: securityResults.summary,
        vulnerabilities: securityResults.vulnerabilities,
      },
      annotations: {
        summary: annotationResults.summary,
        criticalIssues: annotationResults.scores
          .filter((s) => s.overallSeverity === "CRITICAL")
          .map((s) => ({
            tool: s.tool,
            issues: s.issues,
            score: s.score,
          })),
      },
      combined: {
        vulnerableTools: [...vulnerableTools],
        toolsWithAnnotationIssues: [...toolsWithIssues],
        intersectionTools: intersection,
      },
    };
  }
}
```

### Usage Example

```typescript
// Usage
const assessmentService = new FullAssessmentService();

const results = await assessmentService.assessServer(
  "my-mcp-server",
  tools,
  callTool,
  {
    securityMode: "standard",
    onProgress: (event) => {
      if (event.phase === "security") {
        console.log(
          `Security: ${event.percentage}% (${event.testRate} tests/sec)`,
        );
      }
    },
  },
);

console.log(`\n=== ASSESSMENT RESULTS ===`);
console.log(`Vulnerabilities: ${results.security.summary.vulnerabilities}`);
console.log(`Annotation Issues: ${results.annotations.summary.criticalIssues}`);
console.log(
  `High Risk Tools: ${results.combined.intersectionTools.join(", ")}`,
);
```

---

## Error Handling Strategies

### Connection Error Handling

```typescript
import { SecurityResponseAnalyzer } from "@/services/assessment/modules/securityTests";

const analyzer = new SecurityResponseAnalyzer();

async function testWithErrorHandling(tool, callTool) {
  try {
    const response = await callTool(tool.name, params);

    // Check for connection errors FIRST
    if (analyzer.isConnectionError(response)) {
      const errorType = analyzer.classifyError(response);
      return {
        status: "connection_error",
        errorType,
        tool: tool.name,
        shouldRetry: errorType !== "protocol",
      };
    }

    // Normal analysis
    const result = analyzer.analyzeResponse(response, payload, tool);
    return {
      status: "success",
      vulnerable: result.isVulnerable,
      evidence: result.evidence,
    };
  } catch (error) {
    // Check if caught error is connection-related
    if (analyzer.isConnectionErrorFromException(error)) {
      const errorType = analyzer.classifyErrorFromException(error);
      return {
        status: "connection_error",
        errorType,
        tool: tool.name,
        shouldRetry: errorType !== "protocol",
        message: error.message,
      };
    }

    // Tool rejected input (validation error)
    return {
      status: "validation_error",
      tool: tool.name,
      message: error.message,
    };
  }
}
```

### Timeout Handling

```typescript
// Create smart timeout executor
function createAdaptiveTimeoutExecutor(baseTimeout = 5000) {
  const timeouts: Record<string, number> = {};

  return async <T>(
    promise: Promise<T>,
    timeout: number,
    toolName?: string,
  ): Promise<T> => {
    // Adjust timeout based on tool history
    const adjustedTimeout = toolName ? timeouts[toolName] || timeout : timeout;

    const timeoutPromise = new Promise<T>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Timeout after ${adjustedTimeout}ms`)),
        adjustedTimeout,
      ),
    );

    try {
      const result = await Promise.race([promise, timeoutPromise]);

      // Record successful timeout for this tool
      if (toolName) {
        timeouts[toolName] = Math.min(adjustedTimeout * 1.2, 15000);
      }

      return result;
    } catch (error) {
      // Tool is slow - increase timeout next time
      if (toolName && error.message.includes("Timeout")) {
        timeouts[toolName] = Math.min(adjustedTimeout * 1.5, 15000);
      }
      throw error;
    }
  };
}
```

### Retry Strategy

```typescript
async function testPayloadWithRetry(
  tool,
  attackName,
  payload,
  callTool,
  maxRetries = 2,
) {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await tester.testPayload(
        tool,
        attackName,
        payload,
        callTool,
      );

      // Success
      if (!result.connectionError) {
        return result;
      }

      // Connection error - retry
      if (result.errorType === "connection" && attempt < maxRetries) {
        console.log(
          `Connection error (attempt ${attempt}/${maxRetries}), retrying...`,
        );
        await sleep(1000 * attempt); // Exponential backoff
        continue;
      }

      // Protocol error or last attempt - return as-is
      return result;
    } catch (error) {
      lastError = error;

      if (attempt < maxRetries) {
        console.log(`Error (attempt ${attempt}/${maxRetries}), retrying...`);
        await sleep(1000 * attempt);
      }
    }
  }

  throw lastError;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

---

## Performance Optimization

### Concurrency Tuning

```typescript
// Determine optimal concurrency based on available resources
function determineOptimalConcurrency(): number {
  const cpuCount = navigator.hardwareConcurrency || 4;

  // For network I/O, allow more concurrent operations
  if (typeof window === "undefined") {
    // Node.js environment
    return cpuCount * 2;
  } else {
    // Browser environment - be more conservative
    return Math.min(cpuCount, 4);
  }
}

// Use in configuration
const config = {
  maxParallelTests: determineOptimalConcurrency(),
};
```

### Caching Results

```typescript
// Cache poisoning scan results
const poisoningCache = new Map<string, PoisoningScanResult>();

function getCachedPoisoningScan(tool): PoisoningScanResult {
  const cacheKey = `${tool.name}:${tool.description}`;

  if (poisoningCache.has(cacheKey)) {
    return poisoningCache.get(cacheKey)!;
  }

  const result = scanDescriptionForPoisoning(tool);
  poisoningCache.set(cacheKey, result);

  return result;
}

// Clear cache when tools update
function invalidatePoisoningCache(toolNames?: string[]) {
  if (!toolNames) {
    poisoningCache.clear();
  } else {
    for (const toolName of toolNames) {
      // Find and remove all cache entries for this tool
      for (const key of poisoningCache.keys()) {
        if (key.startsWith(toolName + ":")) {
          poisoningCache.delete(key);
        }
      }
    }
  }
}
```

### Batch Processing

```typescript
// Process tools in batches
async function assessToolsInBatches(tools, batchSize = 10, assessFn) {
  const results = [];

  for (let i = 0; i < tools.length; i += batchSize) {
    const batch = tools.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map((tool) => assessFn(tool)));

    results.push(...batchResults);

    // Report progress
    console.log(
      `Processed ${Math.min(i + batchSize, tools.length)}/${tools.length} tools`,
    );

    // Allow GC between batches
    if (i + batchSize < tools.length) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  return results;
}
```

---

## Troubleshooting Guide

### Common Issues

#### Issue: "Tool has no input parameters"

```typescript
// Diagnosis
if (!generator.hasInputParameters(tool)) {
  console.log("Tool has no injectable parameters");
  console.log("Tool schema:", tool.inputSchema);
}

// Solution: Skip injection tests for this tool
// The test framework handles this automatically with passing results
```

#### Issue: All Tests Timing Out

```typescript
// Check timeout configuration
const config = {
  securityTestTimeout: 10000, // Increase from 5000
};

// Or increase per-tool timeout dynamically
const executeWithTimeout = async (promise, timeout) => {
  // Try with increased timeout for slow tools
  const increasedTimeout = timeout * 2;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), increasedTimeout),
      ),
    ]);
  } catch (error) {
    if (error.message.includes("Timeout")) {
      console.log("Tool is very slow - consider longer timeout");
    }
    throw error;
  }
};
```

#### Issue: High False Positive Rate

```typescript
// Review confidence levels
const vulnerabilities = results.filter(
  (r) => r.vulnerable && r.confidence === "high",
);

// Check manual review flags
const needsReview = vulnerabilities.filter((v) => v.requiresManualReview);
console.log(`${needsReview.length} results need manual review`);

// Investigate specific tool
const toolResults = results.filter((r) => r.toolName === "myTool");
const lowConfidence = toolResults.filter((r) => r.confidence === "low");
console.log(`Low confidence matches: ${lowConfidence.length}`);
console.log(
  "Details:",
  lowConfidence.map((r) => r.manualReviewReason),
);
```

#### Issue: Memory Usage Growing

```typescript
// Implement periodic cleanup
setInterval(() => {
  // Clear test result cache if too large
  if (testResultCache.size > 1000) {
    // Keep only recent 500 results
    const sorted = Array.from(testResultCache.entries())
      .sort((a, b) => b[1].timestamp - a[1].timestamp)
      .slice(0, 500);

    testResultCache.clear();
    for (const [key, value] of sorted) {
      testResultCache.set(key, value);
    }
  }
}, 60000); // Every minute
```

---

## Related Documentation

- **ASSESSMENT_MODULES_API.md** - Complete API reference
- **SECURITY_PATTERNS_CATALOG.md** - Attack patterns and payloads
- **CLI_ASSESSMENT_GUIDE.md** - Command-line usage
- **ASSESSMENT_MODULE_DEVELOPER_GUIDE.md** - Creating custom modules

---

**Last Updated**: January 2025
**Target Audience**: Developers integrating assessment modules
