/**
 * JSONL Event Emission Helpers
 *
 * These functions emit structured JSONL events to stderr for real-time
 * machine parsing during CLI assessment runs.
 *
 * Event Types:
 * - server_connected: Emitted after successful MCP connection
 * - tool_discovered: Emitted for each tool found
 * - tools_discovery_complete: Emitted after all tools listed
 * - assessment_complete: Emitted at end of assessment
 *
 * Shared helpers (normalizeModuleKey, calculateModuleScore) are imported from
 * client/src/lib/moduleScoring.ts to maintain a single source of truth.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Import and re-export shared helpers from client module
// This maintains a single source of truth for scoring and normalization logic
export {
  normalizeModuleKey,
  calculateModuleScore,
  INSPECTOR_VERSION,
} from "../../client/src/lib/moduleScoring.js";

import {
  normalizeModuleKey,
  INSPECTOR_VERSION,
} from "../../client/src/lib/moduleScoring.js";

// ============================================================================
// Types
// ============================================================================

export interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

export interface ServerConnectedEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
}

export interface ToolDiscoveredEvent {
  event: "tool_discovered";
  name: string;
  description: string | null;
  params: ToolParam[];
}

export interface ToolsDiscoveryCompleteEvent {
  event: "tools_discovery_complete";
  count: number;
}

export interface AssessmentCompleteEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
}

// New events for real-time progress tracking
export interface ModuleStartedEvent {
  event: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
}

export interface TestBatchEvent {
  event: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

export interface ModuleCompleteEvent {
  event: "module_complete";
  module: string;
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  score: number;
  testsRun: number;
  duration: number;
}

// Real-time security vulnerability detection event
export interface VulnerabilityFoundEvent {
  event: "vulnerability_found";
  version: string;
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string; // The test payload that triggered the vulnerability
}

// Tool annotation events for real-time annotation status reporting
export interface AnnotationMissingEvent {
  event: "annotation_missing";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParam[];
  inferredBehavior: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
  };
}

export interface AnnotationMisalignedEvent {
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
}

/**
 * Event emitted when annotation alignment cannot be confidently determined.
 * Used for ambiguous patterns like store_*, queue_*, cache_* where behavior
 * varies by implementation context. Does not indicate a failure - just flags
 * for human review.
 */
export interface AnnotationReviewRecommendedEvent {
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
}

export type JSONLEvent =
  | ServerConnectedEvent
  | ToolDiscoveredEvent
  | ToolsDiscoveryCompleteEvent
  | AssessmentCompleteEvent
  | ModuleStartedEvent
  | TestBatchEvent
  | ModuleCompleteEvent
  | VulnerabilityFoundEvent
  | AnnotationMissingEvent
  | AnnotationMisalignedEvent
  | AnnotationReviewRecommendedEvent;

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Emit a JSONL event to stderr for real-time machine parsing.
 * Automatically includes version field for compatibility checking.
 */
export function emitJSONL(event: Record<string, unknown>): void {
  console.error(JSON.stringify({ ...event, version: INSPECTOR_VERSION }));
}

/**
 * Emit server_connected event after successful connection.
 */
export function emitServerConnected(
  serverName: string,
  transport: "stdio" | "http" | "sse",
): void {
  emitJSONL({ event: "server_connected", serverName, transport });
}

/**
 * Emit tool_discovered event for each tool found.
 */
export function emitToolDiscovered(tool: Tool): void {
  const params = extractToolParams(tool.inputSchema);
  emitJSONL({
    event: "tool_discovered",
    name: tool.name,
    description: tool.description || null,
    params,
  });
}

/**
 * Emit tools_discovery_complete event after all tools discovered.
 */
export function emitToolsDiscoveryComplete(count: number): void {
  emitJSONL({ event: "tools_discovery_complete", count });
}

/**
 * Emit assessment_complete event at the end of assessment.
 */
export function emitAssessmentComplete(
  overallStatus: string,
  totalTests: number,
  executionTime: number,
  outputPath: string,
): void {
  emitJSONL({
    event: "assessment_complete",
    overallStatus,
    totalTests,
    executionTime,
    outputPath,
  });
}

/**
 * Extract parameter metadata from tool input schema.
 */
export function extractToolParams(schema: unknown): ToolParam[] {
  if (!schema || typeof schema !== "object") return [];
  const s = schema as Record<string, unknown>;
  if (!s.properties || typeof s.properties !== "object") return [];

  const required = new Set(
    Array.isArray(s.required) ? (s.required as string[]) : [],
  );
  const properties = s.properties as Record<string, Record<string, unknown>>;

  return Object.entries(properties).map(([name, prop]) => {
    const param: ToolParam = {
      name,
      type: (prop.type as string) || "any",
      required: required.has(name),
    };
    if (prop.description) {
      param.description = prop.description as string;
    }
    return param;
  });
}

// ============================================================================
// New Progress Event Emitters
// ============================================================================

/**
 * Emit module_started event before assessment module begins.
 * Module name is normalized to snake_case for consistent parsing.
 */
export function emitModuleStarted(
  module: string,
  estimatedTests: number,
  toolCount: number,
): void {
  emitJSONL({
    event: "module_started",
    module: normalizeModuleKey(module),
    estimatedTests,
    toolCount,
  });
}

/**
 * Emit test_batch event during assessment for real-time progress.
 */
export function emitTestBatch(
  module: string,
  completed: number,
  total: number,
  batchSize: number,
  elapsed: number,
): void {
  emitJSONL({
    event: "test_batch",
    module,
    completed,
    total,
    batchSize,
    elapsed,
  });
}

/**
 * Emit module_complete event with enhanced data.
 * Module name is normalized to snake_case for consistent parsing.
 */
export function emitModuleComplete(
  module: string,
  status: "PASS" | "FAIL" | "NEED_MORE_INFO",
  score: number,
  testsRun: number,
  duration: number,
): void {
  emitJSONL({
    event: "module_complete",
    module: normalizeModuleKey(module),
    status,
    score,
    testsRun,
    duration,
  });
}

/**
 * Emit vulnerability_found event when a security vulnerability is detected.
 * This provides real-time alerts during security assessment.
 */
export function emitVulnerabilityFound(
  tool: string,
  pattern: string,
  confidence: "high" | "medium" | "low",
  evidence: string,
  riskLevel: "HIGH" | "MEDIUM" | "LOW",
  requiresReview: boolean,
  payload?: string,
): void {
  emitJSONL({
    event: "vulnerability_found",
    tool,
    pattern,
    confidence,
    evidence,
    riskLevel,
    requiresReview,
    ...(payload && { payload }),
  });
}

/**
 * Emit annotation_missing event when a tool lacks required annotations.
 * This provides real-time alerts during annotation assessment.
 */
export function emitAnnotationMissing(
  tool: string,
  title: string | undefined,
  description: string | undefined,
  parameters: ToolParam[],
  inferredBehavior: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
  },
): void {
  emitJSONL({
    event: "annotation_missing",
    tool,
    ...(title && { title }),
    ...(description && { description }),
    parameters,
    inferredBehavior,
  });
}

/**
 * Emit annotation_misaligned event when annotations don't match inferred behavior.
 * This provides real-time alerts during annotation assessment.
 */
export function emitAnnotationMisaligned(
  tool: string,
  title: string | undefined,
  description: string | undefined,
  parameters: ToolParam[],
  field: "readOnlyHint" | "destructiveHint",
  actual: boolean | undefined,
  expected: boolean,
  confidence: number,
  reason: string,
): void {
  emitJSONL({
    event: "annotation_misaligned",
    tool,
    ...(title && { title }),
    ...(description && { description }),
    parameters,
    field,
    actual,
    expected,
    confidence,
    reason,
  });
}

/**
 * Emit annotation_review_recommended event for ambiguous patterns.
 * This indicates human review is suggested but no automated penalty applied.
 * Used for patterns like store_*, queue_*, cache_* where behavior varies.
 */
export function emitAnnotationReviewRecommended(
  tool: string,
  title: string | undefined,
  description: string | undefined,
  parameters: ToolParam[],
  field: "readOnlyHint" | "destructiveHint",
  actual: boolean | undefined,
  inferred: boolean,
  confidence: "high" | "medium" | "low",
  isAmbiguous: boolean,
  reason: string,
): void {
  emitJSONL({
    event: "annotation_review_recommended",
    tool,
    ...(title && { title }),
    ...(description && { description }),
    parameters,
    field,
    actual,
    inferred,
    confidence,
    isAmbiguous,
    reason,
  });
}

// ============================================================================
// EventBatcher - Batches test progress events for volume control
// ============================================================================

export interface TestResult {
  toolName: string;
  testName: string;
  passed: boolean;
}

export interface TestBatch {
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

/**
 * Batches test results and emits progress events at controlled intervals.
 * Flushes either when batch size reached OR interval elapsed (whichever first).
 */
export class EventBatcher {
  private module: string;
  private total: number;
  private completed: number = 0;
  private batchBuffer: TestResult[] = [];
  private startTime: number;
  private lastFlushTime: number;
  private flushIntervalMs: number;
  private maxBatchSize: number;
  private onBatchCallback?: (batch: TestBatch) => void;
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(
    module: string,
    total: number,
    flushIntervalMs: number = 500,
    maxBatchSize: number = 10,
  ) {
    this.module = module;
    this.total = total;
    this.flushIntervalMs = flushIntervalMs;
    this.maxBatchSize = maxBatchSize;
    this.startTime = Date.now();
    this.lastFlushTime = this.startTime;
  }

  /**
   * Register callback for batch events.
   */
  onBatch(callback: (batch: TestBatch) => void): void {
    this.onBatchCallback = callback;
  }

  /**
   * Add a test result to the batch buffer.
   * Triggers flush if max batch size reached.
   */
  addResult(result: TestResult): void {
    this.completed++;
    this.batchBuffer.push(result);

    // Check if we should flush
    const now = Date.now();
    const timeSinceLastFlush = now - this.lastFlushTime;

    if (
      this.batchBuffer.length >= this.maxBatchSize ||
      timeSinceLastFlush >= this.flushIntervalMs
    ) {
      this.flush();
    } else if (!this.flushTimer) {
      // Set a timer to flush after interval if nothing else triggers it
      this.flushTimer = setTimeout(() => {
        if (this.batchBuffer.length > 0) {
          this.flush();
        }
      }, this.flushIntervalMs - timeSinceLastFlush);
    }
  }

  /**
   * Force flush the current batch buffer.
   */
  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    if (this.batchBuffer.length === 0) return;

    const batch: TestBatch = {
      module: this.module,
      completed: this.completed,
      total: this.total,
      batchSize: this.batchBuffer.length,
      elapsed: Date.now() - this.startTime,
    };

    // Clear buffer before callback to prevent re-entrancy issues
    this.batchBuffer = [];
    this.lastFlushTime = Date.now();

    // Emit via JSONL
    emitTestBatch(
      batch.module,
      batch.completed,
      batch.total,
      batch.batchSize,
      batch.elapsed,
    );

    // Call registered callback
    if (this.onBatchCallback) {
      this.onBatchCallback(batch);
    }
  }

  /**
   * Update the total test count (useful when estimate changes).
   */
  updateTotal(newTotal: number): void {
    this.total = newTotal;
  }

  /**
   * Get current progress stats.
   */
  getProgress(): { completed: number; total: number; elapsed: number } {
    return {
      completed: this.completed,
      total: this.total,
      elapsed: Date.now() - this.startTime,
    };
  }
}
