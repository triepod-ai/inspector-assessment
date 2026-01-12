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
  SCHEMA_VERSION,
} from "../../client/src/lib/moduleScoring.js";

import {
  normalizeModuleKey,
  INSPECTOR_VERSION,
  SCHEMA_VERSION,
} from "../../client/src/lib/moduleScoring.js";
import { DEFAULT_PERFORMANCE_CONFIG } from "../../client/src/services/assessment/config/performanceConfig.js";

// ============================================================================
// Types
// ============================================================================

export interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

/**
 * Base interface for all JSONL events.
 * All events include version (software version) and schemaVersion (event schema version)
 * for compatibility checking and schema evolution.
 */
export interface BaseEvent {
  /** Inspector software version (e.g., "1.29.0") */
  version: string;
  /** Event schema version (integer, increment when structure changes) */
  schemaVersion: number;
}

export interface ServerConnectedEvent extends BaseEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
}

export interface ToolDiscoveredEvent extends BaseEvent {
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
}

export interface ToolsDiscoveryCompleteEvent extends BaseEvent {
  event: "tools_discovery_complete";
  count: number;
}

export interface AssessmentCompleteEvent extends BaseEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
}

// New events for real-time progress tracking
export interface ModuleStartedEvent extends BaseEvent {
  event: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
}

export interface TestBatchEvent extends BaseEvent {
  event: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

export interface ModuleCompleteEvent extends BaseEvent {
  event: "module_complete";
  module: string;
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  score: number;
  testsRun: number;
  duration: number;
  // AUP-specific enrichment (only present when module=aup)
  violationsSample?: AUPViolationSample[];
  samplingNote?: string;
  violationMetrics?: AUPViolationMetrics;
  scannedLocations?: AUPScannedLocations;
  highRiskDomains?: string[];
}

/**
 * Sampled AUP violation for JSONL output.
 * Contains essential fields for Claude analysis without full violation details.
 */
export interface AUPViolationSample {
  category: string;
  categoryName: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  matchedText: string;
  location: "tool_name" | "tool_description" | "readme" | "source_code";
  confidence: "high" | "medium" | "low";
}

/**
 * Quantitative metrics about AUP violations for quick assessment.
 */
export interface AUPViolationMetrics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  byCategory: Record<string, number>;
}

/**
 * Tracks which locations were scanned for AUP compliance.
 */
export interface AUPScannedLocations {
  toolNames: boolean;
  toolDescriptions: boolean;
  readme: boolean;
  sourceCode: boolean;
}

/**
 * AUP enrichment data for module_complete events.
 */
export interface AUPEnrichment {
  violationsSample: AUPViolationSample[];
  samplingNote: string;
  violationMetrics: AUPViolationMetrics;
  scannedLocations: AUPScannedLocations;
  highRiskDomains: string[];
}

// Real-time security vulnerability detection event
export interface VulnerabilityFoundEvent extends BaseEvent {
  event: "vulnerability_found";
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string; // The test payload that triggered the vulnerability
}

// Tool annotation events for real-time annotation status reporting
export interface AnnotationMissingEvent extends BaseEvent {
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

export interface AnnotationMisalignedEvent extends BaseEvent {
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
export interface AnnotationReviewRecommendedEvent extends BaseEvent {
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

/**
 * Event emitted when tool annotations correctly match inferred behavior.
 */
export interface AnnotationAlignedEvent extends BaseEvent {
  event: "annotation_aligned";
  tool: string;
  confidence: "high" | "medium" | "low";
  annotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    openWorldHint?: boolean;
    idempotentHint?: boolean;
  };
}

// ============================================================================
// Phase 7 Events - Per-Tool Testing & Phase Lifecycle
// ============================================================================

/**
 * Emitted after all tests for a single tool complete.
 * Provides per-tool summary for real-time progress in auditor UI.
 */
export interface ToolTestCompleteEvent extends BaseEvent {
  event: "tool_test_complete";
  tool: string;
  module: string;
  scenariosPassed: number;
  scenariosExecuted: number;
  confidence: "high" | "medium" | "low";
  status: "PASS" | "FAIL" | "ERROR";
  executionTime: number;
}

/**
 * Emitted with per-tool input validation metrics.
 * Tracks how tools handle invalid inputs (wrong types, missing required, etc.)
 */
export interface ValidationSummaryEvent extends BaseEvent {
  event: "validation_summary";
  tool: string;
  wrongType: number;
  missingRequired: number;
  extraParams: number;
  nullValues: number;
  invalidValues: number;
}

/**
 * Emitted when an assessment phase begins.
 * Used for high-level progress tracking (discovery, assessment, analysis).
 */
export interface PhaseStartedEvent extends BaseEvent {
  event: "phase_started";
  phase: string;
}

/**
 * Emitted when an assessment phase completes.
 * Includes duration for performance tracking.
 */
export interface PhaseCompleteEvent extends BaseEvent {
  event: "phase_complete";
  phase: string;
  duration: number;
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
  | AnnotationReviewRecommendedEvent
  | AnnotationAlignedEvent
  | ToolTestCompleteEvent
  | ValidationSummaryEvent
  | PhaseStartedEvent
  | PhaseCompleteEvent;

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Emit a JSONL event to stderr for real-time machine parsing.
 * Automatically includes version and schemaVersion fields for compatibility checking.
 */
export function emitJSONL(event: Record<string, unknown>): void {
  console.error(
    JSON.stringify({
      ...event,
      version: INSPECTOR_VERSION,
      schemaVersion: SCHEMA_VERSION,
    }),
  );
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
 * Includes annotations if the server provides them.
 */
export function emitToolDiscovered(tool: Tool): void {
  const params = extractToolParams(tool.inputSchema);

  // Extract annotations, null if not present
  const annotations = tool.annotations
    ? {
        readOnlyHint: tool.annotations.readOnlyHint,
        destructiveHint: tool.annotations.destructiveHint,
        idempotentHint: tool.annotations.idempotentHint,
        openWorldHint: tool.annotations.openWorldHint,
      }
    : null;

  emitJSONL({
    event: "tool_discovered",
    name: tool.name,
    description: tool.description || null,
    params,
    annotations,
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
 * For AUP module, enrichment can include violation samples and metrics.
 */
export function emitModuleComplete(
  module: string,
  status: "PASS" | "FAIL" | "NEED_MORE_INFO",
  score: number,
  testsRun: number,
  duration: number,
  enrichment?: AUPEnrichment,
): void {
  emitJSONL({
    event: "module_complete",
    module: normalizeModuleKey(module),
    status,
    score,
    testsRun,
    duration,
    ...(enrichment && {
      violationsSample: enrichment.violationsSample,
      samplingNote: enrichment.samplingNote,
      violationMetrics: enrichment.violationMetrics,
      scannedLocations: enrichment.scannedLocations,
      highRiskDomains: enrichment.highRiskDomains,
    }),
  });
}

// ============================================================================
// AUP Enrichment Helpers
// ============================================================================

/**
 * Build AUP enrichment data from an AUP compliance assessment result.
 * Samples violations prioritizing by severity (CRITICAL > HIGH > MEDIUM).
 *
 * @param aupResult - The raw AUP compliance assessment result
 * @param maxSamples - Maximum number of violations to include (default: 10)
 * @returns AUP enrichment data for module_complete event
 */
export function buildAUPEnrichment(
  aupResult: {
    violations?: Array<{
      category: string;
      categoryName: string;
      severity: "CRITICAL" | "HIGH" | "MEDIUM";
      matchedText: string;
      location: "tool_name" | "tool_description" | "readme" | "source_code";
      confidence: "high" | "medium" | "low";
    }>;
    highRiskDomains?: string[];
    scannedLocations?: {
      toolNames: boolean;
      toolDescriptions: boolean;
      readme: boolean;
      sourceCode: boolean;
    };
  },
  maxSamples: number = 10,
): AUPEnrichment {
  const violations = aupResult.violations || [];

  // Calculate metrics
  const metrics: AUPViolationMetrics = {
    total: violations.length,
    critical: violations.filter((v) => v.severity === "CRITICAL").length,
    high: violations.filter((v) => v.severity === "HIGH").length,
    medium: violations.filter((v) => v.severity === "MEDIUM").length,
    byCategory: {},
  };

  // Count by category
  for (const v of violations) {
    metrics.byCategory[v.category] = (metrics.byCategory[v.category] || 0) + 1;
  }

  // Sample violations prioritizing by severity
  const sampled: AUPViolationSample[] = [];
  const severityOrder: Array<"CRITICAL" | "HIGH" | "MEDIUM"> = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
  ];

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

  // Build sampling note
  let samplingNote = "";
  if (violations.length === 0) {
    samplingNote = "No violations detected.";
  } else if (violations.length <= maxSamples) {
    samplingNote = `All ${violations.length} violation(s) included.`;
  } else {
    samplingNote = `Sampled ${sampled.length} of ${violations.length} violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).`;
  }

  return {
    violationsSample: sampled,
    samplingNote,
    violationMetrics: metrics,
    scannedLocations: aupResult.scannedLocations || {
      toolNames: false,
      toolDescriptions: false,
      readme: false,
      sourceCode: false,
    },
    highRiskDomains: (aupResult.highRiskDomains || []).slice(0, 10),
  };
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

/**
 * Emit annotation_aligned event when tool annotations correctly match behavior.
 * This provides real-time confirmation during annotation assessment.
 */
export function emitAnnotationAligned(
  tool: string,
  confidence: "high" | "medium" | "low",
  annotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    openWorldHint?: boolean;
    idempotentHint?: boolean;
  },
): void {
  emitJSONL({
    event: "annotation_aligned",
    tool,
    confidence,
    annotations,
  });
}

/**
 * Emit modules_configured event to inform consumers which modules are enabled.
 * Useful for accurate progress tracking when using --skip-modules or --only-modules.
 */
export function emitModulesConfigured(
  enabled: string[],
  skipped: string[],
  reason: "skip-modules" | "only-modules" | "default",
): void {
  emitJSONL({
    event: "modules_configured",
    enabled,
    skipped,
    reason,
  });
}

// ============================================================================
// Phase 7 Events - Per-Tool Testing & Phase Lifecycle
// ============================================================================

/**
 * Emit tool_test_complete event after all tests for a single tool finish.
 * Provides per-tool summary for real-time progress in auditor UI.
 */
export function emitToolTestComplete(
  tool: string,
  module: string,
  scenariosPassed: number,
  scenariosExecuted: number,
  confidence: "high" | "medium" | "low",
  status: "PASS" | "FAIL" | "ERROR",
  executionTime: number,
): void {
  emitJSONL({
    event: "tool_test_complete",
    tool,
    module,
    scenariosPassed,
    scenariosExecuted,
    confidence,
    status,
    executionTime,
  });
}

/**
 * Emit validation_summary event with per-tool input validation metrics.
 * Tracks how tools handle invalid inputs (wrong types, missing required, etc.)
 */
export function emitValidationSummary(
  tool: string,
  wrongType: number,
  missingRequired: number,
  extraParams: number,
  nullValues: number,
  invalidValues: number,
): void {
  emitJSONL({
    event: "validation_summary",
    tool,
    wrongType,
    missingRequired,
    extraParams,
    nullValues,
    invalidValues,
  });
}

// ============================================================================
// Tiered Output Events (Issue #136)
// ============================================================================

/**
 * Event emitted when tiered output is generated.
 * Contains paths and token estimates for each tier.
 *
 * NOTE: This interface and emitTieredOutput() function are duplicated in
 * cli/src/lib/jsonl-events.ts to avoid module dependency issues between
 * CLI and scripts workspaces. This is an architectural constraint, not a bug.
 * Any changes to this interface MUST be kept in sync with the CLI version.
 */
export interface TieredOutputEvent extends BaseEvent {
  event: "tiered_output_generated";
  outputDir: string;
  outputFormat: "tiered" | "summary-only";
  tiers: {
    executiveSummary: {
      path: string;
      estimatedTokens: number;
    };
    toolSummaries: {
      path: string;
      estimatedTokens: number;
      toolCount: number;
    };
    toolDetails?: {
      directory: string;
      fileCount: number;
      totalEstimatedTokens: number;
    };
  };
}

/**
 * Emit tiered_output_generated event when tiered output is created.
 * Issue #136: Tiered output strategy for large assessments
 *
 * NOTE: This function is duplicated in cli/src/lib/jsonl-events.ts.
 * Keep both implementations in sync. See TieredOutputEvent comment above.
 */
export function emitTieredOutput(
  outputDir: string,
  outputFormat: "tiered" | "summary-only",
  tiers: TieredOutputEvent["tiers"],
): void {
  emitJSONL({
    event: "tiered_output_generated",
    outputDir,
    outputFormat,
    tiers,
  });
}

/**
 * Emit phase_started event when an assessment phase begins.
 * Used for high-level progress tracking (discovery, assessment, analysis).
 */
export function emitPhaseStarted(phase: string): void {
  emitJSONL({
    event: "phase_started",
    phase,
  });
}

/**
 * Emit phase_complete event when an assessment phase finishes.
 * Includes duration for performance tracking.
 */
export function emitPhaseComplete(phase: string, duration: number): void {
  emitJSONL({
    event: "phase_complete",
    phase,
    duration,
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

  /**
   * Create a new EventBatcher.
   *
   * @param module - Module name for progress tracking
   * @param total - Total number of tests expected
   * @param flushIntervalMs - Interval between flushes (default from PerformanceConfig)
   * @param maxBatchSize - Maximum batch size before flush (default from PerformanceConfig)
   */
  constructor(
    module: string,
    total: number,
    flushIntervalMs: number = DEFAULT_PERFORMANCE_CONFIG.batchFlushIntervalMs,
    maxBatchSize: number = DEFAULT_PERFORMANCE_CONFIG.securityBatchSize,
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
