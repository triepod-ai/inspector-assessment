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
// Core Functions
// ============================================================================
/**
 * Emit a JSONL event to stderr for real-time machine parsing.
 * Automatically includes version field for compatibility checking.
 */
export function emitJSONL(event) {
  console.error(JSON.stringify({ ...event, version: INSPECTOR_VERSION }));
}
/**
 * Emit server_connected event after successful connection.
 */
export function emitServerConnected(serverName, transport) {
  emitJSONL({ event: "server_connected", serverName, transport });
}
/**
 * Emit tool_discovered event for each tool found.
 */
export function emitToolDiscovered(tool) {
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
export function emitToolsDiscoveryComplete(count) {
  emitJSONL({ event: "tools_discovery_complete", count });
}
/**
 * Emit assessment_complete event at the end of assessment.
 */
export function emitAssessmentComplete(
  overallStatus,
  totalTests,
  executionTime,
  outputPath,
) {
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
export function extractToolParams(schema) {
  if (!schema || typeof schema !== "object") return [];
  const s = schema;
  if (!s.properties || typeof s.properties !== "object") return [];
  const required = new Set(Array.isArray(s.required) ? s.required : []);
  const properties = s.properties;
  return Object.entries(properties).map(([name, prop]) => {
    const param = {
      name,
      type: prop.type || "any",
      required: required.has(name),
    };
    if (prop.description) {
      param.description = prop.description;
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
export function emitModuleStarted(module, estimatedTests, toolCount) {
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
export function emitTestBatch(module, completed, total, batchSize, elapsed) {
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
  module,
  status,
  score,
  testsRun,
  duration,
  enrichment,
) {
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
export function buildAUPEnrichment(aupResult, maxSamples = 10) {
  const violations = aupResult.violations || [];
  // Calculate metrics
  const metrics = {
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
  const sampled = [];
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
  tool,
  pattern,
  confidence,
  evidence,
  riskLevel,
  requiresReview,
  payload,
) {
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
  tool,
  title,
  description,
  parameters,
  inferredBehavior,
) {
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
  tool,
  title,
  description,
  parameters,
  field,
  actual,
  expected,
  confidence,
  reason,
) {
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
  tool,
  title,
  description,
  parameters,
  field,
  actual,
  inferred,
  confidence,
  isAmbiguous,
  reason,
) {
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
 * Batches test results and emits progress events at controlled intervals.
 * Flushes either when batch size reached OR interval elapsed (whichever first).
 */
export class EventBatcher {
  module;
  total;
  completed = 0;
  batchBuffer = [];
  startTime;
  lastFlushTime;
  flushIntervalMs;
  maxBatchSize;
  onBatchCallback;
  flushTimer;
  constructor(module, total, flushIntervalMs = 500, maxBatchSize = 10) {
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
  onBatch(callback) {
    this.onBatchCallback = callback;
  }
  /**
   * Add a test result to the batch buffer.
   * Triggers flush if max batch size reached.
   */
  addResult(result) {
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
  flush() {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    if (this.batchBuffer.length === 0) return;
    const batch = {
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
  updateTotal(newTotal) {
    this.total = newTotal;
  }
  /**
   * Get current progress stats.
   */
  getProgress() {
    return {
      completed: this.completed,
      total: this.total,
      elapsed: Date.now() - this.startTime,
    };
  }
}
