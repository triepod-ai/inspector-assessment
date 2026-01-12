/**
 * JSONL Event Emission Helpers for CLI
 *
 * These functions emit structured JSONL events to stderr for real-time
 * machine parsing during CLI assessment runs.
 *
 * This is a CLI-local version that imports from the built client lib
 * to avoid rootDir conflicts in TypeScript compilation.
 *
 * NOTE: Phase 7 events (tool_test_complete, validation_summary, phase_started,
 * phase_complete) are re-exported from scripts/lib/jsonl-events.ts to maintain
 * a single source of truth. See Issue #88.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  INSPECTOR_VERSION,
  SCHEMA_VERSION,
} from "../../../client/lib/lib/moduleScoring.js";

// Re-export for consumers of this module
export { SCHEMA_VERSION };

// ============================================================================
// Types
// ============================================================================

export interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

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
 * Emit vulnerability_found event when security testing detects issues.
 */
export function emitVulnerabilityFound(
  tool: string,
  pattern: string,
  confidence: "high" | "medium" | "low",
  evidence: string,
  riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH",
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
 * Emit annotation_misaligned event when actual annotations contradict inferred behavior.
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
// Tiered Output Events - Issue #136
// ============================================================================

/**
 * Event emitted when tiered output files are generated.
 * See Issue #136 for tiered output strategy documentation.
 *
 * NOTE: This interface and emitTieredOutput() function are duplicated in
 * scripts/lib/jsonl-events.ts to avoid module dependency issues between
 * CLI and scripts workspaces. This is an architectural constraint, not a bug.
 * Any changes to this interface MUST be kept in sync with the scripts version.
 */
export interface TieredOutputEvent {
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
 * Emit tiered_output_generated event when tiered output files are created.
 * Includes paths and token estimates for each tier.
 *
 * NOTE: This function is duplicated in scripts/lib/jsonl-events.ts.
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
