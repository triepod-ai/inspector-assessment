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
 *
 * Issue #155: Check multiple locations for annotations:
 * 1. tool.annotations object (MCP 2024-11 spec)
 * 2. Direct properties (tool.readOnlyHint, etc.)
 * 3. tool.metadata object
 * 4. tool._meta object
 */
export function emitToolDiscovered(tool: Tool): void {
  const params = extractToolParams(tool.inputSchema);

  // Issue #155: Extract annotations from multiple sources (priority order)
  // Issue #160: Also check non-suffixed variants (readOnly, destructive, etc.)
  // for servers that use the shorter property names instead of *Hint versions.
  const toolAny = tool as Record<string, unknown>;
  const annotationsAny = tool.annotations as
    | Record<string, unknown>
    | undefined;

  // Priority 1: Check tool.annotations object (MCP spec)
  // Issue #160: Use nullish coalescing to fall back to non-suffixed versions
  let readOnlyHint: boolean | undefined;
  let destructiveHint: boolean | undefined;
  let idempotentHint: boolean | undefined;
  let openWorldHint: boolean | undefined;

  if (annotationsAny) {
    // Check *Hint version first, fall back to non-suffixed (Issue #160)
    if (typeof annotationsAny.readOnlyHint === "boolean") {
      readOnlyHint = annotationsAny.readOnlyHint;
    } else if (typeof annotationsAny.readOnly === "boolean") {
      readOnlyHint = annotationsAny.readOnly;
    }
    if (typeof annotationsAny.destructiveHint === "boolean") {
      destructiveHint = annotationsAny.destructiveHint;
    } else if (typeof annotationsAny.destructive === "boolean") {
      destructiveHint = annotationsAny.destructive;
    }
    if (typeof annotationsAny.idempotentHint === "boolean") {
      idempotentHint = annotationsAny.idempotentHint;
    } else if (typeof annotationsAny.idempotent === "boolean") {
      idempotentHint = annotationsAny.idempotent;
    }
    if (typeof annotationsAny.openWorldHint === "boolean") {
      openWorldHint = annotationsAny.openWorldHint;
    } else if (typeof annotationsAny.openWorld === "boolean") {
      openWorldHint = annotationsAny.openWorld;
    }
  }

  // Priority 2: Check direct properties on tool object
  // Only use if not already found in annotations
  // Issue #160: Check both *Hint and non-suffixed versions
  if (readOnlyHint === undefined) {
    if (typeof toolAny.readOnlyHint === "boolean") {
      readOnlyHint = toolAny.readOnlyHint;
    } else if (typeof toolAny.readOnly === "boolean") {
      readOnlyHint = toolAny.readOnly;
    }
  }
  if (destructiveHint === undefined) {
    if (typeof toolAny.destructiveHint === "boolean") {
      destructiveHint = toolAny.destructiveHint;
    } else if (typeof toolAny.destructive === "boolean") {
      destructiveHint = toolAny.destructive;
    }
  }
  if (idempotentHint === undefined) {
    if (typeof toolAny.idempotentHint === "boolean") {
      idempotentHint = toolAny.idempotentHint;
    } else if (typeof toolAny.idempotent === "boolean") {
      idempotentHint = toolAny.idempotent;
    }
  }
  if (openWorldHint === undefined) {
    if (typeof toolAny.openWorldHint === "boolean") {
      openWorldHint = toolAny.openWorldHint;
    } else if (typeof toolAny.openWorld === "boolean") {
      openWorldHint = toolAny.openWorld;
    }
  }

  // Priority 3: Check tool.metadata object
  // Issue #160: Check both *Hint and non-suffixed versions
  const metadata = toolAny.metadata as Record<string, unknown> | undefined;
  if (metadata) {
    if (readOnlyHint === undefined) {
      if (typeof metadata.readOnlyHint === "boolean") {
        readOnlyHint = metadata.readOnlyHint;
      } else if (typeof metadata.readOnly === "boolean") {
        readOnlyHint = metadata.readOnly;
      }
    }
    if (destructiveHint === undefined) {
      if (typeof metadata.destructiveHint === "boolean") {
        destructiveHint = metadata.destructiveHint;
      } else if (typeof metadata.destructive === "boolean") {
        destructiveHint = metadata.destructive;
      }
    }
    if (idempotentHint === undefined) {
      if (typeof metadata.idempotentHint === "boolean") {
        idempotentHint = metadata.idempotentHint;
      } else if (typeof metadata.idempotent === "boolean") {
        idempotentHint = metadata.idempotent;
      }
    }
    if (openWorldHint === undefined) {
      if (typeof metadata.openWorldHint === "boolean") {
        openWorldHint = metadata.openWorldHint;
      } else if (typeof metadata.openWorld === "boolean") {
        openWorldHint = metadata.openWorld;
      }
    }
  }

  // Priority 4: Check tool._meta object
  // Issue #160: Check both *Hint and non-suffixed versions
  const _meta = toolAny._meta as Record<string, unknown> | undefined;
  if (_meta) {
    if (readOnlyHint === undefined) {
      if (typeof _meta.readOnlyHint === "boolean") {
        readOnlyHint = _meta.readOnlyHint;
      } else if (typeof _meta.readOnly === "boolean") {
        readOnlyHint = _meta.readOnly;
      }
    }
    if (destructiveHint === undefined) {
      if (typeof _meta.destructiveHint === "boolean") {
        destructiveHint = _meta.destructiveHint;
      } else if (typeof _meta.destructive === "boolean") {
        destructiveHint = _meta.destructive;
      }
    }
    if (idempotentHint === undefined) {
      if (typeof _meta.idempotentHint === "boolean") {
        idempotentHint = _meta.idempotentHint;
      } else if (typeof _meta.idempotent === "boolean") {
        idempotentHint = _meta.idempotent;
      }
    }
    if (openWorldHint === undefined) {
      if (typeof _meta.openWorldHint === "boolean") {
        openWorldHint = _meta.openWorldHint;
      } else if (typeof _meta.openWorld === "boolean") {
        openWorldHint = _meta.openWorld;
      }
    }
  }

  // Build annotations object if any hints were found
  const hasAnnotations =
    readOnlyHint !== undefined ||
    destructiveHint !== undefined ||
    idempotentHint !== undefined ||
    openWorldHint !== undefined;

  const annotations = hasAnnotations
    ? {
        readOnlyHint,
        destructiveHint,
        idempotentHint,
        openWorldHint,
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

// ============================================================================
// Native Module Warning Events - Issue #212
// ============================================================================

/**
 * Emit native_module_warning event when native modules detected in package.json.
 * This is a pre-flight warning that doesn't block assessment, but alerts
 * users to potential issues with native binaries being blocked by Gatekeeper.
 *
 * @param moduleName - Name of the detected native module (e.g., "canvas")
 * @param category - Module category (image, database, graphics, system, crypto)
 * @param severity - Impact severity (HIGH or MEDIUM)
 * @param warningMessage - Human-readable warning about potential issues
 * @param dependencyType - Where found (dependencies, devDependencies, optionalDependencies)
 * @param version - Version specifier from package.json
 * @param suggestedEnvVars - Optional environment variables to mitigate issues
 */
export function emitNativeModuleWarning(
  moduleName: string,
  category: string,
  severity: "HIGH" | "MEDIUM",
  warningMessage: string,
  dependencyType: string,
  version: string,
  suggestedEnvVars?: Record<string, string>,
): void {
  emitJSONL({
    event: "native_module_warning",
    moduleName,
    category,
    severity,
    warningMessage,
    dependencyType,
    version,
    ...(suggestedEnvVars &&
      Object.keys(suggestedEnvVars).length > 0 && { suggestedEnvVars }),
  });
}
