/**
 * Alignment Checker Module
 * Handles tool annotation alignment detection, extraction, and metrics calculation
 *
 * Extracted from ToolAnnotationAssessor.ts as part of Issue #105 refactoring.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type {
  ToolAnnotationResult,
  AssessmentStatus,
  AlignmentStatus,
  ToolParamProgress,
  AnnotationSource,
} from "@/lib/assessmentTypes";
import type {
  CompiledPatterns,
  ServerPersistenceContext,
} from "../../config/annotationPatterns";

import { scanDescriptionForPoisoning } from "./DescriptionPoisoningDetector";

/**
 * Extended Tool type with MCP annotation properties
 * The base Tool type from the SDK may not include annotation properties,
 * so we extend it to provide type safety for annotation access.
 */
interface ToolWithAnnotations extends Tool {
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    title?: string;
    rateLimit?: RateLimitConfig;
    permissions?: string | string[];
    scopes?: string[];
    supportsBulkOperations?: boolean;
  };
  metadata?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    title?: string;
    rateLimit?: RateLimitConfig;
    requiredPermission?: string;
    permissions?: string | string[];
    requiredScopes?: string[];
    scopes?: string[];
    bulkOperations?: BulkOperationsConfig;
    supportsBulkOperations?: boolean;
    maxBatchSize?: number;
    returnSchema?: Record<string, unknown>;
  };
  // Direct properties (legacy/alternative annotation locations)
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  title?: string;
  rateLimit?: RateLimitConfig;
  requiredPermission?: string;
  permissions?: string | string[];
  requiredScopes?: string[];
  scopes?: string[];
  bulkOperations?: BulkOperationsConfig;
  supportsBulkOperations?: boolean;
  returnSchema?: Record<string, unknown>;
}

interface RateLimitConfig {
  windowMs?: number;
  maxRequests?: number;
  requestsPerMinute?: number;
  requestsPerSecond?: number;
}

interface BulkOperationsConfig {
  maxBatchSize?: number;
  supportsBulk?: boolean;
}
import {
  detectAnnotationDeception,
  isActionableConfidence,
} from "./AnnotationDeceptionDetector";
import { inferBehavior } from "./BehaviorInference";

/**
 * Extracted annotation structure from a tool
 */
export interface ExtractedAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  title?: string;
  description?: string;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  source: AnnotationSource;
}

/**
 * Alignment metrics result
 */
export interface AlignmentMetricsResult {
  metrics: {
    coverage: number;
    consistency: number;
    correctness: number;
    reviewRequired: number;
  };
  alignmentBreakdown: {
    aligned: number;
    misaligned: number;
    reviewRecommended: number;
    unknown: number;
  };
}

/**
 * Extract annotations from a tool
 * Checks multiple sources in priority order: annotations object, direct properties, metadata
 */
export function extractAnnotations(tool: Tool): ExtractedAnnotations {
  const extendedTool = tool as ToolWithAnnotations;

  // Priority 1: Check annotations object (MCP 2024-11 spec)
  if (extendedTool.annotations) {
    const hasAnnotations =
      extendedTool.annotations.readOnlyHint !== undefined ||
      extendedTool.annotations.destructiveHint !== undefined;

    if (hasAnnotations) {
      return {
        readOnlyHint: extendedTool.annotations.readOnlyHint,
        destructiveHint: extendedTool.annotations.destructiveHint,
        title: extendedTool.annotations.title || extendedTool.title,
        description: tool.description,
        idempotentHint: extendedTool.annotations.idempotentHint,
        openWorldHint: extendedTool.annotations.openWorldHint,
        source: "mcp",
      };
    }
  }

  // Priority 2: Check direct properties
  if (
    extendedTool.readOnlyHint !== undefined ||
    extendedTool.destructiveHint !== undefined
  ) {
    return {
      readOnlyHint: extendedTool.readOnlyHint,
      destructiveHint: extendedTool.destructiveHint,
      title: extendedTool.title,
      description: tool.description,
      idempotentHint: extendedTool.idempotentHint,
      openWorldHint: extendedTool.openWorldHint,
      source: "mcp",
    };
  }

  // Priority 3: Check metadata
  if (extendedTool.metadata) {
    const hasMetadataAnnotations =
      extendedTool.metadata.readOnlyHint !== undefined ||
      extendedTool.metadata.destructiveHint !== undefined;

    if (hasMetadataAnnotations) {
      return {
        readOnlyHint: extendedTool.metadata.readOnlyHint,
        destructiveHint: extendedTool.metadata.destructiveHint,
        title: extendedTool.metadata.title || extendedTool.title,
        description: tool.description,
        idempotentHint: extendedTool.metadata.idempotentHint,
        openWorldHint: extendedTool.metadata.openWorldHint,
        source: "mcp",
      };
    }
  }

  return {
    title: extendedTool.title,
    description: tool.description,
    source: "none",
  };
}

/**
 * Extract extended metadata from tool (Issue #54)
 * Extracts rate limits, permissions, return schemas, and bulk operation support
 */
export function extractExtendedMetadata(
  tool: Tool,
): ToolAnnotationResult["extendedMetadata"] {
  const extendedTool = tool as ToolWithAnnotations;
  const metadata: NonNullable<ToolAnnotationResult["extendedMetadata"]> = {};

  // Rate limiting - check annotations, metadata, and direct props
  const rateLimit =
    extendedTool.rateLimit ||
    extendedTool.annotations?.rateLimit ||
    extendedTool.metadata?.rateLimit;
  if (rateLimit && typeof rateLimit === "object") {
    metadata.rateLimit = {
      windowMs: rateLimit.windowMs,
      maxRequests: rateLimit.maxRequests,
      requestsPerMinute: rateLimit.requestsPerMinute,
      requestsPerSecond: rateLimit.requestsPerSecond,
    };
  }

  // Permissions - check requiredPermission, permissions, scopes
  const permissions =
    extendedTool.requiredPermission ||
    extendedTool.permissions ||
    extendedTool.annotations?.permissions ||
    extendedTool.metadata?.requiredPermission ||
    extendedTool.metadata?.permissions;
  if (permissions) {
    const required = Array.isArray(permissions) ? permissions : [permissions];
    const scopes =
      extendedTool.scopes ||
      extendedTool.annotations?.scopes ||
      extendedTool.metadata?.scopes;
    metadata.permissions = {
      required: required.filter((p: unknown) => typeof p === "string"),
      scopes: Array.isArray(scopes)
        ? scopes.filter((s: unknown) => typeof s === "string")
        : undefined,
    };
  }

  // Return schema - check outputSchema (MCP 2025-06-18 spec)
  if (extendedTool.outputSchema) {
    metadata.returnSchema = {
      hasSchema: true,
      schema: extendedTool.outputSchema,
    };
  }

  // Bulk operations - check metadata for batch support
  const bulkSupport =
    extendedTool.supportsBulkOperations ||
    extendedTool.annotations?.supportsBulkOperations ||
    extendedTool.metadata?.supportsBulkOperations;
  const maxBatchSize = extendedTool.metadata?.maxBatchSize;
  if (bulkSupport !== undefined || maxBatchSize !== undefined) {
    metadata.bulkOperations = {
      supported: !!bulkSupport,
      maxBatchSize: typeof maxBatchSize === "number" ? maxBatchSize : undefined,
    };
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

/**
 * Extract parameters from tool input schema
 */
export function extractToolParams(schema: unknown): ToolParamProgress[] {
  if (!schema || typeof schema !== "object") return [];
  const s = schema as Record<string, unknown>;
  if (!s.properties || typeof s.properties !== "object") return [];

  const required = new Set(
    Array.isArray(s.required) ? (s.required as string[]) : [],
  );
  const properties = s.properties as Record<string, Record<string, unknown>>;

  return Object.entries(properties).map(([name, prop]) => {
    const param: ToolParamProgress = {
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
 * Assess a single tool's annotations
 */
export function assessSingleTool(
  tool: Tool,
  compiledPatterns: CompiledPatterns,
  persistenceContext?: ServerPersistenceContext,
): ToolAnnotationResult {
  const issues: string[] = [];
  const recommendations: string[] = [];

  const annotations = extractAnnotations(tool);
  const hasAnnotations =
    annotations.readOnlyHint !== undefined ||
    annotations.destructiveHint !== undefined;

  const inferredBehavior = inferBehavior(
    tool.name,
    tool.description,
    compiledPatterns,
    persistenceContext,
  );

  let alignmentStatus: AlignmentStatus = "ALIGNED";

  if (!hasAnnotations) {
    issues.push("Missing tool annotations (readOnlyHint, destructiveHint)");
    recommendations.push(
      `Add annotations to ${tool.name}: readOnlyHint=${inferredBehavior.expectedReadOnly}, destructiveHint=${inferredBehavior.expectedDestructive}`,
    );
    alignmentStatus = "UNKNOWN";
  } else {
    // Check for high-confidence deception
    const deception = detectAnnotationDeception(tool.name, {
      readOnlyHint: annotations.readOnlyHint,
      destructiveHint: annotations.destructiveHint,
    });

    if (deception) {
      alignmentStatus = "MISALIGNED";
      issues.push(`DECEPTIVE ANNOTATION: ${deception.reason}`);
      recommendations.push(
        `CRITICAL: Fix deceptive ${deception.field} for ${tool.name} - tool name contains '${deception.matchedKeyword}' which contradicts the annotation`,
      );

      if (deception.field === "readOnlyHint") {
        inferredBehavior.expectedReadOnly = false;
        inferredBehavior.confidence = "high";
        inferredBehavior.isAmbiguous = false;
        inferredBehavior.reason = deception.reason;
      } else {
        inferredBehavior.expectedDestructive = true;
        inferredBehavior.confidence = "high";
        inferredBehavior.isAmbiguous = false;
        inferredBehavior.reason = deception.reason;
      }
    } else {
      // Check for misaligned annotations
      const readOnlyMismatch =
        annotations.readOnlyHint !== undefined &&
        annotations.readOnlyHint !== inferredBehavior.expectedReadOnly;

      const destructiveMismatch =
        annotations.destructiveHint !== undefined &&
        annotations.destructiveHint !== inferredBehavior.expectedDestructive;

      if (readOnlyMismatch || destructiveMismatch) {
        if (
          !inferredBehavior.isAmbiguous &&
          isActionableConfidence(inferredBehavior.confidence)
        ) {
          alignmentStatus = "MISALIGNED";

          if (readOnlyMismatch) {
            issues.push(
              `Potentially misaligned readOnlyHint: set to ${annotations.readOnlyHint}, expected ${inferredBehavior.expectedReadOnly} based on tool name pattern`,
            );
            recommendations.push(
              `Verify readOnlyHint for ${tool.name}: currently ${annotations.readOnlyHint}, tool name suggests ${inferredBehavior.expectedReadOnly}`,
            );
          }
          if (destructiveMismatch) {
            issues.push(
              `Potentially misaligned destructiveHint: set to ${annotations.destructiveHint}, expected ${inferredBehavior.expectedDestructive} based on tool name pattern`,
            );
            recommendations.push(
              `Verify destructiveHint for ${tool.name}: currently ${annotations.destructiveHint}, tool name suggests ${inferredBehavior.expectedDestructive}`,
            );
          }
        }
      }
    }
  }

  // Check for destructive tools without explicit hint
  if (
    inferredBehavior.expectedDestructive &&
    isActionableConfidence(inferredBehavior.confidence) &&
    annotations.destructiveHint !== true
  ) {
    issues.push(
      "Tool appears destructive but destructiveHint is not set to true",
    );
    recommendations.push(
      `Set destructiveHint=true for ${tool.name} - this tool appears to perform destructive operations`,
    );
    if (inferredBehavior.confidence === "high") {
      alignmentStatus = "MISALIGNED";
    }
  }

  // Scan for description poisoning
  const descriptionPoisoning = scanDescriptionForPoisoning(tool);
  if (descriptionPoisoning.detected) {
    issues.push(
      `Tool description contains suspicious patterns: ${descriptionPoisoning.patterns.map((p) => p.name).join(", ")}`,
    );
    recommendations.push(
      `Review ${tool.name} description for potential prompt injection or hidden instructions`,
    );
  }

  // Extract extended metadata (Issue #54)
  const extendedMetadata = extractExtendedMetadata(tool);

  return {
    toolName: tool.name,
    hasAnnotations,
    annotations: hasAnnotations ? annotations : undefined,
    annotationSource: annotations.source,
    inferredBehavior,
    alignmentStatus,
    issues,
    recommendations,
    descriptionPoisoning,
    extendedMetadata,
  };
}

/**
 * Determine overall status based on tool results
 */
export function determineAnnotationStatus(
  results: ToolAnnotationResult[],
  totalTools: number,
): AssessmentStatus {
  if (totalTools === 0) return "PASS";

  const annotatedCount = results.filter((r) => r.hasAnnotations).length;
  const poisonedCount = results.filter(
    (r) => r.descriptionPoisoning?.detected === true,
  ).length;

  if (poisonedCount > 0) return "FAIL";

  const misalignedCount = results.filter(
    (r) => r.alignmentStatus === "MISALIGNED",
  ).length;

  const destructiveWithoutHint = results.filter(
    (r) =>
      r.inferredBehavior?.expectedDestructive === true &&
      r.inferredBehavior?.confidence === "high" &&
      r.annotations?.destructiveHint !== true,
  ).length;

  if (destructiveWithoutHint > 0) return "FAIL";
  if (misalignedCount > 0) return "FAIL";
  if (annotatedCount === totalTools) return "PASS";

  const annotationRate = annotatedCount / totalTools;
  if (annotationRate >= 0.8) return "NEED_MORE_INFO";
  if (annotationRate < 0.5) return "FAIL";

  return "NEED_MORE_INFO";
}

/**
 * Calculate metrics and alignment breakdown
 */
export function calculateMetrics(
  results: ToolAnnotationResult[],
  totalTools: number,
): AlignmentMetricsResult {
  const alignmentBreakdown = {
    aligned: results.filter((r) => r.alignmentStatus === "ALIGNED").length,
    misaligned: results.filter((r) => r.alignmentStatus === "MISALIGNED")
      .length,
    reviewRecommended: results.filter(
      (r) => r.alignmentStatus === "REVIEW_RECOMMENDED",
    ).length,
    unknown: results.filter((r) => r.alignmentStatus === "UNKNOWN").length,
  };

  const annotatedCount = results.filter((r) => r.hasAnnotations).length;

  const metrics = {
    coverage: totalTools > 0 ? (annotatedCount / totalTools) * 100 : 100,
    consistency:
      totalTools > 0
        ? ((totalTools - alignmentBreakdown.misaligned) / totalTools) * 100
        : 100,
    correctness:
      annotatedCount > 0
        ? (alignmentBreakdown.aligned / annotatedCount) * 100
        : 0,
    reviewRequired: alignmentBreakdown.reviewRecommended,
  };

  return { metrics, alignmentBreakdown };
}
