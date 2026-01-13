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

import {
  scanDescriptionForPoisoning,
  type PoisoningScanResult,
} from "./DescriptionPoisoningDetector";

/**
 * Extended Tool type with MCP annotation properties
 * The base Tool type from the SDK may not include annotation properties,
 * so we extend it to provide type safety for annotation access.
 */
interface ToolWithAnnotations extends Tool {
  annotations?: {
    // Standard MCP 2024-11 spec with *Hint suffix
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    // Issue #150: Non-suffixed fallback versions
    readOnly?: boolean;
    destructive?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
    title?: string;
    rateLimit?: RateLimitConfig;
    permissions?: string | string[];
    scopes?: string[];
    supportsBulkOperations?: boolean;
  };
  metadata?: {
    // Standard MCP 2024-11 spec with *Hint suffix
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    // Issue #150: Non-suffixed fallback versions
    readOnly?: boolean;
    destructive?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
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
  // Issue #150: Non-suffixed fallback versions
  readOnly?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  openWorld?: boolean;
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
 * Helper to resolve annotation value with fallback (Issue #150)
 * Checks *Hint suffix first (MCP spec), then non-suffixed version as fallback
 * This handles servers that use 'readOnly' instead of 'readOnlyHint'
 *
 * @param obj - The object to search for annotation properties
 * @param hintKey - The MCP spec compliant key (e.g., 'readOnlyHint')
 * @param fallbackKey - The non-suffixed fallback key (e.g., 'readOnly')
 * @returns The boolean annotation value, or undefined if not found or not a boolean
 */
function resolveAnnotationValue(
  obj: Record<string, unknown> | undefined,
  hintKey: string,
  fallbackKey: string,
): boolean | undefined {
  if (!obj) return undefined;
  // Priority: *Hint version (MCP spec)
  if (obj[hintKey] !== undefined) {
    const val = obj[hintKey];
    if (typeof val === "boolean") return val;
  }
  // Fallback: non-suffixed version (Issue #150)
  if (obj[fallbackKey] !== undefined) {
    const val = obj[fallbackKey];
    if (typeof val === "boolean") return val;
  }
  return undefined;
}

/**
 * Extract annotations from a tool
 * Checks multiple sources in priority order: annotations object, direct properties, metadata
 * Issue #150: Also checks non-suffixed property names (readOnly, destructive) as fallback
 */
export function extractAnnotations(tool: Tool): ExtractedAnnotations {
  const extendedTool = tool as ToolWithAnnotations;

  // Priority 1: Check annotations object (MCP 2024-11 spec)
  // Issue #150: Use resolveAnnotationValue to check both *Hint and non-suffixed versions
  if (extendedTool.annotations) {
    const annotationsObj = extendedTool.annotations as Record<string, unknown>;
    const readOnlyValue = resolveAnnotationValue(
      annotationsObj,
      "readOnlyHint",
      "readOnly",
    );
    const destructiveValue = resolveAnnotationValue(
      annotationsObj,
      "destructiveHint",
      "destructive",
    );

    const hasAnnotations =
      readOnlyValue !== undefined || destructiveValue !== undefined;

    if (hasAnnotations) {
      return {
        readOnlyHint: readOnlyValue,
        destructiveHint: destructiveValue,
        title: extendedTool.annotations.title || extendedTool.title,
        description: tool.description,
        idempotentHint: resolveAnnotationValue(
          annotationsObj,
          "idempotentHint",
          "idempotent",
        ),
        openWorldHint: resolveAnnotationValue(
          annotationsObj,
          "openWorldHint",
          "openWorld",
        ),
        source: "mcp",
      };
    }
  }

  // Priority 2: Check direct properties
  // Issue #150: Use resolveAnnotationValue to check both *Hint and non-suffixed versions
  const directObj = extendedTool as unknown as Record<string, unknown>;
  const directReadOnly = resolveAnnotationValue(
    directObj,
    "readOnlyHint",
    "readOnly",
  );
  const directDestructive = resolveAnnotationValue(
    directObj,
    "destructiveHint",
    "destructive",
  );

  if (directReadOnly !== undefined || directDestructive !== undefined) {
    return {
      readOnlyHint: directReadOnly,
      destructiveHint: directDestructive,
      title: extendedTool.title,
      description: tool.description,
      idempotentHint: resolveAnnotationValue(
        directObj,
        "idempotentHint",
        "idempotent",
      ),
      openWorldHint: resolveAnnotationValue(
        directObj,
        "openWorldHint",
        "openWorld",
      ),
      source: "mcp",
    };
  }

  // Priority 3: Check metadata
  // Issue #150: Use resolveAnnotationValue to check both *Hint and non-suffixed versions
  if (extendedTool.metadata) {
    const metadataObj = extendedTool.metadata as Record<string, unknown>;
    const metaReadOnly = resolveAnnotationValue(
      metadataObj,
      "readOnlyHint",
      "readOnly",
    );
    const metaDestructive = resolveAnnotationValue(
      metadataObj,
      "destructiveHint",
      "destructive",
    );

    const hasMetadataAnnotations =
      metaReadOnly !== undefined || metaDestructive !== undefined;

    if (hasMetadataAnnotations) {
      return {
        readOnlyHint: metaReadOnly,
        destructiveHint: metaDestructive,
        title: extendedTool.metadata.title || extendedTool.title,
        description: tool.description,
        idempotentHint: resolveAnnotationValue(
          metadataObj,
          "idempotentHint",
          "idempotent",
        ),
        openWorldHint: resolveAnnotationValue(
          metadataObj,
          "openWorldHint",
          "openWorld",
        ),
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
 * Scan all description fields in tool input schema for poisoning patterns
 * Issue #119, Challenge #15: Input schema description poisoning detection
 *
 * Malicious actors may embed hidden instructions in parameter descriptions
 * rather than the main tool description to evade detection.
 */
export function scanInputSchemaDescriptions(tool: Tool): PoisoningScanResult {
  const allMatches: PoisoningScanResult["patterns"] = [];

  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  if (!schema || !schema.properties) {
    return { detected: false, patterns: [], riskLevel: "NONE" };
  }

  const properties = schema.properties as Record<
    string,
    Record<string, unknown>
  >;

  for (const [propName, propDef] of Object.entries(properties)) {
    const propDescription = propDef.description as string | undefined;
    if (!propDescription) continue;

    // Create a fake tool to reuse existing scanner
    const fakeTool: Tool = {
      name: `${tool.name}.inputSchema.properties.${propName}`,
      description: propDescription,
      inputSchema: { type: "object", properties: {} },
    };

    const result = scanDescriptionForPoisoning(fakeTool);
    if (result.detected) {
      // Prefix evidence with property location for clear identification
      for (const match of result.patterns) {
        allMatches.push({
          ...match,
          evidence: `[inputSchema.properties.${propName}.description] ${match.evidence}`,
        });
      }
    }
  }

  // Calculate overall risk level
  let riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH" = "NONE";
  if (allMatches.some((m) => m.severity === "HIGH")) {
    riskLevel = "HIGH";
  } else if (allMatches.some((m) => m.severity === "MEDIUM")) {
    riskLevel = "MEDIUM";
  } else if (allMatches.length > 0) {
    riskLevel = "LOW";
  }

  return {
    detected: allMatches.length > 0,
    patterns: allMatches,
    riskLevel,
  };
}

/**
 * Merge two poisoning scan results, combining patterns and taking highest risk
 */
function mergePoisoningScanResults(
  primary: PoisoningScanResult,
  secondary: PoisoningScanResult,
): PoisoningScanResult {
  const combinedPatterns = [...primary.patterns, ...secondary.patterns];

  let riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH" = "NONE";
  if (
    primary.riskLevel === "HIGH" ||
    secondary.riskLevel === "HIGH" ||
    combinedPatterns.some((m) => m.severity === "HIGH")
  ) {
    riskLevel = "HIGH";
  } else if (
    primary.riskLevel === "MEDIUM" ||
    secondary.riskLevel === "MEDIUM" ||
    combinedPatterns.some((m) => m.severity === "MEDIUM")
  ) {
    riskLevel = "MEDIUM";
  } else if (combinedPatterns.length > 0) {
    riskLevel = "LOW";
  }

  return {
    detected: combinedPatterns.length > 0,
    patterns: combinedPatterns,
    riskLevel,
    // Keep lengthWarning from primary (tool description) if present
    lengthWarning: primary.lengthWarning,
  };
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

  // Scan for description poisoning (tool.description)
  const toolDescriptionPoisoning = scanDescriptionForPoisoning(tool);

  // Issue #119, Challenge #15: Also scan input schema property descriptions
  // Malicious actors may hide instructions in parameter descriptions
  const schemaPoisoning = scanInputSchemaDescriptions(tool);

  // Merge results from both scans
  const descriptionPoisoning = mergePoisoningScanResults(
    toolDescriptionPoisoning,
    schemaPoisoning,
  );

  if (descriptionPoisoning.detected) {
    // Differentiate between tool description and schema description poisoning in issues
    const toolDescPatterns = toolDescriptionPoisoning.patterns.map(
      (p) => p.name,
    );
    const schemaPatterns = schemaPoisoning.patterns.map((p) => p.name);

    if (toolDescPatterns.length > 0) {
      issues.push(
        `Tool description contains suspicious patterns: ${toolDescPatterns.join(", ")}`,
      );
    }
    if (schemaPatterns.length > 0) {
      issues.push(
        `Input schema property descriptions contain suspicious patterns: ${schemaPatterns.join(", ")}`,
      );
    }
    recommendations.push(
      `Review ${tool.name} description and parameter descriptions for potential prompt injection or hidden instructions`,
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
