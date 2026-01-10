/**
 * Annotation Event Emitter Module
 * Handles emitting annotation-related progress events during assessment
 *
 * Extracted from ToolAnnotationAssessor.ts as part of Issue #105 refactoring.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type {
  ToolAnnotationResult,
  AlignmentStatus,
  ToolParamProgress,
  ProgressCallback,
} from "@/lib/assessmentTypes";

import { isActionableConfidence } from "./AnnotationDeceptionDetector";
import { extractAnnotations, extractToolParams } from "./AlignmentChecker";
import type { EnhancedToolAnnotationResult } from "./types";

/**
 * Emit annotation-related progress events
 */
export function emitAnnotationEvents(
  onProgress: ProgressCallback | undefined,
  tool: Tool,
  result: EnhancedToolAnnotationResult,
): void {
  if (!onProgress || !result.inferredBehavior) return;

  const annotations = result.annotations;
  const inferred = result.inferredBehavior;
  const confidence = result.claudeInference?.confidence ?? 50;
  const toolParams = extractToolParams(tool.inputSchema);
  const toolAnnotations = extractAnnotations(tool);

  // Emit missing annotation event
  if (!result.hasAnnotations) {
    onProgress({
      type: "annotation_missing",
      tool: tool.name,
      title: toolAnnotations.title,
      description: tool.description,
      parameters: toolParams,
      inferredBehavior: {
        expectedReadOnly: inferred.expectedReadOnly,
        expectedDestructive: inferred.expectedDestructive,
        reason: inferred.reason,
      },
    });
    return;
  }

  // Emit aligned event
  if (result.alignmentStatus === "ALIGNED") {
    onProgress({
      type: "annotation_aligned",
      tool: tool.name,
      confidence: inferred.confidence ?? "medium",
      annotations: {
        readOnlyHint: annotations?.readOnlyHint,
        destructiveHint: annotations?.destructiveHint,
        openWorldHint: annotations?.openWorldHint,
        idempotentHint: annotations?.idempotentHint,
      },
    });
    return;
  }

  // Get alignment status with fallback to UNKNOWN if undefined
  const alignmentStatus = result.alignmentStatus ?? "UNKNOWN";

  // Check readOnlyHint mismatch
  if (
    annotations?.readOnlyHint !== undefined &&
    annotations.readOnlyHint !== inferred.expectedReadOnly
  ) {
    emitMismatchEvent(
      onProgress,
      tool,
      toolParams,
      toolAnnotations,
      "readOnlyHint",
      annotations.readOnlyHint,
      inferred.expectedReadOnly,
      confidence,
      inferred,
      alignmentStatus,
    );
  }

  // Check destructiveHint mismatch
  if (
    annotations?.destructiveHint !== undefined &&
    annotations.destructiveHint !== inferred.expectedDestructive
  ) {
    emitMismatchEvent(
      onProgress,
      tool,
      toolParams,
      toolAnnotations,
      "destructiveHint",
      annotations.destructiveHint,
      inferred.expectedDestructive,
      confidence,
      inferred,
      alignmentStatus,
    );
  }
}

/**
 * Emit mismatch event (misaligned or review_recommended)
 */
export function emitMismatchEvent(
  onProgress: ProgressCallback | undefined,
  tool: Tool,
  toolParams: ToolParamProgress[],
  toolAnnotations: { title?: string },
  field: "readOnlyHint" | "destructiveHint",
  actual: boolean | undefined,
  expected: boolean,
  confidence: number,
  inferred: NonNullable<ToolAnnotationResult["inferredBehavior"]>,
  alignmentStatus: AlignmentStatus,
): void {
  if (!onProgress) return;

  if (alignmentStatus === "REVIEW_RECOMMENDED") {
    onProgress({
      type: "annotation_review_recommended",
      tool: tool.name,
      title: toolAnnotations.title,
      description: tool.description,
      parameters: toolParams,
      field,
      actual,
      inferred: expected,
      confidence: inferred.confidence,
      isAmbiguous: inferred.isAmbiguous,
      reason: inferred.reason,
    });
  } else if (
    !inferred.isAmbiguous &&
    isActionableConfidence(inferred.confidence)
  ) {
    onProgress({
      type: "annotation_misaligned",
      tool: tool.name,
      title: toolAnnotations.title,
      description: tool.description,
      parameters: toolParams,
      field,
      actual,
      expected,
      confidence,
      reason: `Tool has ${field}=${actual}, but ${inferred.reason}`,
    });
  }
}
