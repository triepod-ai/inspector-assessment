/**
 * Claude Integration Module
 * Handles Claude-enhanced tool behavior inference
 *
 * Extracted from ToolAnnotationAssessor.ts as part of Issue #105 refactoring.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolAnnotationResult } from "@/lib/assessmentTypes";
import type { ClaudeCodeBridge } from "../../lib/claudeCodeBridge";
import type { Logger } from "../../lib/logger";
import type { EnhancedToolAnnotationResult } from "./types";

// Re-export for backwards compatibility
export type { EnhancedToolAnnotationResult } from "./types";

/**
 * Enhance tool assessment with Claude inference
 */
export async function enhanceWithClaudeInference(
  tool: Tool,
  baseResult: ToolAnnotationResult,
  claudeBridge: ClaudeCodeBridge | undefined,
  logger: Logger,
): Promise<EnhancedToolAnnotationResult> {
  const inferredBehavior = baseResult.inferredBehavior ?? {
    expectedReadOnly: false,
    expectedDestructive: false,
    reason: "No behavior inference available",
  };

  if (!claudeBridge) {
    return {
      ...baseResult,
      claudeInference: {
        expectedReadOnly: inferredBehavior.expectedReadOnly,
        expectedDestructive: inferredBehavior.expectedDestructive,
        confidence: 50,
        reasoning: inferredBehavior.reason,
        suggestedAnnotations: {
          readOnlyHint: inferredBehavior.expectedReadOnly,
          destructiveHint: inferredBehavior.expectedDestructive,
        },
        misalignmentDetected: baseResult.issues.some((i) =>
          i.includes("misaligned"),
        ),
        source: "pattern-based",
      },
    };
  }

  try {
    const currentAnnotations = baseResult.annotations
      ? {
          readOnlyHint: baseResult.annotations.readOnlyHint,
          destructiveHint: baseResult.annotations.destructiveHint,
        }
      : undefined;

    const inference = await claudeBridge.inferToolBehavior(
      tool,
      currentAnnotations,
    );

    if (!inference) {
      return {
        ...baseResult,
        claudeInference: {
          expectedReadOnly: inferredBehavior.expectedReadOnly,
          expectedDestructive: inferredBehavior.expectedDestructive,
          confidence: 0,
          reasoning:
            "Claude inference unavailable. Using pattern-based analysis.",
          suggestedAnnotations: {},
          misalignmentDetected: false,
          source: "pattern-based",
        },
      };
    }

    const updatedIssues = [...baseResult.issues];
    const updatedRecommendations = [...baseResult.recommendations];

    if (inference.misalignmentDetected && inference.confidence >= 70) {
      const misalignmentMsg = inference.misalignmentDetails
        ? `Claude analysis (${inference.confidence}% confidence): ${inference.misalignmentDetails}`
        : `Claude analysis detected annotation misalignment with ${inference.confidence}% confidence`;

      if (!updatedIssues.some((i) => i.includes("Claude analysis"))) {
        updatedIssues.push(misalignmentMsg);
      }

      if (inference.suggestedAnnotations) {
        const { readOnlyHint, destructiveHint, idempotentHint } =
          inference.suggestedAnnotations;

        if (
          readOnlyHint !== undefined &&
          readOnlyHint !== baseResult.annotations?.readOnlyHint
        ) {
          updatedRecommendations.push(
            `Claude suggests: Set readOnlyHint=${readOnlyHint} for ${tool.name}`,
          );
        }
        if (
          destructiveHint !== undefined &&
          destructiveHint !== baseResult.annotations?.destructiveHint
        ) {
          updatedRecommendations.push(
            `Claude suggests: Set destructiveHint=${destructiveHint} for ${tool.name}`,
          );
        }
        if (idempotentHint !== undefined) {
          updatedRecommendations.push(
            `Claude suggests: Consider adding idempotentHint=${idempotentHint} for ${tool.name}`,
          );
        }
      }
    }

    return {
      ...baseResult,
      issues: updatedIssues,
      recommendations: updatedRecommendations,
      claudeInference: {
        expectedReadOnly: inference.expectedReadOnly,
        expectedDestructive: inference.expectedDestructive,
        confidence: inference.confidence,
        reasoning: inference.reasoning,
        suggestedAnnotations: inference.suggestedAnnotations,
        misalignmentDetected: inference.misalignmentDetected,
        misalignmentDetails: inference.misalignmentDetails,
        source: "claude-inferred",
      },
    };
  } catch (error) {
    logger.error(`Claude inference failed for ${tool.name}`, { error });

    return {
      ...baseResult,
      claudeInference: {
        expectedReadOnly: inferredBehavior.expectedReadOnly,
        expectedDestructive: inferredBehavior.expectedDestructive,
        confidence: 50,
        reasoning: `Claude inference failed, using pattern-based: ${inferredBehavior.reason}`,
        suggestedAnnotations: {
          readOnlyHint: inferredBehavior.expectedReadOnly,
          destructiveHint: inferredBehavior.expectedDestructive,
        },
        misalignmentDetected: baseResult.issues.some((i) =>
          i.includes("misaligned"),
        ),
        source: "pattern-based",
      },
    };
  }
}

/**
 * Create pattern-based Claude inference fallback
 * Used when Claude enhancement is not enabled
 */
export function createPatternBasedInference(
  baseResult: ToolAnnotationResult,
): EnhancedToolAnnotationResult {
  const inferredBehavior = baseResult.inferredBehavior ?? {
    expectedReadOnly: false,
    expectedDestructive: false,
    reason: "No behavior inference available",
  };

  return {
    ...baseResult,
    claudeInference: {
      expectedReadOnly: inferredBehavior.expectedReadOnly,
      expectedDestructive: inferredBehavior.expectedDestructive,
      confidence: 50,
      reasoning: inferredBehavior.reason,
      suggestedAnnotations: {
        readOnlyHint: inferredBehavior.expectedReadOnly,
        destructiveHint: inferredBehavior.expectedDestructive,
      },
      misalignmentDetected: baseResult.issues.some((i) =>
        i.includes("misaligned"),
      ),
      source: "pattern-based",
    },
  };
}
