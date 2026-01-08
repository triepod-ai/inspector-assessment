/**
 * Behavior Inference
 * Infers expected tool behavior from name patterns and descriptions
 *
 * Extracted from ToolAnnotationAssessor.ts for maintainability.
 * Handles persistence model detection and behavior classification.
 */

import type { InferenceConfidence } from "@/lib/assessmentTypes";
import {
  type CompiledPatterns,
  type ServerPersistenceContext,
  getDefaultCompiledPatterns,
  matchToolPattern,
  checkDescriptionForImmediatePersistence,
} from "../../config/annotationPatterns";
import { isRunKeywordExempt } from "./AnnotationDeceptionDetector";

/**
 * Result of behavior inference
 */
export interface BehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: InferenceConfidence;
  isAmbiguous: boolean;
}

/**
 * Infer expected behavior from tool name and description
 * Returns confidence level and ambiguity flag for better handling
 */
export function inferBehavior(
  toolName: string,
  description?: string,
  compiledPatterns?: CompiledPatterns,
  persistenceContext?: ServerPersistenceContext,
): BehaviorInferenceResult {
  const patterns = compiledPatterns ?? getDefaultCompiledPatterns();
  const lowerDesc = (description || "").toLowerCase();

  // Issue #18: Early check for run + analysis suffix pattern
  // Tools like "runAccessibilityAudit" are genuinely read-only (fetch analysis data)
  // Check this BEFORE pattern matching to override the generic "run_" write pattern
  if (isRunKeywordExempt(toolName)) {
    return {
      expectedReadOnly: true,
      expectedDestructive: false,
      reason: `Tool name contains 'run' with analysis suffix (audit, check, scan, etc.) - this is a read-only analysis operation`,
      confidence: "medium",
      isAmbiguous: false,
    };
  }

  // Use the configurable pattern matching system
  const patternMatch = matchToolPattern(toolName, patterns);

  // Handle pattern match results
  switch (patternMatch.category) {
    case "ambiguous":
      // Ambiguous patterns - don't make strong assertions
      return {
        expectedReadOnly: false,
        expectedDestructive: false,
        reason: `Tool name matches ambiguous pattern '${patternMatch.pattern}' - behavior varies by implementation context`,
        confidence: "low",
        isAmbiguous: true,
      };

    case "destructive":
      return {
        expectedReadOnly: false,
        expectedDestructive: true,
        reason: `Tool name matches destructive pattern: ${patternMatch.pattern}`,
        confidence: "high",
        isAmbiguous: false,
      };

    case "readOnly":
      return {
        expectedReadOnly: true,
        expectedDestructive: false,
        reason: `Tool name matches read-only pattern: ${patternMatch.pattern}`,
        confidence: "high",
        isAmbiguous: false,
      };

    case "write": {
      // CREATE operations are NEVER destructive - they only ADD new data
      // Only UPDATE/MODIFY operations can be considered destructive when they modify existing data
      const isCreateOperation = /^(create|add|insert|new|generate)[_-]/i.test(
        toolName,
      );
      if (isCreateOperation) {
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches create pattern: ${patternMatch.pattern} - create operations only add data and are not destructive`,
          confidence: "high",
          isAmbiguous: false,
        };
      }

      // Three-Tier Classification: Check persistence model for UPDATE/MODIFY operations
      // If immediate persistence detected, update operations should be marked destructive
      const descriptionCheck = checkDescriptionForImmediatePersistence(
        description || "",
      );

      // Priority 1: Description explicitly indicates deferred persistence
      if (descriptionCheck.indicatesDeferred) {
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches write pattern (${patternMatch.pattern}), description indicates deferred/in-memory operation`,
          confidence: "medium",
          isAmbiguous: false,
        };
      }

      // Priority 2: Description explicitly indicates immediate persistence
      if (descriptionCheck.indicatesImmediate) {
        return {
          expectedReadOnly: false,
          expectedDestructive: true,
          reason: `Tool name matches write pattern (${patternMatch.pattern}), description indicates immediate persistence to storage (${descriptionCheck.matchedPatterns.slice(0, 2).join(", ")})`,
          confidence: "medium",
          isAmbiguous: false,
        };
      }

      // Priority 3: Server-level persistence model (no save operations = immediate)
      if (persistenceContext?.model === "immediate") {
        return {
          expectedReadOnly: false,
          expectedDestructive: true,
          reason: `Tool name matches write pattern (${patternMatch.pattern}), server has no save operations → write operations likely persist immediately`,
          confidence: "medium",
          isAmbiguous: false,
        };
      }

      // Priority 4: Server has save operations = deferred (in-memory until save)
      if (persistenceContext?.model === "deferred") {
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches write pattern (${patternMatch.pattern}), server has save operations → write operations likely in-memory until explicit save`,
          confidence: "medium",
          isAmbiguous: false,
        };
      }

      // Default: Unknown persistence model - conservative approach (not destructive)
      return {
        expectedReadOnly: false,
        expectedDestructive: false,
        reason: `Tool name matches write pattern: ${patternMatch.pattern}`,
        confidence: "medium",
        isAmbiguous: false,
      };
    }

    case "unknown":
    default:
      // Fall through to description-based analysis
      break;
  }

  // Check description for hints (medium confidence)
  if (lowerDesc.includes("delete") || lowerDesc.includes("remove")) {
    return {
      expectedReadOnly: false,
      expectedDestructive: true,
      reason: "Description mentions delete/remove operations",
      confidence: "medium",
      isAmbiguous: false,
    };
  }

  if (
    lowerDesc.includes("read") ||
    lowerDesc.includes("get") ||
    lowerDesc.includes("fetch")
  ) {
    return {
      expectedReadOnly: true,
      expectedDestructive: false,
      reason: "Description suggests read-only operation",
      confidence: "medium",
      isAmbiguous: false,
    };
  }

  // Default: assume write with low confidence (ambiguous)
  return {
    expectedReadOnly: false,
    expectedDestructive: false,
    reason: "Could not infer behavior from name pattern",
    confidence: "low",
    isAmbiguous: true,
  };
}
