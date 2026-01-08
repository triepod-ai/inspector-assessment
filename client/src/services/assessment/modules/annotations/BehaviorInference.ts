/**
 * Behavior Inference
 * Infers expected tool behavior from name patterns and descriptions
 *
 * Extracted from ToolAnnotationAssessor.ts for maintainability.
 * Handles persistence model detection and behavior classification.
 *
 * Enhanced in Issue #57 with multi-signal inference from descriptions and schemas.
 */

import type { InferenceConfidence } from "@/lib/assessmentTypes";
import type {
  InferenceSignal,
  EnhancedBehaviorInferenceResult,
} from "@/lib/assessment/extendedTypes";
import { analyzeDescription } from "./DescriptionAnalyzer";
import {
  analyzeInputSchema,
  analyzeOutputSchema,
  type JSONSchema,
} from "./SchemaAnalyzer";
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

/**
 * Enhanced behavior inference using multiple signals.
 *
 * Analyzes tool name patterns, descriptions, and schemas to provide
 * a more accurate behavior inference with aggregated confidence.
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 *
 * @param toolName - Name of the tool
 * @param description - Tool description (optional)
 * @param inputSchema - Input parameter schema (optional)
 * @param outputSchema - Output/return schema (optional)
 * @param compiledPatterns - Compiled regex patterns for name matching
 * @param persistenceContext - Server-level persistence context
 * @returns EnhancedBehaviorInferenceResult with multi-signal analysis
 */
export function inferBehaviorEnhanced(
  toolName: string,
  description?: string,
  inputSchema?: JSONSchema,
  outputSchema?: JSONSchema,
  compiledPatterns?: CompiledPatterns,
  persistenceContext?: ServerPersistenceContext,
): EnhancedBehaviorInferenceResult {
  // Get the basic name-pattern inference
  const baseResult = inferBehavior(
    toolName,
    description,
    compiledPatterns,
    persistenceContext,
  );

  // Initialize signals collection
  const signals: EnhancedBehaviorInferenceResult["signals"] = {};

  // Convert base result to name pattern signal
  signals.namePatternSignal = {
    expectedReadOnly: baseResult.expectedReadOnly,
    expectedDestructive: baseResult.expectedDestructive,
    confidence: confidenceToNumber(baseResult.confidence),
    evidence: [baseResult.reason],
  };

  // Analyze description if provided
  if (description && description.trim().length > 0) {
    signals.descriptionSignal = analyzeDescription(description);
  }

  // Analyze input schema if provided
  if (inputSchema) {
    signals.inputSchemaSignal = analyzeInputSchema(inputSchema);
  }

  // Analyze output schema if provided
  if (outputSchema) {
    signals.outputSchemaSignal = analyzeOutputSchema(outputSchema);
  }

  // Aggregate signals to determine final result
  const aggregated = aggregateSignals(signals);

  return {
    expectedReadOnly: aggregated.expectedReadOnly,
    expectedDestructive: aggregated.expectedDestructive,
    reason: aggregated.reason,
    confidence: numberToConfidence(aggregated.confidence),
    isAmbiguous: aggregated.isAmbiguous,
    signals,
    aggregatedConfidence: aggregated.confidence,
  };
}

/**
 * Convert string confidence to numeric value (0-100).
 */
function confidenceToNumber(confidence: InferenceConfidence): number {
  switch (confidence) {
    case "high":
      return 90;
    case "medium":
      return 70;
    case "low":
      return 40;
    default:
      return 0;
  }
}

/**
 * Convert numeric confidence (0-100) to string confidence level.
 */
function numberToConfidence(confidence: number): InferenceConfidence {
  if (confidence >= 80) return "high";
  if (confidence >= 50) return "medium";
  return "low";
}

/**
 * Aggregate multiple signals into a final inference result.
 *
 * Signal aggregation rules:
 * 1. Destructive signals take priority if confidence >= 70
 * 2. Read-only signals are aggregated when no destructive signals
 * 3. Conflicting signals decrease overall confidence
 * 4. Multiple agreeing signals increase confidence
 */
function aggregateSignals(
  signals: EnhancedBehaviorInferenceResult["signals"],
): {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: number;
  isAmbiguous: boolean;
} {
  const activeSignals = Object.entries(signals).filter(
    ([_, signal]) => signal && signal.confidence > 0,
  ) as Array<[string, InferenceSignal]>;

  if (activeSignals.length === 0) {
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      reason: "No signals detected",
      confidence: 0,
      isAmbiguous: true,
    };
  }

  // Count signals by behavior type
  let readOnlySignals: Array<{ name: string; signal: InferenceSignal }> = [];
  let destructiveSignals: Array<{ name: string; signal: InferenceSignal }> = [];
  let writeSignals: Array<{ name: string; signal: InferenceSignal }> = [];

  for (const [name, signal] of activeSignals) {
    if (signal.expectedDestructive) {
      destructiveSignals.push({ name, signal });
    } else if (signal.expectedReadOnly) {
      readOnlySignals.push({ name, signal });
    } else {
      writeSignals.push({ name, signal });
    }
  }

  // Determine final behavior
  let expectedReadOnly = false;
  let expectedDestructive = false;
  let reason: string;
  let confidence: number;
  let isAmbiguous = false;

  // Priority 1: Strong destructive signals
  const strongDestructive = destructiveSignals.filter(
    (s) => s.signal.confidence >= 70,
  );
  if (strongDestructive.length > 0) {
    expectedDestructive = true;
    const avgConfidence =
      strongDestructive.reduce((sum, s) => sum + s.signal.confidence, 0) /
      strongDestructive.length;
    confidence = Math.min(100, avgConfidence + strongDestructive.length * 5); // Boost for multiple signals
    reason = `Destructive behavior detected from: ${strongDestructive.map((s) => formatSignalName(s.name)).join(", ")}`;

    // Check for conflicts
    if (readOnlySignals.length > 0) {
      confidence -= 10;
      reason += ` (conflicts with read-only signals)`;
      isAmbiguous = true;
    }
  }
  // Priority 2: Read-only signals
  else if (readOnlySignals.length > 0) {
    expectedReadOnly = true;
    const avgConfidence =
      readOnlySignals.reduce((sum, s) => sum + s.signal.confidence, 0) /
      readOnlySignals.length;
    confidence = Math.min(100, avgConfidence + readOnlySignals.length * 5); // Boost for multiple signals
    reason = `Read-only behavior detected from: ${readOnlySignals.map((s) => formatSignalName(s.name)).join(", ")}`;

    // Check for conflicts with write signals
    if (writeSignals.some((s) => s.signal.confidence >= 70)) {
      confidence -= 15;
      reason += ` (conflicts with write signals)`;
      isAmbiguous = true;
    }
  }
  // Priority 3: Write signals (not destructive)
  else if (writeSignals.length > 0) {
    const avgConfidence =
      writeSignals.reduce((sum, s) => sum + s.signal.confidence, 0) /
      writeSignals.length;
    confidence = avgConfidence;
    reason = `Write behavior detected from: ${writeSignals.map((s) => formatSignalName(s.name)).join(", ")}`;
  }
  // Fallback: No clear signals
  else {
    confidence = 30;
    reason = "No clear behavior signals detected";
    isAmbiguous = true;
  }

  // Ensure confidence is in valid range
  confidence = Math.max(0, Math.min(100, confidence));

  return {
    expectedReadOnly,
    expectedDestructive,
    reason,
    confidence: Math.round(confidence),
    isAmbiguous,
  };
}

/**
 * Format signal name for display.
 */
function formatSignalName(name: string): string {
  return name
    .replace(/Signal$/, "")
    .replace(/([A-Z])/g, " $1")
    .trim()
    .toLowerCase();
}
