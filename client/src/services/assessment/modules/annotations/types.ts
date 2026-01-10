/**
 * Shared Types for Annotation Assessment Modules
 *
 * Consolidates common type definitions used across annotation helper modules.
 * Created as part of Issue #105 refactoring to eliminate duplicate definitions.
 */

import type { ToolAnnotationResult } from "@/lib/assessmentTypes";

/**
 * Claude inference result structure
 * Contains semantic analysis of tool behavior from Claude
 */
export interface ClaudeInference {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  confidence: number;
  reasoning: string;
  suggestedAnnotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
  misalignmentDetected: boolean;
  misalignmentDetails?: string;
  source: "claude-inferred" | "pattern-based";
}

/**
 * Enhanced tool annotation result with Claude inference
 * Extends the base result with optional Claude semantic analysis
 */
export interface EnhancedToolAnnotationResult extends ToolAnnotationResult {
  claudeInference?: ClaudeInference;
}
