/**
 * Temporal Security Types
 *
 * Types for temporal/rug pull detection and variance classification.
 * Detects tools that change behavior after N invocations and distinguishes
 * legitimate response variance from suspicious behavioral changes.
 *
 * @module assessment/temporalSecurityTypes
 */

import type { AssessmentStatus } from "./coreTypes";

// ============================================================================
// Variance Classification Types (Issue #69)
// Distinguishes legitimate response variance from suspicious behavioral changes
// ============================================================================

/**
 * Classification of temporal variance between tool invocations.
 * Used to reduce false positives while maintaining detection capability.
 *
 * - LEGITIMATE: Expected variance (IDs, timestamps, search results, pagination)
 * - SUSPICIOUS: Concerning changes (capabilities, permissions, schema structure)
 * - BEHAVIORAL: Semantic changes (promotional keywords, error injection)
 */
export type VarianceType = "LEGITIMATE" | "SUSPICIOUS" | "BEHAVIORAL";

/**
 * Result of variance classification analysis.
 * Provides transparency into why a response difference was classified.
 */
export interface VarianceClassification {
  /** Type of variance detected */
  type: VarianceType;
  /** Confidence in the classification */
  confidence: "high" | "medium" | "low";
  /** Human-readable reasons for the classification */
  reasons: string[];
  /** Field paths that varied between invocations */
  variedFields?: string[];
  /** Suspicious patterns detected (if type is SUSPICIOUS or BEHAVIORAL) */
  suspiciousPatterns?: string[];
}

// ============================================================================
// Temporal/Rug Pull Assessment Types
// Detects tools that change behavior after N invocations
// ============================================================================

export interface TemporalToolResult {
  tool: string;
  vulnerable: boolean;
  totalInvocations: number;
  firstDeviationAt: number | null;
  deviationCount: number;
  errorCount: number; // Track errors during invocations (subset of deviationCount)
  pattern: "RUG_PULL_TEMPORAL" | "RUG_PULL_DEFINITION" | null;
  severity: "HIGH" | "MEDIUM" | "NONE";
  reducedInvocations?: boolean; // True if destructive tool detection applied
  note?: string; // Additional context (e.g., stateful tool with expected variation)
  evidence?: {
    safeResponseExample: unknown;
    maliciousResponseExample: unknown;
  };
  // Definition mutation tracking (Issue #7)
  definitionMutated?: boolean; // True if tool description/schema changed during invocations
  definitionMutationAt?: number | null; // Invocation number where mutation was detected
  definitionEvidence?: {
    baselineDescription?: string;
    mutatedDescription?: string;
    baselineSchema?: unknown;
    mutatedSchema?: unknown;
  };
  /** Issue #69: Variance classification for reduced false positives */
  varianceClassification?: VarianceClassification;
  /** Issue #69: Per-invocation variance details for transparency */
  varianceDetails?: Array<{
    invocation: number;
    classification: VarianceClassification;
  }>;
  /**
   * Issue #119, Challenge #2: Detection phase tracking
   * Indicates when the deviation was first detected
   * - "baseline" (invocations 1-5): Deviation during safe behavior establishment
   * - "monitoring" (invocations 6-15): Deviation during threshold monitoring
   * - null: No deviation detected
   */
  detectionPhase?: "baseline" | "monitoring" | null;
}

export interface TemporalAssessment {
  toolsTested: number;
  invocationsPerTool: number;
  rugPullsDetected: number;
  definitionMutationsDetected: number; // Tools that changed description/schema during invocations
  details: TemporalToolResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
