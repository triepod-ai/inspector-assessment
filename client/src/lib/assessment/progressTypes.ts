/**
 * Progress Event Types
 *
 * Types for real-time test progress tracking during assessment.
 * Used by CLI to emit batched JSONL events.
 *
 * @public
 * @module assessment/progressTypes
 */

import type { AssessmentStatus, InferenceConfidence } from "./coreTypes";

/**
 * Progress callback for assessment modules to report test execution progress.
 * Used by CLI to emit batched JSONL events.
 * @public
 */
export interface ProgressCallback {
  (event: ProgressEvent): void;
}

/**
 * Union type for all progress events emitted during assessment.
 * @public
 */
export type ProgressEvent =
  | ModuleStartedProgress
  | TestBatchProgress
  | ModuleCompleteProgress
  | VulnerabilityFoundProgress
  | TestValidityWarningProgress
  | AnnotationMissingProgress
  | AnnotationMisalignedProgress
  | AnnotationReviewRecommendedProgress
  | AnnotationPoisonedProgress
  | AnnotationAlignedProgress
  | ToolTestCompleteProgress
  | ValidationSummaryProgress
  | PhaseStartedProgress
  | PhaseCompleteProgress;

/**
 * Emitted when an assessment module begins execution.
 * @public
 */
export interface ModuleStartedProgress {
  type: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
}

/**
 * Emitted periodically during module execution with batched test results.
 * Batching reduces event volume for large assessments.
 * @public
 */
export interface TestBatchProgress {
  type: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

/**
 * Emitted when an assessment module completes with final stats.
 * @public
 */
export interface ModuleCompleteProgress {
  type: "module_complete";
  module: string;
  status: AssessmentStatus;
  score: number;
  testsRun: number;
  duration: number;
}

/**
 * Emitted when a security vulnerability is detected during assessment.
 * Provides real-time alerts for security findings.
 * @public
 */
export interface VulnerabilityFoundProgress {
  type: "vulnerability_found";
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string;
}

/**
 * Emitted when test validity analysis detects uniform responses.
 * Warns that security tests may not have reached security-relevant code.
 * Issue #134: Detect identical security test responses
 * @public
 */
export interface TestValidityWarningProgress {
  type: "test_validity_warning";
  module: "security";
  identicalResponseCount: number;
  totalResponses: number;
  percentageIdentical: number;
  detectedPattern:
    | "configuration_error"
    | "connection_error"
    | "timeout"
    | "empty_response"
    | "generic_error"
    | "unknown";
  warningLevel: "warning" | "critical";
  recommendedConfidence: "high" | "medium" | "low";
}

/**
 * Tool parameter metadata for annotation events.
 * Reusable type matching jsonl-events.ts ToolParam.
 * @public
 */
export interface ToolParamProgress {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

/**
 * Emitted when a tool is missing required annotations.
 * Provides real-time alerts during annotation assessment.
 * @public
 */
export interface AnnotationMissingProgress {
  type: "annotation_missing";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  inferredBehavior: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
  };
}

/**
 * Emitted when tool annotations don't match inferred behavior.
 * Provides real-time alerts during annotation assessment.
 * @public
 */
export interface AnnotationMisalignedProgress {
  type: "annotation_misaligned";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  expected: boolean;
  confidence: number;
  reason: string;
}

/**
 * Emitted when annotation alignment cannot be confidently determined.
 * Used for ambiguous patterns like store_*, queue_*, cache_* where behavior
 * varies by implementation context. Does not indicate a failure - just flags
 * for human review.
 * @public
 */
export interface AnnotationReviewRecommendedProgress {
  type: "annotation_review_recommended";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  inferred: boolean;
  confidence: InferenceConfidence;
  isAmbiguous: boolean;
  reason: string;
}

/**
 * Emitted when tool description contains poisoning patterns (Issue #8).
 * Indicates potential prompt injection or malicious instructions in tool metadata.
 * @public
 */
export interface AnnotationPoisonedProgress {
  type: "annotation_poisoned";
  tool: string;
  description?: string;
  patterns: Array<{
    name: string;
    pattern: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    category: string;
    evidence: string;
  }>;
  riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
}

/**
 * Emitted when tool annotations correctly match inferred behavior.
 * Provides real-time confirmation during annotation assessment.
 * @public
 */
export interface AnnotationAlignedProgress {
  type: "annotation_aligned";
  tool: string;
  confidence: "high" | "medium" | "low";
  annotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    openWorldHint?: boolean;
    idempotentHint?: boolean;
  };
}

// ============================================================================
// Phase 7 Events - Per-Tool Testing & Phase Lifecycle
// ============================================================================

/**
 * Emitted after all tests for a single tool complete.
 * Provides per-tool summary for real-time progress in auditor UI.
 * @public
 */
export interface ToolTestCompleteProgress {
  type: "tool_test_complete";
  tool: string;
  module: string;
  scenariosPassed: number;
  scenariosExecuted: number;
  confidence: "high" | "medium" | "low";
  status: "PASS" | "FAIL" | "ERROR";
  executionTime: number;
}

/**
 * Emitted with per-tool input validation metrics.
 * Tracks how tools handle invalid inputs (wrong types, missing required, etc.)
 * @public
 */
export interface ValidationSummaryProgress {
  type: "validation_summary";
  tool: string;
  wrongType: number;
  missingRequired: number;
  extraParams: number;
  nullValues: number;
  invalidValues: number;
}

/**
 * Emitted when an assessment phase begins.
 * Used for high-level progress tracking (discovery, assessment, analysis).
 * @public
 */
export interface PhaseStartedProgress {
  type: "phase_started";
  phase: string;
}

/**
 * Emitted when an assessment phase completes.
 * Includes duration for performance tracking.
 * @public
 */
export interface PhaseCompleteProgress {
  type: "phase_complete";
  phase: string;
  duration: number;
}
