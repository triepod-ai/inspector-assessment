/**
 * Progress Event Types
 *
 * Types for real-time test progress tracking during assessment.
 * Used by CLI to emit batched JSONL events.
 *
 * @module assessment/progressTypes
 */

import type { AssessmentStatus, InferenceConfidence } from "./coreTypes";

/**
 * Progress callback for assessment modules to report test execution progress.
 * Used by CLI to emit batched JSONL events.
 */
export interface ProgressCallback {
  (event: ProgressEvent): void;
}

/**
 * Union type for all progress events emitted during assessment.
 */
export type ProgressEvent =
  | ModuleStartedProgress
  | TestBatchProgress
  | ModuleCompleteProgress
  | VulnerabilityFoundProgress
  | AnnotationMissingProgress
  | AnnotationMisalignedProgress
  | AnnotationReviewRecommendedProgress
  | AnnotationPoisonedProgress
  | AnnotationAlignedProgress;

/**
 * Emitted when an assessment module begins execution.
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
 * Tool parameter metadata for annotation events.
 * Reusable type matching jsonl-events.ts ToolParam.
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
