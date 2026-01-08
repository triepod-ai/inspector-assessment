/**
 * Annotations Assessment Module
 * Exports all annotation-related components
 */

export {
  DESCRIPTION_POISONING_PATTERNS,
  scanDescriptionForPoisoning,
  type PoisoningPattern,
  type PoisoningScanResult,
} from "./DescriptionPoisoningDetector";

export {
  READONLY_CONTRADICTION_KEYWORDS,
  RUN_READONLY_EXEMPT_SUFFIXES,
  DESTRUCTIVE_CONTRADICTION_KEYWORDS,
  containsKeyword,
  isRunKeywordExempt,
  isActionableConfidence,
  detectAnnotationDeception,
  type DeceptionResult,
} from "./AnnotationDeceptionDetector";

export {
  inferBehavior,
  type BehaviorInferenceResult,
} from "./BehaviorInference";
