/**
 * Annotations Assessment Module
 * Exports all annotation-related components
 *
 * Enhanced in Issue #57 with architecture detection and multi-signal behavior inference.
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
  inferBehaviorEnhanced,
  type BehaviorInferenceResult,
} from "./BehaviorInference";

// Issue #57: Description Analyzer
export {
  analyzeDescription,
  hasReadOnlyIndicators,
  hasDestructiveIndicators,
  hasWriteIndicators,
  DESCRIPTION_BEHAVIOR_KEYWORDS,
} from "./DescriptionAnalyzer";

// Issue #57: Schema Analyzer
export {
  analyzeInputSchema,
  analyzeOutputSchema,
  hasBulkOperationIndicators,
  hasPaginationParameters,
  hasForceFlags,
  INPUT_READONLY_PATTERNS,
  INPUT_DESTRUCTIVE_PATTERNS,
  INPUT_WRITE_PATTERNS,
  OUTPUT_READONLY_PATTERNS,
  OUTPUT_DESTRUCTIVE_PATTERNS,
  OUTPUT_WRITE_PATTERNS,
  type JSONSchema,
} from "./SchemaAnalyzer";

// Issue #57: Architecture Detector
export {
  detectArchitecture,
  hasDatabaseToolPatterns,
  extractDatabasesFromDependencies,
  type Tool as ArchitectureTool,
  type ArchitectureContext,
} from "./ArchitectureDetector";

// Issue #105: Alignment Checker
export {
  extractAnnotations,
  extractExtendedMetadata,
  extractToolParams,
  assessSingleTool,
  determineAnnotationStatus,
  calculateMetrics,
  type ExtractedAnnotations,
  type AlignmentMetricsResult,
} from "./AlignmentChecker";

// Issue #105: Explanation Generator
export {
  generateExplanation,
  generateEnhancedExplanation,
  generateRecommendations,
  generateEnhancedRecommendations,
  type EnhancedToolAnnotationResultForExplanation,
} from "./ExplanationGenerator";

// Issue #105: Event Emitter
export {
  emitAnnotationEvents,
  emitMismatchEvent,
  type EnhancedToolAnnotationResultForEvents,
} from "./EventEmitter";

// Issue #105: Claude Integration
export {
  enhanceWithClaudeInference,
  createPatternBasedInference,
  type EnhancedToolAnnotationResult,
} from "./ClaudeIntegration";
