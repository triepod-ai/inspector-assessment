/**
 * Resource Assessment Module
 *
 * Exports all resource-related components for testing MCP server resources.
 * Includes pattern definitions, validators, testers, and result builders.
 *
 * @public
 * @module assessment/resources
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

// Pattern definitions and constants
export {
  SENSITIVE_PATTERNS,
  PATH_TRAVERSAL_PAYLOADS,
  URI_INJECTION_PAYLOADS,
  HIDDEN_RESOURCE_PATTERNS,
  DOS_SIZE_PAYLOADS,
  POLYGLOT_COMBINATIONS,
  MIME_MAGIC_BYTES,
  SENSITIVE_CONTENT_PATTERNS,
  SENSITIVE_PATTERN_DEFINITIONS,
  PROMPT_INJECTION_PATTERNS,
  type PolyglotCombination,
  type MagicBytesInfo,
  type SensitivePatternDefinition,
  type PromptInjectionPattern,
} from "./ResourcePatterns";

// Content analysis utilities
export {
  detectSensitivePatterns,
  containsSensitiveContent,
  detectPromptInjection,
  validateMimeType,
  formatBytes,
  stringToBytes,
  startsWithBytes,
  type SensitivePatternResult,
  type MimeValidationResult,
} from "./ResourceContentAnalyzer";

// URI validation utilities
export {
  isValidUri,
  isValidUriTemplate,
  isSensitiveUri,
  inferAccessControls,
  inferDataClassification,
  injectPayloadIntoTemplate,
  type AccessControlInference,
  type DataClassification,
} from "./ResourceUriValidator";

// Result building utilities
export {
  determineResourceStatus,
  generateExplanation,
  generateRecommendations,
  createNoResourcesResponse,
  calculateMetrics,
  type ResourceMetrics,
} from "./ResourceResultBuilder";

// Resource tester classes
export {
  ResourceTester,
  type ResourceTesterConfig,
  type TestLogger as ResourceTesterLogger,
} from "./ResourceTester";

export {
  ResourceProbeTester,
  type ProbeTesterConfig,
  type TestLogger as ProbeTesterLogger,
} from "./ResourceProbeTester";

// Enrichment builder
export { ResourceEnrichmentBuilder } from "./ResourceEnrichmentBuilder";

// Factory pattern for dependency injection (Issue #180 - Modularization)
export {
  createResourceTesters,
  createResourceTestersWithOverrides,
  type ResourceTesters,
  type ResourceTestersConfig,
  type TestLogger,
} from "./factory";
