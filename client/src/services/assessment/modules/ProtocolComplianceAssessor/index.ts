/**
 * Protocol Compliance Assessor Module
 *
 * Unified module for MCP protocol compliance validation and error handling testing.
 * Merges the functionality of the original ProtocolComplianceAssessor and ErrorHandlingAssessor.
 *
 * @module assessment/modules/ProtocolComplianceAssessor
 * @see GitHub Issue #188
 */

// Main assessor export
export {
  ProtocolComplianceAssessor,
  type UnifiedProtocolComplianceAssessment,
} from "./ProtocolComplianceAssessor";

// Protocol check sub-modules
export {
  JsonRpcChecker,
  SchemaChecker,
  ErrorResponseChecker,
  CapabilitiesChecker,
  ServerInfoChecker,
  ContentTypeChecker,
  InitializationChecker,
  OutputSchemaAnalyzer,
  MetadataExtractor,
} from "./protocolChecks";

// Error handling sub-modules
export {
  InputValidationTester,
  InvalidValuesAnalyzer,
  ErrorHandlingScorer,
  ErrorHandlingReporter,
} from "./errorHandling";

// Shared types
export type {
  ProtocolCheckResult,
  ErrorTestContext,
  InvalidValuesAnalysis,
  SuggestionDetectionResult,
  InvalidValueParamsResult,
  ErrorInfo,
  ToolErrorTestResults,
  ErrorHandlingConfig,
  ScoreCalculationResult,
  CallToolFunction,
  ContentItem,
  ValidContentType,
} from "./types";

export { VALID_CONTENT_TYPES, EXTERNAL_SERVICE_ERROR_PATTERNS } from "./types";
