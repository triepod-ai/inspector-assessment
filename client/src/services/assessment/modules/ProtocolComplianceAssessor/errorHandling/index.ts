/**
 * Error Handling Sub-Module
 *
 * Exports all error handling testing components.
 * These components test application-level input validation.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/errorHandling
 * @see GitHub Issue #188
 */

// Error handling components will be exported here as they are extracted
// Each component handles a specific aspect of error testing

export { InputValidationTester } from "./InputValidationTester";
export { InvalidValuesAnalyzer } from "./InvalidValuesAnalyzer";
export { ErrorHandlingScorer } from "./ErrorHandlingScorer";
export { ErrorHandlingReporter } from "./ErrorHandlingReporter";

// Re-export types used by error handling components
export type {
  ErrorTestContext,
  InvalidValuesAnalysis,
  SuggestionDetectionResult,
  InvalidValueParamsResult,
  ErrorInfo,
  ToolErrorTestResults,
  ErrorHandlingConfig,
  ScoreCalculationResult,
} from "../types";
