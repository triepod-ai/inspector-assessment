/**
 * Shared Types for ProtocolComplianceAssessor
 *
 * Contains type definitions, interfaces, and re-exports used by
 * the protocol compliance and error handling sub-modules.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/types
 * @see GitHub Issue #188
 */

import type {
  ErrorHandlingAssessment,
  ErrorHandlingMetrics,
  ErrorTestDetail,
  AssessmentStatus,
  JSONSchema7,
} from "@/lib/assessmentTypes";
import type { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type { ProtocolCheck } from "@/lib/assessment/extendedTypes";
import type {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { Logger } from "../../lib/logger";

// Re-export types used by sub-modules
export type {
  ErrorHandlingAssessment,
  ErrorHandlingMetrics,
  ErrorTestDetail,
  AssessmentStatus,
  JSONSchema7,
  ProtocolCheck,
  AssessmentConfiguration,
  Tool,
  CompatibilityCallToolResult,
  Logger,
};

/**
 * Result of individual protocol check operations.
 * Used by protocol check sub-modules.
 */
export interface ProtocolCheckResult {
  passed: boolean;
  confidence: "high" | "medium" | "low";
  evidence?: string;
  rawResponse?: unknown;
  warnings?: string[];
  details?: Record<string, unknown>;
}

/**
 * Context for error handling tests.
 * Passed to InputValidationTester for individual tool tests.
 */
export interface ErrorTestContext {
  tool: Tool;
  callTool: CallToolFunction;
  isExternalAPI: boolean;
  config: AssessmentConfiguration;
}

/**
 * Result of invalid values analysis for contextual scoring.
 * Used by InvalidValuesAnalyzer.
 */
export interface InvalidValuesAnalysis {
  shouldPenalize: boolean;
  penaltyAmount: number;
  classification:
    | "safe_rejection"
    | "safe_reflection"
    | "defensive_programming"
    | "graceful_degradation"
    | "execution_detected"
    | "unknown";
  reason: string;
  bonusPoints: number;
}

/**
 * Call tool function type.
 * Standard signature for tool invocation.
 */
export type CallToolFunction = (
  name: string,
  params: Record<string, unknown>,
) => Promise<CompatibilityCallToolResult>;

/**
 * Result of suggestion pattern detection.
 * Issue #173: Bonus points for helpful error messages.
 */
export interface SuggestionDetectionResult {
  hasSuggestions: boolean;
  suggestions: string[];
}

/**
 * Metadata for generated invalid value parameters.
 * Issue #173: Tracks which parameter is being tested.
 */
export interface InvalidValueParamsResult {
  params: Record<string, unknown>;
  testedParameter: string;
  parameterIsRequired: boolean;
}

/**
 * Error info extracted from responses/exceptions.
 */
export interface ErrorInfo {
  code?: string | number;
  message?: string;
}

/**
 * Combined result from all error handling tests for a single tool.
 * Used internally by InputValidationTester.
 */
export interface ToolErrorTestResults {
  tests: ErrorTestDetail[];
  toolName: string;
}

/**
 * Configuration for error handling testing.
 * Subset of AssessmentConfiguration relevant to error handling.
 */
export interface ErrorHandlingConfig {
  testTimeout?: number;
  maxParallelTests?: number;
  delayBetweenTests?: number;
  selectedToolsForTesting?: string[];
  maxToolsToTestForErrors?: number;
}

/**
 * Score calculation result from ErrorHandlingScorer.
 */
export interface ScoreCalculationResult {
  score: number;
  maxPossibleScore: number;
  gracefulDegradationCount: number;
  suggestionCount: number;
  suggestionBonusPoints: number;
}

/**
 * Base interface for checker classes.
 * All checkers follow this pattern.
 */
export interface BaseChecker {
  /** Logger instance for structured logging */
  logger: Logger;
  /** Configuration for the assessment */
  config: AssessmentConfiguration;
}

/**
 * External service error indicators.
 * Issue #168: Patterns that indicate external API unavailability.
 */
export const EXTERNAL_SERVICE_ERROR_PATTERNS =
  /rate\s*limit|429|503|502|504|service\s*unavailable|temporarily|timeout|connection\s*refused|network\s*error|api\s*error|external\s*service|upstream|gateway|unreachable|econnrefused|enotfound|etimedout|socket\s*hang\s*up/i;

/**
 * Valid MCP content types per specification.
 */
export const VALID_CONTENT_TYPES = [
  "text",
  "image",
  "audio",
  "resource",
  "resource_link",
] as const;

export type ValidContentType = (typeof VALID_CONTENT_TYPES)[number];

/**
 * MCP content item structure.
 */
export interface ContentItem {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
}
