/**
 * Error Handling Reporter
 *
 * Generates explanations and recommendations for error handling results.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/errorHandling/ErrorHandlingReporter
 * @see GitHub Issue #188
 */

import type {
  ErrorHandlingMetrics,
  ErrorTestDetail,
  ErrorInfo,
  Logger,
  AssessmentConfiguration,
} from "../types";
import { EXTERNAL_SERVICE_ERROR_PATTERNS } from "../types";

/**
 * Generates human-readable reports for error handling assessment.
 */
export class ErrorHandlingReporter {
  constructor(_config: AssessmentConfiguration, _logger: Logger) {}

  /**
   * Generate explanation of error handling results.
   */
  generateExplanation(
    metrics: ErrorHandlingMetrics,
    tests: ErrorTestDetail[],
  ): string {
    // Handle case when no tools were tested
    if (tests.length === 0) {
      return "No tools selected for error handling testing. Select tools to run error handling assessments.";
    }

    const parts: string[] = [];

    // Filter out invalid_values for scoring context
    const scoredTests = tests.filter((t) => t.testType !== "invalid_values");
    const passedScoredTests = scoredTests.filter((t) => t.passed).length;
    const totalScoredTests = scoredTests.length;

    parts.push(
      `Error handling compliance score: ${metrics.mcpComplianceScore.toFixed(1)}% (${passedScoredTests}/${totalScoredTests} scored tests passed).`,
    );

    // Count how many types of validation are working (only scored tests)
    const validationTypes: string[] = [];
    if (tests.some((t) => t.testType === "missing_required" && t.passed)) {
      validationTypes.push("missing parameter validation");
    }
    if (tests.some((t) => t.testType === "wrong_type" && t.passed)) {
      validationTypes.push("type validation");
    }
    if (tests.some((t) => t.testType === "excessive_input" && t.passed)) {
      validationTypes.push("input size validation");
    }

    // Add informational note about invalid_values tests
    const invalidValuesTests = tests.filter(
      (t) => t.testType === "invalid_values",
    );
    if (invalidValuesTests.length > 0) {
      const passedInvalidValues = invalidValuesTests.filter(
        (t) => t.passed,
      ).length;
      validationTypes.push(
        `edge case handling (${passedInvalidValues}/${invalidValuesTests.length} - informational only)`,
      );
    }

    if (validationTypes.length > 0) {
      const scoredValidationCount = validationTypes.filter(
        (v) => !v.includes("informational only"),
      ).length;
      parts.push(
        `Implements ${scoredValidationCount}/3 validation types (scored): ${validationTypes.join(", ")}.`,
      );
    } else {
      parts.push("No input validation detected.");
    }

    parts.push(
      `${metrics.hasDescriptiveMessages ? "Has" : "Missing"} descriptive error messages,`,
      `${metrics.hasProperErrorCodes ? "uses" : "missing"} proper error codes.`,
    );

    // Count tools tested
    const toolsTested = [...new Set(tests.map((t) => t.toolName))].length;
    const totalTests = tests.length;
    parts.push(
      `Tested ${toolsTested} tools with ${totalScoredTests} scored scenarios (${totalTests} total including informational).`,
    );

    return parts.join(" ");
  }

  /**
   * Generate recommendations based on test results.
   */
  generateRecommendations(
    metrics: ErrorHandlingMetrics,
    tests: ErrorTestDetail[],
  ): string[] {
    const recommendations: string[] = [];

    if (!metrics.hasProperErrorCodes) {
      recommendations.push(
        "Implement consistent error codes for different error types",
      );
    }

    if (!metrics.hasDescriptiveMessages) {
      recommendations.push(
        "Provide descriptive error messages that help users understand the issue",
      );
    }

    if (!metrics.validatesInputs) {
      recommendations.push(
        "Implement proper input validation for all parameters",
      );
    }

    const failedTypes = [
      ...new Set(tests.filter((t) => !t.passed).map((t) => t.testType)),
    ];

    if (failedTypes.includes("missing_required")) {
      recommendations.push("Validate and report missing required parameters");
    }

    if (failedTypes.includes("wrong_type")) {
      recommendations.push("Implement type checking for all parameters");
    }

    if (failedTypes.includes("excessive_input")) {
      recommendations.push(
        "Implement input size limits and handle large inputs gracefully",
      );
    }

    return recommendations;
  }

  /**
   * Check if an error indicates an external service failure.
   * Issue #168: External API tools may fail due to service unavailability.
   */
  isExternalServiceError(errorInfo: ErrorInfo): boolean {
    const message = errorInfo.message?.toLowerCase() ?? "";
    const code = String(errorInfo.code ?? "").toLowerCase();

    return (
      EXTERNAL_SERVICE_ERROR_PATTERNS.test(message) ||
      EXTERNAL_SERVICE_ERROR_PATTERNS.test(code)
    );
  }
}
