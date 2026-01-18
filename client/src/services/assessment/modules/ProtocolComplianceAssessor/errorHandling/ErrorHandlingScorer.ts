/**
 * Error Handling Scorer
 *
 * Calculates metrics and scores from error handling test results.
 * Issue #173: Tracks graceful degradation and suggestion metrics.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/errorHandling/ErrorHandlingScorer
 * @see GitHub Issue #173, #188
 */

import type {
  ErrorHandlingMetrics,
  ErrorTestDetail,
  AssessmentStatus,
  Logger,
  AssessmentConfiguration,
} from "../types";
import { InvalidValuesAnalyzer } from "./InvalidValuesAnalyzer";

/**
 * Calculates error handling metrics and scores.
 */
export class ErrorHandlingScorer {
  private invalidValuesAnalyzer: InvalidValuesAnalyzer;

  constructor(config: AssessmentConfiguration, logger: Logger) {
    this.invalidValuesAnalyzer = new InvalidValuesAnalyzer(config, logger);
  }

  /**
   * Calculate metrics from test results.
   */
  calculateMetrics(
    tests: ErrorTestDetail[],
    _passed: number, // parameter kept for API compatibility
  ): ErrorHandlingMetrics {
    // Calculate enhanced score with bonus points for quality
    let enhancedScore = 0;
    let maxPossibleScore = 0;

    // Issue #173: Track graceful degradation and suggestion metrics
    let gracefulDegradationCount = 0;
    let suggestionCount = 0;
    let suggestionBonusPoints = 0;

    tests.forEach((test) => {
      // Issue #99: Contextual scoring for invalid_values tests
      if (test.testType === "invalid_values") {
        const analysis = this.invalidValuesAnalyzer.analyze(test);

        // Issue #173: Track graceful degradation
        if (analysis.classification === "graceful_degradation") {
          gracefulDegradationCount++;
        }

        // Issue #173: Track suggestions
        if (test.hasSuggestions) {
          suggestionCount++;
        }

        // Issue #173: Apply bonus points for graceful handling and suggestions
        if (analysis.bonusPoints > 0) {
          enhancedScore += analysis.bonusPoints;
          maxPossibleScore += analysis.bonusPoints;
          suggestionBonusPoints += analysis.bonusPoints;
        }

        if (!analysis.shouldPenalize) {
          // Safe response (rejection, reflection, defensive programming, graceful degradation)
          return;
        }
        // Execution detected or unknown - include in scoring with penalty
        maxPossibleScore += 100;
        const scoreEarned = 100 * (1 - analysis.penaltyAmount / 100);
        enhancedScore += test.passed ? scoreEarned : 0;
        return;
      }

      maxPossibleScore += 100; // Base score for each test

      if (test.passed) {
        enhancedScore += 100; // Base points for passing

        // Extra points for specific field names in error
        if (
          /\b(query|field|parameter|argument|prop|key)\b/i.test(
            test.actualResponse.errorMessage ?? "",
          )
        ) {
          enhancedScore += 10;
          maxPossibleScore += 10;
        }

        // Extra points for helpful context
        if (
          test.actualResponse.errorMessage &&
          test.actualResponse.errorMessage.length > 30
        ) {
          enhancedScore += 5;
          maxPossibleScore += 5;
        }

        // Extra points for proper error codes
        if (test.actualResponse.errorCode) {
          enhancedScore += 5;
          maxPossibleScore += 5;
        }

        // Issue #173: Extra points for suggestions in other test types
        if (test.hasSuggestions) {
          suggestionCount++;
          enhancedScore += 10;
          maxPossibleScore += 10;
          suggestionBonusPoints += 10;
        }
      }
    });

    const score =
      maxPossibleScore > 0 ? (enhancedScore / maxPossibleScore) * 100 : 0;

    // Determine quality rating based on enhanced score
    let quality: ErrorHandlingMetrics["errorResponseQuality"];
    if (score >= 85) quality = "excellent";
    else if (score >= 70) quality = "good";
    else if (score >= 50) quality = "fair";
    else quality = "poor";

    // Check for proper error codes and messages (only among actual errors)
    const actualErrors = tests.filter((t) => t.actualResponse.isError);
    const errorsWithCodes = actualErrors.filter(
      (t) => t.actualResponse.errorCode !== undefined,
    ).length;
    const errorsWithMessages = actualErrors.filter(
      (t) =>
        t.actualResponse.errorMessage &&
        t.actualResponse.errorMessage.length > 10,
    ).length;

    // Handle case when no tests were run
    const hasProperErrorCodes =
      tests.length === 0
        ? false
        : actualErrors.length === 0
          ? true
          : errorsWithCodes / actualErrors.length >= 0.5;

    const hasDescriptiveMessages =
      tests.length === 0
        ? false
        : actualErrors.length === 0
          ? true
          : errorsWithMessages / actualErrors.length >= 0.5;

    const validatesInputs = tests
      .filter((t) => ["missing_required", "wrong_type"].includes(t.testType))
      .some((t) => t.passed);

    return {
      mcpComplianceScore: score,
      errorResponseQuality: quality,
      hasProperErrorCodes,
      hasDescriptiveMessages,
      validatesInputs,
      testDetails: tests,
      // Issue #173: Graceful degradation and suggestion metrics
      gracefulDegradationCount,
      suggestionCount,
      suggestionBonusPoints,
    };
  }

  /**
   * Determine error handling status based on metrics.
   */
  determineStatus(
    metrics: ErrorHandlingMetrics,
    testCount: number,
  ): AssessmentStatus {
    // If no tests were run, we can't determine error handling status
    if (testCount === 0) return "NEED_MORE_INFO";

    // More lenient thresholds that recognize good error handling
    if (metrics.mcpComplianceScore >= 70) return "PASS";
    if (metrics.mcpComplianceScore >= 40) return "NEED_MORE_INFO";
    return "FAIL";
  }
}
