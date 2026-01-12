/**
 * Test Validity Analyzer
 *
 * Detects when security test responses are suspiciously uniform,
 * indicating tests may not have reached security-relevant code paths.
 *
 * @see Issue #134: Detect identical security test responses (test validity masking)
 */

import type { SecurityTestResult } from "@/lib/assessment/resultTypes";
import type { TestValidityWarning } from "@/lib/assessment/resultTypes";

/**
 * Configuration for test validity analysis
 */
export interface TestValidityConfig {
  /** Percentage threshold to trigger warning (default: 80) */
  warningThresholdPercent: number;
  /** Percentage threshold to reduce confidence (default: 90) */
  confidenceReduceThresholdPercent: number;
  /** Minimum tests required for analysis (default: 10) */
  minimumTestsForAnalysis: number;
  /** Maximum response length to compare (default: 1000) */
  maxResponseCompareLength: number;
}

/**
 * Result of test validity analysis
 */
export interface TestValidityResult {
  /** Whether test validity is compromised */
  isCompromised: boolean;
  /** Warning level: none, warning, critical */
  warningLevel: "none" | "warning" | "critical";
  /** Recommended confidence adjustment */
  recommendedConfidence: "high" | "medium" | "low";
  /** Detailed warning information */
  warning?: TestValidityWarning;
  /** Per-tool uniformity analysis */
  toolUniformity?: Map<
    string,
    {
      identicalCount: number;
      totalCount: number;
      percentageIdentical: number;
    }
  >;
}

const DEFAULT_CONFIG: TestValidityConfig = {
  warningThresholdPercent: 80,
  confidenceReduceThresholdPercent: 90,
  minimumTestsForAnalysis: 10,
  maxResponseCompareLength: 1000,
};

/**
 * Analyzes security test results for response uniformity.
 *
 * When a high percentage of test responses are identical, it indicates
 * that tests may be hitting a configuration error, connection issue,
 * or other problem that prevents them from reaching security-relevant code.
 */
export class TestValidityAnalyzer {
  private config: TestValidityConfig;

  constructor(config?: Partial<TestValidityConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Analyze test results for response uniformity
   *
   * @param testResults - Array of security test results with responses
   * @returns Analysis result with warning details if uniformity detected
   */
  analyze(testResults: SecurityTestResult[]): TestValidityResult {
    // Filter to tests with responses
    const testsWithResponses = testResults.filter(
      (t) => t.response !== undefined && t.response !== null,
    );

    // Need minimum number of tests for meaningful analysis
    if (testsWithResponses.length < this.config.minimumTestsForAnalysis) {
      return {
        isCompromised: false,
        warningLevel: "none",
        recommendedConfidence: "high",
      };
    }

    // Count response frequency with normalization
    const responseCounts = this.countNormalizedResponses(testsWithResponses);

    // Find most common response
    const [mostCommonResponse, mostCommonCount] =
      this.findMostCommon(responseCounts);
    const percentageIdentical =
      (mostCommonCount / testsWithResponses.length) * 100;

    // Detect pattern category
    const detectedPattern = this.detectPatternCategory(mostCommonResponse);

    // Per-tool analysis
    const toolUniformity = this.analyzePerTool(testResults);

    // Determine warning level
    let warningLevel: "none" | "warning" | "critical" = "none";
    let recommendedConfidence: "high" | "medium" | "low" = "high";

    if (percentageIdentical >= this.config.confidenceReduceThresholdPercent) {
      warningLevel = "critical";
      recommendedConfidence = "low";
    } else if (percentageIdentical >= this.config.warningThresholdPercent) {
      warningLevel = "warning";
      recommendedConfidence = "medium";
    }

    const isCompromised = warningLevel !== "none";

    // Find the original (non-normalized) sample response for display
    const sampleResponse = this.findOriginalSample(
      testsWithResponses,
      mostCommonResponse,
    );

    return {
      isCompromised,
      warningLevel,
      recommendedConfidence,
      warning: isCompromised
        ? {
            identicalResponseCount: mostCommonCount,
            totalResponses: testsWithResponses.length,
            percentageIdentical: Math.round(percentageIdentical * 10) / 10,
            sampleResponse: sampleResponse.substring(0, 500),
            detectedPattern,
            explanation: this.generateExplanation(
              percentageIdentical,
              detectedPattern,
              mostCommonCount,
              testsWithResponses.length,
            ),
          }
        : undefined,
      toolUniformity,
    };
  }

  /**
   * Normalize response for comparison.
   * Removes timestamps, UUIDs, request IDs, and other variable content.
   */
  private normalizeResponse(response: string): string {
    let normalized = response.substring(
      0,
      this.config.maxResponseCompareLength,
    );

    // Remove common variable patterns
    normalized = normalized
      // ISO timestamps
      .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*Z?/g, "<TIMESTAMP>")
      // Unix timestamps (10-13 digits)
      .replace(/\b\d{10,13}\b/g, "<TIMESTAMP>")
      // UUIDs
      .replace(
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        "<UUID>",
      )
      // Request/correlation IDs (common patterns)
      .replace(
        /"(?:request_?id|correlation_?id|trace_?id)"\s*:\s*"[^"]+"/gi,
        '"<ID>": "<VALUE>"',
      )
      // Generic hex IDs (16+ chars)
      .replace(/\b[0-9a-f]{16,}\b/gi, "<HEX_ID>")
      // Normalize whitespace
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();

    return normalized;
  }

  /**
   * Count occurrences of normalized responses
   */
  private countNormalizedResponses(
    tests: SecurityTestResult[],
  ): Map<string, number> {
    const counts = new Map<string, number>();

    for (const test of tests) {
      if (test.response) {
        const normalized = this.normalizeResponse(test.response);
        counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
      }
    }

    return counts;
  }

  /**
   * Find the most common response
   */
  private findMostCommon(counts: Map<string, number>): [string, number] {
    let maxCount = 0;
    let mostCommon = "";

    for (const [response, count] of counts) {
      if (count > maxCount) {
        maxCount = count;
        mostCommon = response;
      }
    }

    return [mostCommon, maxCount];
  }

  /**
   * Find original (non-normalized) sample that matches the normalized pattern
   */
  private findOriginalSample(
    tests: SecurityTestResult[],
    normalizedPattern: string,
  ): string {
    for (const test of tests) {
      if (test.response) {
        const normalized = this.normalizeResponse(test.response);
        if (normalized === normalizedPattern) {
          return test.response;
        }
      }
    }
    return normalizedPattern;
  }

  /**
   * Detect the category of the response pattern
   */
  private detectPatternCategory(
    response: string,
  ): TestValidityWarning["detectedPattern"] {
    const lower = response.toLowerCase();

    // Configuration errors
    if (
      /api[_\s]?key|credentials?|auth|token|secret|config/i.test(lower) &&
      /missing|invalid|required|not found|error/i.test(lower)
    ) {
      return "configuration_error";
    }

    // Connection errors
    if (
      /connection|refused|econnrefused|timeout|unreachable|network|socket/i.test(
        lower,
      )
    ) {
      return "connection_error";
    }

    // Timeout
    if (/timeout|timed?\s*out|exceeded/i.test(lower)) {
      return "timeout";
    }

    // Empty responses
    if (
      response.length < 50 ||
      /^(\s*\{\s*\}|\s*\[\s*\]|\s*null\s*|)$/i.test(response.trim())
    ) {
      return "empty_response";
    }

    // Generic error
    if (/error|exception|fail|invalid/i.test(lower)) {
      return "generic_error";
    }

    return "unknown";
  }

  /**
   * Analyze uniformity per tool
   */
  private analyzePerTool(
    tests: SecurityTestResult[],
  ): Map<
    string,
    { identicalCount: number; totalCount: number; percentageIdentical: number }
  > {
    const result = new Map<
      string,
      {
        identicalCount: number;
        totalCount: number;
        percentageIdentical: number;
      }
    >();
    const toolTests = new Map<string, SecurityTestResult[]>();

    // Group by tool
    for (const test of tests) {
      const toolName = test.toolName ?? "unknown";
      if (!toolTests.has(toolName)) {
        toolTests.set(toolName, []);
      }
      toolTests.get(toolName)!.push(test);
    }

    // Analyze each tool
    for (const [toolName, toolTestResults] of toolTests) {
      const testsWithResponse = toolTestResults.filter((t) => t.response);
      const counts = this.countNormalizedResponses(testsWithResponse);
      const [, maxCount] = this.findMostCommon(counts);
      const total = testsWithResponse.length;

      if (total > 0) {
        result.set(toolName, {
          identicalCount: maxCount,
          totalCount: total,
          percentageIdentical: Math.round((maxCount / total) * 100 * 10) / 10,
        });
      }
    }

    return result;
  }

  /**
   * Generate human-readable explanation
   */
  private generateExplanation(
    percentage: number,
    pattern: TestValidityWarning["detectedPattern"],
    identicalCount: number,
    totalCount: number,
  ): string {
    const patternDescriptions: Record<string, string> = {
      configuration_error: "a configuration error (e.g., missing API key)",
      connection_error: "a connection failure",
      timeout: "request timeouts",
      empty_response: "empty responses",
      generic_error: "a generic error",
      unknown: "an unknown pattern",
    };

    const patternDesc =
      patternDescriptions[pattern] ?? patternDescriptions.unknown;

    return `${Math.round(percentage)}% of security tests (${identicalCount}/${totalCount}) returned identical responses indicating ${patternDesc}. Tests may not have reached security-relevant code paths. Resolve the underlying issue and re-run the assessment for valid security analysis.`;
  }
}
