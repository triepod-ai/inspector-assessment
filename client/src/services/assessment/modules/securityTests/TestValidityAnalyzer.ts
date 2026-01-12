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
  // Issue #135: Enhanced data config
  /** Maximum sample payload-response pairs (default: 10) */
  maxSamplePairs: number;
  /** Maximum response distribution entries (default: 5) */
  maxDistributionEntries: number;
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
  // Issue #135: Enhanced data defaults
  maxSamplePairs: 10,
  maxDistributionEntries: 5,
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
            // Existing fields
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
            // Issue #135: Enhanced fields for Stage B semantic analysis
            responseDiversity: {
              uniqueResponses: responseCounts.size,
              entropyScore:
                Math.round(this.calculateEntropy(responseCounts) * 100) / 100,
              distribution: this.buildResponseDistribution(
                responseCounts,
                testsWithResponses.length,
              ),
            },
            toolUniformity: Object.fromEntries(toolUniformity),
            attackPatternCorrelation:
              this.analyzeAttackPatterns(testsWithResponses),
            samplePairs: this.collectSamplePairs(testsWithResponses),
            responseMetadata: this.collectResponseMetadata(testsWithResponses),
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

  // ==========================================================================
  // Issue #135: Enhanced data methods for Stage B semantic analysis
  // ==========================================================================

  /**
   * Calculate Shannon entropy for response diversity (0=uniform, 1=max diversity)
   */
  private calculateEntropy(counts: Map<string, number>): number {
    const total = Array.from(counts.values()).reduce((a, b) => a + b, 0);
    if (total === 0) return 0;

    let entropy = 0;
    for (const count of counts.values()) {
      if (count > 0) {
        const p = count / total;
        entropy -= p * Math.log2(p);
      }
    }

    // Normalize to 0-1 scale based on max possible entropy
    const maxEntropy = Math.log2(counts.size);
    return maxEntropy > 0 ? entropy / maxEntropy : 0;
  }

  /**
   * Build response distribution sorted by frequency
   */
  private buildResponseDistribution(
    counts: Map<string, number>,
    total: number,
  ): Array<{ response: string; count: number; percentage: number }> {
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.config.maxDistributionEntries)
      .map(([response, count]) => ({
        response: response.substring(0, 200),
        count,
        percentage: Math.round((count / total) * 1000) / 10,
      }));
  }

  /**
   * Extract attack category from test name
   */
  private extractAttackCategory(testName: string): string {
    const lower = testName.toLowerCase();
    if (lower.includes("injection") || lower.includes("sqli"))
      return "injection";
    if (lower.includes("xss") || lower.includes("script")) return "xss";
    if (lower.includes("path") || lower.includes("traversal"))
      return "path_traversal";
    if (lower.includes("command") || lower.includes("rce"))
      return "command_injection";
    if (lower.includes("ssrf")) return "ssrf";
    if (lower.includes("auth")) return "authentication";
    return "other";
  }

  /**
   * Analyze attack pattern correlation by category
   */
  private analyzeAttackPatterns(tests: SecurityTestResult[]): Record<
    string,
    {
      testCount: number;
      uniqueResponses: number;
      samplePayload?: string;
      sampleResponse?: string;
    }
  > {
    const patterns = new Map<string, SecurityTestResult[]>();

    // Group by attack category
    for (const test of tests) {
      const category = this.extractAttackCategory(test.testName);
      if (!patterns.has(category)) patterns.set(category, []);
      patterns.get(category)!.push(test);
    }

    // Build correlation stats
    const result: Record<
      string,
      {
        testCount: number;
        uniqueResponses: number;
        samplePayload?: string;
        sampleResponse?: string;
      }
    > = {};

    for (const [category, categoryTests] of patterns) {
      const withResponse = categoryTests.filter((t) => t.response);
      const counts = this.countNormalizedResponses(withResponse);
      result[category] = {
        testCount: categoryTests.length,
        uniqueResponses: counts.size,
        samplePayload: categoryTests[0]?.payload?.substring(0, 100),
        sampleResponse: categoryTests[0]?.response?.substring(0, 200),
      };
    }

    return result;
  }

  /**
   * Collect sample payload-response pairs with category diversity
   */
  private collectSamplePairs(tests: SecurityTestResult[]): Array<{
    attackCategory: string;
    payload: string;
    response: string;
    vulnerable: boolean;
  }> {
    const pairs: Array<{
      attackCategory: string;
      payload: string;
      response: string;
      vulnerable: boolean;
    }> = [];
    const seenCategories = new Set<string>();

    // Prioritize diverse categories
    for (const test of tests) {
      if (pairs.length >= this.config.maxSamplePairs) break;
      if (!test.response || !test.payload) continue;

      const category = this.extractAttackCategory(test.testName);
      if (!seenCategories.has(category)) {
        seenCategories.add(category);
        pairs.push({
          attackCategory: category,
          payload: test.payload.substring(0, 100),
          response: test.response.substring(0, 300),
          vulnerable: test.vulnerable,
        });
      }
    }

    // Fill remaining slots with additional samples
    for (const test of tests) {
      if (pairs.length >= this.config.maxSamplePairs) break;
      if (!test.response || !test.payload) continue;

      const truncatedPayload = test.payload.substring(0, 100);
      if (!pairs.some((p) => p.payload === truncatedPayload)) {
        pairs.push({
          attackCategory: this.extractAttackCategory(test.testName),
          payload: truncatedPayload,
          response: test.response.substring(0, 300),
          vulnerable: test.vulnerable,
        });
      }
    }

    return pairs;
  }

  /**
   * Collect response metadata statistics
   */
  private collectResponseMetadata(tests: SecurityTestResult[]): {
    avgLength: number;
    minLength: number;
    maxLength: number;
    emptyCount: number;
    errorCount: number;
  } {
    if (tests.length === 0) {
      return {
        avgLength: 0,
        minLength: 0,
        maxLength: 0,
        emptyCount: 0,
        errorCount: 0,
      };
    }

    let totalLength = 0;
    let minLength = Infinity;
    let maxLength = 0;
    let emptyCount = 0;
    let errorCount = 0;
    let nonEmptyCount = 0;

    for (const test of tests) {
      const response = test.response ?? "";
      const len = response.length;

      // Check for empty/minimal responses
      if (
        len === 0 ||
        /^(\s*\{\s*\}|\s*\[\s*\]|\s*null\s*|)$/i.test(response.trim())
      ) {
        emptyCount++;
      } else {
        totalLength += len;
        minLength = Math.min(minLength, len);
        maxLength = Math.max(maxLength, len);
        nonEmptyCount++;
      }

      // Check for error indicators
      if (/error|exception|fail/i.test(response)) {
        errorCount++;
      }
    }

    return {
      avgLength:
        nonEmptyCount > 0 ? Math.round(totalLength / nonEmptyCount) : 0,
      minLength: minLength === Infinity ? 0 : minLength,
      maxLength,
      emptyCount,
      errorCount,
    };
  }
}
