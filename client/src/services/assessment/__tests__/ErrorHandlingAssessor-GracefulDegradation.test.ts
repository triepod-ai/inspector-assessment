/**
 * Unit tests for Issue #173: Graceful Degradation and Suggestion Detection
 * Tests optional parameter handling, suggestion patterns, and bonus scoring
 */

import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor";
import { ErrorTestDetail } from "@/lib/assessmentTypes";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessment/configTypes";
import { getPrivateMethod } from "@/test/utils/testUtils";

// Type definitions for private method return types (Issue #186)
type SuggestionResult = { hasSuggestions: boolean; suggestions: string[] };
type AnalysisResult = {
  classification: string;
  shouldPenalize: boolean;
  bonusPoints: number;
};
type ParamsResult = {
  params: Record<string, unknown>;
  testedParameter: string;
  parameterIsRequired: boolean;
};
type MetricsResult = {
  mcpComplianceScore: number;
  gracefulDegradationCount: number;
  suggestionCount: number;
  suggestionBonusPoints: number;
};
// Schema type for generateInvalidValueParams (Issue #186)
type SchemaParam = Record<string, unknown> | null;

describe("ErrorHandlingAssessor - Graceful Degradation (Issue #173)", () => {
  let assessor: ErrorHandlingAssessor;
  let detectSuggestionPatterns: (text: string) => SuggestionResult;
  let isNeutralGracefulResponse: (text: string) => boolean;
  let analyzeInvalidValuesResponse: (test: ErrorTestDetail) => AnalysisResult;
  let generateInvalidValueParams: (schema: SchemaParam) => ParamsResult;
  let calculateMetrics: (
    tests: ErrorTestDetail[],
    passedTests: number,
  ) => MetricsResult;

  beforeEach(() => {
    assessor = new ErrorHandlingAssessor(DEFAULT_ASSESSMENT_CONFIG);
    // Create typed method references (Issue #186)
    detectSuggestionPatterns = getPrivateMethod(
      assessor,
      "detectSuggestionPatterns",
    );
    isNeutralGracefulResponse = getPrivateMethod(
      assessor,
      "isNeutralGracefulResponse",
    );
    analyzeInvalidValuesResponse = getPrivateMethod(
      assessor,
      "analyzeInvalidValuesResponse",
    );
    generateInvalidValueParams = getPrivateMethod(
      assessor,
      "generateInvalidValueParams",
    );
    calculateMetrics = getPrivateMethod(assessor, "calculateMetrics");
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  /**
   * Helper to create mock ErrorTestDetail for invalid_values tests with Issue #173 fields
   */
  function createInvalidValuesTest(
    toolName: string,
    isError: boolean,
    rawResponse: unknown,
    options: {
      errorMessage?: string;
      testedParameter?: string;
      parameterIsRequired?: boolean;
      hasSuggestions?: boolean;
      suggestions?: string[];
    } = {},
  ): ErrorTestDetail {
    return {
      toolName,
      testType: "invalid_values",
      testInput: { query: "" },
      expectedError: "Invalid parameter values",
      actualResponse: {
        isError,
        errorCode: isError ? -32602 : undefined,
        errorMessage:
          options.errorMessage || (isError ? "Validation failed" : undefined),
        rawResponse,
      },
      passed: isError,
      reason: isError ? undefined : "Tool accepted invalid values",
      testedParameter: options.testedParameter,
      parameterIsRequired: options.parameterIsRequired,
      hasSuggestions: options.hasSuggestions,
      suggestions: options.suggestions,
    };
  }

  describe("detectSuggestionPatterns()", () => {
    it('should detect "did you mean" pattern', () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Invalid component. Did you mean: Button, Checkbox?",
      );

      expect(hasSuggestions).toBe(true);
      expect(suggestions).toContain("Button");
      expect(suggestions).toContain("Checkbox");
    });

    it('should detect "valid options" pattern', () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Unknown type. Valid options: text, number, boolean",
      );

      expect(hasSuggestions).toBe(true);
      expect(suggestions).toContain("text");
      expect(suggestions).toContain("number");
      expect(suggestions).toContain("boolean");
    });

    it('should detect "available" pattern', () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Component not found. Available: Link, Image, Table",
      );

      expect(hasSuggestions).toBe(true);
      expect(suggestions.length).toBeGreaterThan(0);
    });

    it('should detect "try" pattern', () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Resource not found. Try: home, about, contact",
      );

      expect(hasSuggestions).toBe(true);
      expect(suggestions.length).toBeGreaterThan(0);
    });

    it('should detect "expected one of" pattern', () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Invalid format. Expected one of: json, xml, csv",
      );

      expect(hasSuggestions).toBe(true);
      expect(suggestions).toContain("json");
    });

    it("should return empty for no suggestions", () => {
      const { hasSuggestions, suggestions } = detectSuggestionPatterns(
        "Invalid input provided",
      );

      expect(hasSuggestions).toBe(false);
      expect(suggestions).toHaveLength(0);
    });
  });

  describe("ReDoS protection (ISSUE-002)", () => {
    it("should handle very long input without hanging (detectSuggestionPatterns)", () => {
      const longInput = "a".repeat(10000);
      const start = Date.now();

      detectSuggestionPatterns(longInput);

      const elapsed = Date.now() - start;
      // Should complete in well under 1 second due to truncation
      expect(elapsed).toBeLessThan(1000);
    });

    it("should handle very long input without hanging (isNeutralGracefulResponse)", () => {
      const longInput = "x".repeat(10000);
      const start = Date.now();

      isNeutralGracefulResponse(longInput);

      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(1000);
    });

    it("should still detect patterns in truncated input", () => {
      // Pattern near the start should still be detected after truncation
      const longInput = "Did you mean: Button, Checkbox?" + "x".repeat(10000);

      const { hasSuggestions, suggestions } =
        detectSuggestionPatterns(longInput);

      expect(hasSuggestions).toBe(true);
      expect(suggestions).toContain("Button");
    });
  });

  describe("isNeutralGracefulResponse()", () => {
    it("should detect empty JSON array", () => {
      const result = isNeutralGracefulResponse("[]");
      expect(result).toBe(true);
    });

    it("should detect empty JSON object", () => {
      const result = isNeutralGracefulResponse("{}");
      expect(result).toBe(true);
    });

    it('should detect "no results found" pattern', () => {
      const result = isNeutralGracefulResponse(
        "No results found for your query",
      );
      expect(result).toBe(true);
    });

    it('should detect "returned 0" pattern', () => {
      const result = isNeutralGracefulResponse("Search returned 0 items");
      expect(result).toBe(true);
    });

    it("should detect JSON with empty results array", () => {
      const result = isNeutralGracefulResponse('{"results": [], "count": 0}');
      expect(result).toBe(true);
    });

    it("should NOT match non-graceful responses", () => {
      const result = isNeutralGracefulResponse(
        "Successfully executed query with 5 results",
      );
      expect(result).toBe(false);
    });
  });

  describe("graceful_degradation classification", () => {
    it("should classify optional param with empty results as graceful_degradation", () => {
      const test = createInvalidValuesTest(
        "search_tool",
        false,
        {
          content: [{ type: "text", text: "[]" }],
        },
        {
          testedParameter: "query",
          parameterIsRequired: false, // Optional parameter
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("graceful_degradation");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.bonusPoints).toBe(15);
    });

    it("should NOT apply graceful_degradation for REQUIRED parameters", () => {
      const test = createInvalidValuesTest(
        "search_tool",
        false,
        {
          content: [{ type: "text", text: "[]" }],
        },
        {
          testedParameter: "id",
          parameterIsRequired: true, // Required parameter - should still be penalized
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      // Should fall through to another classification, not graceful_degradation
      expect(analysis.classification).not.toBe("graceful_degradation");
    });

    it("should handle 'no results found' as graceful degradation for optional param", () => {
      const test = createInvalidValuesTest(
        "search_tool",
        false,
        {
          content: [{ type: "text", text: "No results found" }],
        },
        {
          testedParameter: "filter",
          parameterIsRequired: false,
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("graceful_degradation");
      expect(analysis.bonusPoints).toBe(15);
    });
  });

  describe("suggestion bonus in safe_rejection", () => {
    it("should award bonus points for error with suggestions", () => {
      const test = createInvalidValuesTest(
        "component_tool",
        true, // isError
        { error: "Component not found. Did you mean: Button, Checkbox?" },
        {
          errorMessage: "Component not found. Did you mean: Button, Checkbox?",
          hasSuggestions: true,
          suggestions: ["Button", "Checkbox"],
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.bonusPoints).toBe(10); // Suggestion bonus
    });

    it("should NOT award bonus for error without suggestions", () => {
      const test = createInvalidValuesTest(
        "component_tool",
        true,
        { error: "Invalid input" },
        {
          errorMessage: "Invalid input",
          hasSuggestions: false,
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.bonusPoints).toBe(0);
    });
  });

  describe("generateInvalidValueParams() metadata", () => {
    it("should track tested parameter name", () => {
      const schema = {
        type: "object" as const,
        properties: {
          query: { type: "string" as const },
          limit: { type: "number" as const },
        },
        required: ["query"],
      };

      const result = generateInvalidValueParams(schema);

      expect(result.testedParameter).toBe("query");
      expect(result.parameterIsRequired).toBe(true);
    });

    it("should identify optional parameters correctly", () => {
      const schema = {
        type: "object" as const,
        properties: {
          filter: { type: "string" as const },
          sort: { type: "string" as const },
        },
        required: [], // No required params
      };

      const result = generateInvalidValueParams(schema);

      expect(result.testedParameter).toBe("filter");
      expect(result.parameterIsRequired).toBe(false);
    });

    it("should handle schema with no properties", () => {
      const result = generateInvalidValueParams(null);

      expect(result.testedParameter).toBe("value");
      expect(result.parameterIsRequired).toBe(false);
    });
  });

  describe("analyzeInvalidValuesResponse() comprehensive tests", () => {
    it("should classify standard error without suggestions as safe_rejection with no bonus", () => {
      const test = createInvalidValuesTest(
        "tool",
        true, // isError
        { error: { code: -32602, message: "Invalid params" } },
        {
          errorMessage: "Invalid params",
          testedParameter: "param",
          parameterIsRequired: true,
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.bonusPoints).toBe(0);
    });

    it("should penalize non-error response on required param", () => {
      const test = createInvalidValuesTest(
        "tool",
        false, // Not an error
        { content: [{ type: "text", text: "Success" }] },
        {
          testedParameter: "id",
          parameterIsRequired: true, // Required param should be validated
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      // Should be penalized because required param wasn't validated
      // Classification is "unknown" since it's not a clear execution or safe response
      expect(analysis.classification).toBe("unknown");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.bonusPoints).toBe(0);
    });

    it("should handle response with isError flag but no error object", () => {
      const test = createInvalidValuesTest(
        "tool",
        true, // isError from actualResponse
        { content: [{ type: "text", text: "Error occurred" }], isError: true },
        {
          errorMessage: "Error occurred",
          testedParameter: "query",
          parameterIsRequired: false,
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.shouldPenalize).toBe(false);
    });

    it("should handle empty content in response gracefully", () => {
      const test = createInvalidValuesTest(
        "tool",
        false,
        { content: [] },
        {
          testedParameter: "query",
          parameterIsRequired: false,
        },
      );

      const analysis = analyzeInvalidValuesResponse(test);

      // Empty content should be checked for graceful response
      expect(analysis).toBeDefined();
      expect(typeof analysis.bonusPoints).toBe("number");
    });
  });

  describe("calculateMetrics() with Issue #173 fields", () => {
    it("should track graceful degradation count", () => {
      const tests: ErrorTestDetail[] = [
        createInvalidValuesTest(
          "tool1",
          false,
          { content: [{ type: "text", text: "[]" }] },
          {
            testedParameter: "query",
            parameterIsRequired: false,
          },
        ),
        createInvalidValuesTest(
          "tool2",
          false,
          { content: [{ type: "text", text: "No results found" }] },
          {
            testedParameter: "filter",
            parameterIsRequired: false,
          },
        ),
      ];

      const metrics = calculateMetrics(tests, 0);

      expect(metrics.gracefulDegradationCount).toBe(2);
    });

    it("should track suggestion count and bonus points", () => {
      const tests: ErrorTestDetail[] = [
        createInvalidValuesTest(
          "tool1",
          true,
          { error: "Did you mean: A, B?" },
          {
            errorMessage: "Did you mean: A, B?",
            hasSuggestions: true,
            suggestions: ["A", "B"],
          },
        ),
      ];

      const metrics = calculateMetrics(tests, 1);

      expect(metrics.suggestionCount).toBe(1);
      expect(metrics.suggestionBonusPoints).toBe(10);
    });

    it("should include bonus points in overall score calculation", () => {
      // Two graceful degradation tests = 2 * 15 = 30 bonus points
      const tests: ErrorTestDetail[] = [
        createInvalidValuesTest(
          "tool1",
          false,
          { content: [{ type: "text", text: "[]" }] },
          {
            testedParameter: "q1",
            parameterIsRequired: false,
          },
        ),
        createInvalidValuesTest(
          "tool2",
          false,
          { content: [{ type: "text", text: "[]" }] },
          {
            testedParameter: "q2",
            parameterIsRequired: false,
          },
        ),
      ];

      const metrics = calculateMetrics(tests, 0);

      // Score should be 100% because bonus points are earned
      expect(metrics.mcpComplianceScore).toBe(100);
      expect(metrics.suggestionBonusPoints).toBe(30); // 2 * 15
    });
  });
});
