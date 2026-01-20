/**
 * Unit tests for Issue #99: Contextual empty string validation scoring
 * Tests the analyzeInvalidValuesResponse() method and calculateMetrics() integration
 */

// @deprecated - using deprecated module for backward compatibility testing
import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor.deprecated";
import { ErrorTestDetail } from "@/lib/assessmentTypes";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessment/configTypes";
import { getPrivateMethod } from "@/test/utils/testUtils";

// Type definitions for private method return types (Issue #186)
type AnalysisResult = {
  classification: string;
  shouldPenalize: boolean;
  penaltyAmount: number;
};
type MetricsResult = {
  mcpComplianceScore: number;
};

// @deprecated These tests are skipped because ErrorHandlingAssessor is now a thin wrapper
// that delegates to ProtocolComplianceAssessor. The internal methods tested here no longer
// exist in the wrapper. These tests will be removed in v2.0.0.
describe.skip("ErrorHandlingAssessor - Invalid Values Contextual Scoring (Issue #99)", () => {
  let assessor: ErrorHandlingAssessor;
  let analyzeInvalidValuesResponse: (test: ErrorTestDetail) => AnalysisResult;
  let extractResponseTextSafe: (response: unknown) => string;
  let isDefensiveProgrammingResponse: (text: string) => boolean;
  let calculateMetrics: (
    tests: ErrorTestDetail[],
    passedTests: number,
  ) => MetricsResult;

  beforeEach(() => {
    assessor = new ErrorHandlingAssessor(DEFAULT_ASSESSMENT_CONFIG);
    // Create typed method references (Issue #186)
    analyzeInvalidValuesResponse = getPrivateMethod(
      assessor,
      "analyzeInvalidValuesResponse",
    );
    extractResponseTextSafe = getPrivateMethod(
      assessor,
      "extractResponseTextSafe",
    );
    isDefensiveProgrammingResponse = getPrivateMethod(
      assessor,
      "isDefensiveProgrammingResponse",
    );
    calculateMetrics = getPrivateMethod(assessor, "calculateMetrics");
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  /**
   * Helper to create mock ErrorTestDetail for invalid_values tests
   */
  function createInvalidValuesTest(
    toolName: string,
    isError: boolean,
    rawResponse: unknown,
    errorMessage?: string,
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
          errorMessage || (isError ? "Validation failed" : undefined),
        rawResponse,
      },
      passed: isError,
      reason: isError ? undefined : "Tool accepted invalid values",
    };
  }

  describe("safe_rejection classification", () => {
    it("should not penalize when tool rejects empty string with error", () => {
      const test = createInvalidValuesTest(
        "test_tool",
        true, // isError
        { error: "Empty string not allowed" },
        "Empty string not allowed for query parameter",
      );

      // Access private method via type casting for testing
      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.penaltyAmount).toBe(0);
    });

    it("should classify MCP validation error as safe_rejection", () => {
      const test = createInvalidValuesTest(
        "mcp_tool",
        true,
        { code: -32602, message: "Invalid params" },
        "Invalid params: query must be non-empty",
      );

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_rejection");
      expect(analysis.shouldPenalize).toBe(false);
    });
  });

  describe("safe_reflection classification", () => {
    it("should not penalize when tool stores empty string without execution", () => {
      const test = createInvalidValuesTest("store_tool", false, {
        content: [{ type: "text", text: 'Stored query: ""' }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_reflection");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.penaltyAmount).toBe(0);
    });

    it("should not penalize echo-style responses", () => {
      const test = createInvalidValuesTest("echo_tool", false, {
        content: [{ type: "text", text: 'Echo: ""' }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_reflection");
      expect(analysis.shouldPenalize).toBe(false);
    });

    it("should not penalize 'saved input' responses", () => {
      const test = createInvalidValuesTest("save_tool", false, {
        content: [{ type: "text", text: "Saved input successfully" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("safe_reflection");
      expect(analysis.shouldPenalize).toBe(false);
    });
  });

  describe("defensive_programming classification", () => {
    it("should not penalize 'Deleted 0 keys' responses", () => {
      const test = createInvalidValuesTest("delete_tool", false, {
        content: [{ type: "text", text: "Deleted 0 keys" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("defensive_programming");
      expect(analysis.shouldPenalize).toBe(false);
      expect(analysis.penaltyAmount).toBe(0);
    });

    it("should not penalize 'No results found' responses", () => {
      const test = createInvalidValuesTest("search_tool", false, {
        content: [{ type: "text", text: "No results found" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("defensive_programming");
      expect(analysis.shouldPenalize).toBe(false);
    });

    it("should not penalize '0 items deleted' responses", () => {
      const test = createInvalidValuesTest("cleanup_tool", false, {
        content: [{ type: "text", text: "0 items deleted" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("defensive_programming");
      expect(analysis.shouldPenalize).toBe(false);
    });

    it("should not penalize 'query returned 0' responses", () => {
      const test = createInvalidValuesTest("query_tool", false, {
        content: [{ type: "text", text: "query returned 0 results" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("defensive_programming");
      expect(analysis.shouldPenalize).toBe(false);
    });

    it("should not penalize 'no action taken' responses", () => {
      const test = createInvalidValuesTest("action_tool", false, {
        content: [{ type: "text", text: "no action taken" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("defensive_programming");
      expect(analysis.shouldPenalize).toBe(false);
    });
  });

  describe("execution_detected classification", () => {
    it("should penalize when response shows execution evidence", () => {
      const test = createInvalidValuesTest("exec_tool", false, {
        content: [{ type: "text", text: "Command executed successfully" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("execution_detected");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.penaltyAmount).toBe(100);
    });

    it("should penalize when response shows database modification", () => {
      const test = createInvalidValuesTest("db_tool", false, {
        content: [{ type: "text", text: "deleted 5 rows from users table" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("execution_detected");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.penaltyAmount).toBe(100);
    });

    it("should penalize when response shows file system artifacts", () => {
      const test = createInvalidValuesTest("file_tool", false, {
        content: [
          {
            type: "text",
            text: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
          },
        ],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("execution_detected");
      expect(analysis.shouldPenalize).toBe(true);
    });

    it("should penalize when response shows query results affected", () => {
      const test = createInvalidValuesTest("sql_tool", false, {
        content: [{ type: "text", text: "query returned 15 results" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("execution_detected");
      expect(analysis.shouldPenalize).toBe(true);
    });

    it("should penalize 'Operation completed' as execution evidence", () => {
      // "completed" is an execution indicator - if tool says operation completed
      // on empty input, that suggests something was executed
      const test = createInvalidValuesTest("complete_tool", false, {
        content: [{ type: "text", text: "Operation completed" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("execution_detected");
      expect(analysis.shouldPenalize).toBe(true);
    });
  });

  describe("unknown classification", () => {
    it("should apply partial penalty for truly ambiguous responses", () => {
      // Response that doesn't match any known pattern
      const test = createInvalidValuesTest("mystery_tool", false, {
        content: [{ type: "text", text: "OK" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("unknown");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.penaltyAmount).toBe(25);
    });

    it("should apply partial penalty for empty responses", () => {
      const test = createInvalidValuesTest("empty_tool", false, {
        content: [{ type: "text", text: "" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("unknown");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.penaltyAmount).toBe(25);
    });

    it("should apply partial penalty for generic success messages", () => {
      // Generic messages without execution keywords
      const test = createInvalidValuesTest("generic_tool", false, {
        content: [{ type: "text", text: "Success" }],
      });

      const analysis = analyzeInvalidValuesResponse(test);

      expect(analysis.classification).toBe("unknown");
      expect(analysis.shouldPenalize).toBe(true);
      expect(analysis.penaltyAmount).toBe(25);
    });
  });

  describe("extractResponseTextSafe helper", () => {
    it("should handle string responses", () => {
      const result = extractResponseTextSafe("plain text");
      expect(result).toBe("plain text");
    });

    it("should handle MCP content array format", () => {
      const result = extractResponseTextSafe({
        content: [
          { type: "text", text: "Hello " },
          { type: "text", text: "World" },
        ],
      });
      expect(result).toBe("Hello  World");
    });

    it("should handle null/undefined responses", () => {
      expect(extractResponseTextSafe(null)).toBe("");
      expect(extractResponseTextSafe(undefined)).toBe("");
    });

    it("should JSON stringify plain objects", () => {
      const result = extractResponseTextSafe({
        status: "ok",
      });
      expect(result).toContain("status");
      expect(result).toContain("ok");
    });
  });

  describe("isDefensiveProgrammingResponse helper", () => {
    it("should match various defensive programming patterns", () => {
      const patterns = [
        "Deleted 0 keys",
        "deleted 0 records",
        "No results found",
        "no matches found",
        "0 items deleted",
        "0 items updated",
        "nothing to delete",
        "nothing to process",
        "empty result",
        "empty query",
        "no action taken",
        "query returned 0",
      ];

      for (const pattern of patterns) {
        expect(isDefensiveProgrammingResponse(pattern)).toBe(true);
      }
    });

    it("should not match execution patterns", () => {
      const executionPatterns = [
        "deleted 5 rows",
        "10 items deleted",
        "command executed",
        "query returned 15 results",
      ];

      for (const pattern of executionPatterns) {
        expect(isDefensiveProgrammingResponse(pattern)).toBe(false);
      }
    });
  });

  describe("calculateMetrics integration", () => {
    it("should not affect score for safe responses", () => {
      const tests: ErrorTestDetail[] = [
        // Non-invalid_values test (should be scored normally)
        {
          toolName: "tool1",
          testType: "missing_required",
          testInput: {},
          expectedError: "Missing required field",
          actualResponse: {
            isError: true,
            errorMessage: "Missing required parameter: query",
          },
          passed: true,
        },
        // invalid_values with safe reflection (should be skipped)
        createInvalidValuesTest("tool2", false, {
          content: [{ type: "text", text: 'Stored query: ""' }],
        }),
      ];

      const metrics = calculateMetrics(tests, 1);

      // Only missing_required should be scored (100 base + bonuses)
      // invalid_values should be skipped (safe reflection)
      expect(metrics.mcpComplianceScore).toBeGreaterThanOrEqual(100);
    });

    it("should penalize execution_detected responses", () => {
      const tests: ErrorTestDetail[] = [
        // Non-invalid_values test
        {
          toolName: "tool1",
          testType: "missing_required",
          testInput: {},
          expectedError: "Missing required field",
          actualResponse: {
            isError: true,
            errorMessage: "Missing required parameter: query",
          },
          passed: true,
        },
        // invalid_values with execution detected (should be penalized)
        createInvalidValuesTest("tool2", false, {
          content: [{ type: "text", text: "deleted 5 rows" }],
        }),
      ];

      const metrics = calculateMetrics(tests, 1);

      // Both tests should be scored
      // missing_required: 100 points (passed)
      // invalid_values: 0 points (100% penalty, passed=false for non-error)
      // Total: 100 / 200 = 50%
      expect(metrics.mcpComplianceScore).toBeLessThan(100);
    });
  });
});
