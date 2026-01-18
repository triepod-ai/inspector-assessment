/**
 * ErrorHandlingAssessor Test Suite
 * Tests error handling assessment and errorTests array exposure
 */

// @deprecated - using deprecated module for backward compatibility testing
import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor.deprecated";
import {
  AssessmentConfiguration,
  ErrorTestDetail,
} from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentContext } from "../AssessmentOrchestrator";

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: true,
    usability: false,
  },
  ...overrides,
});

// Mock tool factory
const createTool = (
  name: string,
  schema: Record<string, unknown> = {},
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
      count: { type: "number" },
    },
    required: ["query"],
    ...schema,
  },
});

// Mock context factory
const createMockContext = (
  tools: Tool[],
  callToolFn: (name: string, args: unknown) => Promise<unknown>,
): AssessmentContext =>
  ({
    tools,
    callTool: callToolFn,
  }) as unknown as AssessmentContext;

describe("ErrorHandlingAssessor", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("errorTests array exposure", () => {
    it("should include errorTests array at top level of assessment result", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [
          { type: "text", text: "Error: Missing required parameter 'query'" },
        ],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Verify errorTests is present at top level
      expect(result).toHaveProperty("errorTests");
      expect(Array.isArray(result.errorTests)).toBe(true);
    });

    it("should have errorTests match metrics.testDetails", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error: validation failed" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Both should contain same data
      expect(result.errorTests).toEqual(result.metrics.testDetails);
    });

    it("should include all test types in errorTests array", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error occurred" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      const testTypes = result.errorTests?.map((t) => t.testType) ?? [];

      // Verify all 4 test types are present
      expect(testTypes).toContain("missing_required");
      expect(testTypes).toContain("wrong_type");
      expect(testTypes).toContain("excessive_input");
      expect(testTypes).toContain("invalid_values");
    });

    it("should include proper ErrorTestDetail structure", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [
          { type: "text", text: "Required parameter 'query' is missing" },
        ],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Verify each test has required fields
      result.errorTests?.forEach((test: ErrorTestDetail) => {
        expect(test).toHaveProperty("toolName");
        expect(test).toHaveProperty("testType");
        expect(test).toHaveProperty("testInput");
        expect(test).toHaveProperty("expectedError");
        expect(test).toHaveProperty("actualResponse");
        expect(test).toHaveProperty("passed");

        // Verify actualResponse structure
        expect(test.actualResponse).toHaveProperty("isError");
        expect(test.actualResponse).toHaveProperty("rawResponse");
      });
    });
  });

  describe("error test execution", () => {
    it("should detect missing required parameters", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Missing required parameter: query" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      const missingRequiredTest = result.errorTests?.find(
        (t) => t.testType === "missing_required",
      );

      expect(missingRequiredTest).toBeDefined();
      expect(missingRequiredTest?.passed).toBe(true);
    });

    it("should detect type validation errors", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Type error: expected string" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      const wrongTypeTest = result.errorTests?.find(
        (t) => t.testType === "wrong_type",
      );

      expect(wrongTypeTest).toBeDefined();
      expect(wrongTypeTest?.passed).toBe(true);
    });

    it("should handle tools with no required parameters gracefully", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool: Tool = {
        name: "optional_params_tool",
        description: "Tool with no required params",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
          // No 'required' array
        },
      };

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      const missingRequiredTest = result.errorTests?.find(
        (t) => t.testType === "missing_required",
      );

      // Should pass because tool correctly accepts empty input
      expect(missingRequiredTest?.passed).toBe(true);
      expect(missingRequiredTest?.reason).toContain("No required parameters");
    });
  });

  describe("configuration options", () => {
    it("should respect selectedToolsForTesting configuration", async () => {
      const assessor = new ErrorHandlingAssessor(
        createConfig({
          selectedToolsForTesting: ["tool_a"],
        }),
      );

      const toolA = createTool("tool_a");
      const toolB = createTool("tool_b");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext([toolA, toolB], mockCallTool);
      const result = await assessor.assess(context);

      // Only tool_a should be tested
      const testedTools = [
        ...new Set(result.errorTests?.map((t) => t.toolName)),
      ];
      expect(testedTools).toContain("tool_a");
      expect(testedTools).not.toContain("tool_b");
    });

    it("should return empty errorTests when selectedToolsForTesting is empty array", async () => {
      const assessor = new ErrorHandlingAssessor(
        createConfig({
          selectedToolsForTesting: [],
        }),
      );

      const tool = createTool("test_tool");

      const mockCallTool = jest.fn();

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.errorTests).toEqual([]);
      expect(mockCallTool).not.toHaveBeenCalled();
    });
  });

  describe("multiple tools", () => {
    it("should include tests for all tools in errorTests array", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());

      const tools = [
        createTool("tool_1"),
        createTool("tool_2"),
        createTool("tool_3"),
      ];

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // Each tool should have 4 test types
      const testedTools = [
        ...new Set(result.errorTests?.map((t) => t.toolName)),
      ];
      expect(testedTools).toHaveLength(3);
      expect(result.errorTests).toHaveLength(12); // 3 tools * 4 test types
    });
  });

  describe("backward compatibility (deprecated maxToolsToTestForErrors)", () => {
    it("should test all tools when neither selectedToolsForTesting nor maxToolsToTestForErrors is set", async () => {
      // Config with neither field set - should test all tools
      const assessor = new ErrorHandlingAssessor(createConfig());

      const tools = [
        createTool("tool_1"),
        createTool("tool_2"),
        createTool("tool_3"),
      ];

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // All 3 tools should be tested
      const testedTools = [
        ...new Set(result.errorTests?.map((t) => t.toolName)),
      ];
      expect(testedTools).toHaveLength(3);
    });

    it("should respect deprecated maxToolsToTestForErrors when selectedToolsForTesting is not set", async () => {
      // Legacy config using deprecated field - should still work
      const assessor = new ErrorHandlingAssessor(
        createConfig({
          maxToolsToTestForErrors: 2,
          selectedToolsForTesting: undefined,
        }),
      );

      const tools = [
        createTool("tool_1"),
        createTool("tool_2"),
        createTool("tool_3"),
        createTool("tool_4"),
      ];

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // Only first 2 tools should be tested (per deprecated config)
      const testedTools = [
        ...new Set(result.errorTests?.map((t) => t.toolName)),
      ];
      expect(testedTools).toHaveLength(2);
      expect(testedTools).toContain("tool_1");
      expect(testedTools).toContain("tool_2");
    });

    it("should prefer selectedToolsForTesting over maxToolsToTestForErrors", async () => {
      // Config with BOTH fields - new field should take precedence
      const assessor = new ErrorHandlingAssessor(
        createConfig({
          maxToolsToTestForErrors: 2, // Would select first 2
          selectedToolsForTesting: ["tool_3"], // Should override to just tool_3
        }),
      );

      const tools = [
        createTool("tool_1"),
        createTool("tool_2"),
        createTool("tool_3"),
        createTool("tool_4"),
      ];

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // Only tool_3 should be tested (selectedToolsForTesting takes precedence)
      const testedTools = [
        ...new Set(result.errorTests?.map((t) => t.toolName)),
      ];
      expect(testedTools).toHaveLength(1);
      expect(testedTools).toContain("tool_3");
    });

    it("should test no tools when selectedToolsForTesting is empty array", async () => {
      // Empty array means "test none"
      const assessor = new ErrorHandlingAssessor(
        createConfig({
          selectedToolsForTesting: [],
        }),
      );

      const tools = [createTool("tool_1"), createTool("tool_2")];

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // No tools should be tested
      expect(result.errorTests).toHaveLength(0);
      expect(mockCallTool).not.toHaveBeenCalled();
    });
  });

  describe("Issue #28: ErrorHandlingAssessor score field", () => {
    it("should populate top-level score field (Issue #28)", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error: validation failed" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Test that result.score exists and equals Math.round(result.metrics.mcpComplianceScore)
      expect(result).toHaveProperty("score");
      expect(typeof result.score).toBe("number");
      expect(result.score).toBe(Math.round(result.metrics.mcpComplianceScore));
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });

  describe("Issue #153: Connection error detection", () => {
    it("should detect connection errors and mark tests as failed", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      // Simulate ECONNREFUSED connection error
      const mockCallTool = jest
        .fn()
        .mockRejectedValue(
          new Error("ECONNREFUSED - connect ECONNREFUSED 127.0.0.1:9999"),
        );

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // All tests should be marked as connection errors
      expect(result.testExecutionMetadata).toBeDefined();
      expect(
        result.testExecutionMetadata?.connectionErrorCount,
      ).toBeGreaterThan(0);

      // Tests with connection errors should be marked as NOT passed
      const connectionErrorTests = result.errorTests.filter(
        (t) => t.isConnectionError === true,
      );
      expect(connectionErrorTests.length).toBeGreaterThan(0);
      connectionErrorTests.forEach((test) => {
        expect(test.passed).toBe(false);
        expect(test.reason).toContain("Connection error");
      });
    });

    it("should detect ETIMEDOUT as connection error", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      // Simulate ETIMEDOUT connection error
      const mockCallTool = jest
        .fn()
        .mockRejectedValue(
          new Error("ETIMEDOUT - connect ETIMEDOUT 127.0.0.1:9999"),
        );

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // All tests should be connection errors
      expect(result.testExecutionMetadata?.connectionErrorCount).toBe(4); // 4 test types per tool

      // Valid tests completed should be 0
      expect(result.testExecutionMetadata?.validTestsCompleted).toBe(0);
    });

    it("should NOT mark non-connection errors as connection errors", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tool = createTool("test_tool");

      // Simulate a normal validation error (not a connection error)
      const mockCallTool = jest
        .fn()
        .mockRejectedValue(new Error("Parameter 'query' is required"));

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Should NOT be marked as connection errors
      expect(result.testExecutionMetadata?.connectionErrorCount).toBe(0);
      expect(result.testExecutionMetadata?.validTestsCompleted).toBe(4);

      // Tests should pass because they got meaningful errors
      const passedTests = result.errorTests.filter((t) => t.passed);
      expect(passedTests.length).toBeGreaterThan(0);
    });

    it("should calculate testCoveragePercent correctly with mixed results", async () => {
      const assessor = new ErrorHandlingAssessor(createConfig());
      const tools = [createTool("tool_1"), createTool("tool_2")];

      let callCount = 0;
      const mockCallTool = jest.fn().mockImplementation(() => {
        callCount++;
        // First tool (4 calls) succeeds, second tool (4 calls) gets connection errors
        if (callCount <= 4) {
          return Promise.resolve({
            isError: true,
            content: [{ type: "text", text: "Error: validation failed" }],
          });
        }
        return Promise.reject(
          new Error("ECONNREFUSED - connect ECONNREFUSED 127.0.0.1:9999"),
        );
      });

      const context = createMockContext(tools, mockCallTool);
      const result = await assessor.assess(context);

      // 8 total tests (2 tools * 4 test types)
      // 4 valid, 4 connection errors
      expect(result.testExecutionMetadata?.totalTestsAttempted).toBe(8);
      expect(result.testExecutionMetadata?.validTestsCompleted).toBe(4);
      expect(result.testExecutionMetadata?.connectionErrorCount).toBe(4);
      expect(result.testExecutionMetadata?.testCoveragePercent).toBe(50);
    });
  });
});
