/**
 * ErrorHandlingAssessor Test Suite
 * Tests error handling assessment and errorTests array exposure
 */

import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor";
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
  maxToolsToTestForErrors: -1, // Test all tools
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
});
