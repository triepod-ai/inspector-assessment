/**
 * Error Handling Assessor Test Suite
 * Validates that error handling tests align with MCP protocol requirements
 */

import { ErrorHandlingAssessor } from "../assessment/modules/ErrorHandlingAssessor";
import { AssessmentContext } from "../assessment/AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("ErrorHandlingAssessor", () => {
  let assessor: ErrorHandlingAssessor;
  let mockContext: AssessmentContext;
  let mockCallTool: jest.Mock;
  let mockConfig: any;

  beforeEach(() => {
    mockConfig = {
      performanceProfiles: {
        default: {
          maxTestsPerAssessment: 20,
          testTimeout: 5000,
          maxConcurrentTests: 3,
        },
      },
    };
    assessor = new ErrorHandlingAssessor(mockConfig);
    mockCallTool = jest.fn();

    const mockTools: Tool[] = [
      {
        name: "testTool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            message: { type: "string" },
            count: { type: "number" },
            enabled: { type: "boolean" },
          },
          required: ["message"],
        },
      },
      {
        name: "enumTool",
        description: "Tool with enum validation",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create", "read", "update", "delete"],
            },
            format: {
              type: "string",
              format: "email",
            },
          },
          required: ["action"],
        },
      },
    ];

    mockContext = {
      serverName: "test-server",
      tools: mockTools,
      callTool: mockCallTool,
      config: mockConfig,
    } as AssessmentContext;
  });

  describe("MCP Protocol Compliance", () => {
    it("should test for missing required parameters", async () => {
      // Mock tool response for missing params
      mockCallTool.mockResolvedValueOnce({
        error: {
          code: -32602,
          message: "Invalid params: missing required field 'message'",
        },
      });

      const result = await assessor.assess(mockContext);

      expect(mockCallTool).toHaveBeenCalledWith("testTool", {});
      expect(result.metrics.validatesInputs).toBe(true);
    });

    it("should test for wrong parameter types", async () => {
      // Mock responses for wrong type tests
      mockCallTool
        .mockResolvedValueOnce({
          // Missing params test
          error: { code: -32602, message: "Invalid params" },
        })
        .mockResolvedValueOnce({
          // Wrong type test
          error: {
            code: -32602,
            message:
              "Invalid params: expected string for 'message', got number",
          },
        })
        .mockResolvedValueOnce({
          // Invalid values test
          error: { code: -32602, message: "Invalid value" },
        })
        .mockResolvedValueOnce({
          // Excessive input test
          content: "Handled large input",
        });

      const result = await assessor.assess(mockContext);

      // Verify wrong type test was called with incorrect types
      const wrongTypeCall = mockCallTool.mock.calls.find(
        (call) => call[0] === "testTool" && typeof call[1].message === "number",
      );
      expect(wrongTypeCall).toBeDefined();
      expect(result.metrics.hasProperErrorCodes).toBe(true);
    });

    it("should test for invalid enum values", async () => {
      // Mock responses for enum validation
      mockCallTool
        .mockResolvedValueOnce({
          // Missing params
          error: { code: -32602, message: "Missing required field 'action'" },
        })
        .mockResolvedValueOnce({
          // Wrong type
          error: { code: -32602, message: "Invalid type" },
        })
        .mockResolvedValueOnce({
          // Invalid enum value
          error: {
            code: -32602,
            message:
              "Invalid params: 'not_in_enum' is not a valid value for 'action'",
          },
        })
        .mockResolvedValueOnce({
          // Excessive input
          content: "Handled",
        });

      const result = await assessor.assess(mockContext);

      // Verify enum validation test
      const enumCall = mockCallTool.mock.calls.find(
        (call) => call[0] === "enumTool" && call[1].action === "not_in_enum",
      );
      expect(enumCall).toBeDefined();
    });

    it("should test for excessive input handling", async () => {
      const largeInput = "x".repeat(100000);

      // Mock graceful handling of large input
      mockCallTool
        .mockResolvedValueOnce({
          error: { code: -32602, message: "Missing params" },
        })
        .mockResolvedValueOnce({
          error: { code: -32602, message: "Wrong type" },
        })
        .mockResolvedValueOnce({
          error: { code: -32602, message: "Invalid value" },
        })
        .mockResolvedValueOnce({
          error: {
            code: -32603,
            message: "Input size exceeds maximum allowed",
          },
        });

      const result = await assessor.assess(mockContext);

      // Verify large input test was called
      const largeInputCall = mockCallTool.mock.calls.find(
        (call) =>
          call[1].message?.length > 50000 || call[1].value?.length > 50000,
      );
      expect(largeInputCall).toBeDefined();
    });

    it("should detect tool-specific error patterns with isError flag", async () => {
      // Mock tool-specific error response pattern
      mockCallTool.mockResolvedValueOnce({
        content: [{ type: "text", text: "Parameter validation failed" }],
        isError: true,
      });

      const result = await assessor.assess(mockContext);

      expect(result.metrics.testDetails[0].actualResponse.isError).toBe(true);
      expect(result.metrics.testDetails[0].passed).toBe(true);
    });

    it("should calculate validation coverage metrics", async () => {
      // Mock mixed results
      mockCallTool
        .mockResolvedValueOnce({
          // Missing params - PASS
          error: { code: -32602, message: "Missing required field" },
        })
        .mockResolvedValueOnce({
          // Wrong type - FAIL
          content: "Accepted wrong type",
        })
        .mockResolvedValueOnce({
          // Invalid value - PASS
          error: { code: -32602, message: "Invalid value" },
        })
        .mockResolvedValueOnce({
          // Excessive input - PASS
          error: { code: -32603, message: "Too large" },
        });

      const result = await assessor.assess(mockContext);

      // Should have 75% pass rate (3/4 tests)
      expect(result.metrics.mcpComplianceScore).toBe(75);
      expect(result.metrics.errorResponseQuality).toBe("good");
    });

    it("should generate appropriate recommendations based on failures", async () => {
      // Mock all failures
      mockCallTool.mockResolvedValue({
        content: "No validation performed",
      });

      const result = await assessor.assess(mockContext);

      expect(result.recommendations).toContain(
        "Implement consistent error codes for different error types",
      );
      expect(result.recommendations).toContain(
        "Implement proper input validation for all parameters",
      );
      expect(result.recommendations).toContain(
        "Validate and report missing required parameters",
      );
    });

    it("should handle timeout scenarios gracefully", async () => {
      // Mock timeout by never resolving
      mockCallTool.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 10000)),
      );

      const result = await assessor.assess(mockContext);

      // Should handle timeout and mark as error
      expect(
        result.metrics.testDetails[0].actualResponse.errorMessage,
      ).toContain("timeout");
    });

    it("should properly categorize error response quality", async () => {
      // Test excellent quality (≥90% pass rate)
      mockCallTool.mockResolvedValue({
        error: {
          code: -32602,
          message: "Detailed validation error with helpful context",
        },
      });

      let result = await assessor.assess(mockContext);
      expect(result.metrics.errorResponseQuality).toBe("excellent");

      // Test poor quality (<50% pass rate)
      mockCallTool.mockResolvedValue({
        content: "Success despite invalid input",
      });

      assessor = new ErrorHandlingAssessor(mockConfig);
      result = await assessor.assess(mockContext);
      expect(result.metrics.errorResponseQuality).toBe("poor");
    });
  });

  describe("Error Detection Methods", () => {
    it("should detect standard JSON-RPC error format", () => {
      const response = {
        error: {
          code: -32602,
          message: "Invalid params",
        },
      };

      const assessorAny = assessor as any;
      expect(assessorAny.isErrorResponse(response)).toBe(true);

      const errorInfo = assessorAny.extractErrorInfo(response);
      expect(errorInfo.code).toBe(-32602);
      expect(errorInfo.message).toBe("Invalid params");
    });

    it("should detect tool-specific isError flag", () => {
      const response = {
        content: "Error occurred",
        isError: true,
      };

      const assessorAny = assessor as any;
      expect(assessorAny.isErrorResponse(response)).toBe(true);
    });

    it("should detect error keywords in content", () => {
      const response = {
        content: "Error: Invalid input provided",
      };

      const assessorAny = assessor as any;
      expect(assessorAny.isErrorResponse(response)).toBe(true);
    });
  });

  describe("Test Input Generation", () => {
    it("should generate appropriate wrong type parameters", () => {
      const schema = {
        properties: {
          text: { type: "string" },
          count: { type: "number" },
          flag: { type: "boolean" },
          list: { type: "array" },
          obj: { type: "object" },
        },
      };

      const assessorAny = assessor as any;
      const wrongTypes = assessorAny.generateWrongTypeParams(schema);

      expect(typeof wrongTypes.text).toBe("number");
      expect(typeof wrongTypes.count).toBe("string");
      expect(typeof wrongTypes.flag).toBe("string");
      expect(typeof wrongTypes.list).toBe("string");
      expect(typeof wrongTypes.obj).toBe("string");
    });

    it("should generate invalid values for constrained fields", () => {
      const schema = {
        properties: {
          choice: { type: "string", enum: ["a", "b", "c"] },
          email: { type: "string", format: "email" },
          url: { type: "string", format: "uri" },
          limited: { type: "number", minimum: 0, maximum: 100 },
        },
      };

      const assessorAny = assessor as any;
      const invalidValues = assessorAny.generateInvalidValueParams(schema);

      expect(invalidValues.choice).toBe("not_in_enum");
      expect(invalidValues.email).toBe("invalid-email");
      expect(invalidValues.url).toBe("not://a/valid/uri");
      expect(invalidValues.limited).toBeLessThan(0);
    });
  });
});
