/**
 * Error Handling Assessor Test Suite
 * Validates that error handling tests align with MCP protocol requirements
 */

import { ErrorHandlingAssessor } from "../assessment/modules/ErrorHandlingAssessor";
import { AssessmentContext } from "../assessment/AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";

describe("ErrorHandlingAssessor", () => {
  let assessor: ErrorHandlingAssessor;
  let mockContext: AssessmentContext;
  let mockCallTool: jest.Mock;
  let mockConfig: AssessmentConfiguration;

  beforeEach(() => {
    mockConfig = {
      testTimeout: 5000,
      skipBrokenTools: false,
      maxToolsToTestForErrors: 20,
      maxParallelTests: 3,
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

      // Score is calculated with weighted scoring, not simple pass/fail
      expect(result.metrics.mcpComplianceScore).toBeGreaterThan(50);
      expect(result.metrics.mcpComplianceScore).toBeLessThan(75);
      expect(result.metrics.errorResponseQuality).toBe("fair");
    });

    it("should generate appropriate recommendations based on failures", async () => {
      // Mock all failures (no validation - tools accept invalid input)
      mockCallTool.mockResolvedValue({
        content: "No validation performed",
      });

      const result = await assessor.assess(mockContext);

      // When tools don't return errors at all, the issue is validation, not error codes
      expect(result.recommendations).toContain(
        "Implement proper input validation for all parameters",
      );
      expect(result.recommendations).toContain(
        "Validate and report missing required parameters",
      );

      // Note: "Implement consistent error codes" is NOT expected here because
      // the tools aren't returning errors at all - they're accepting invalid input
      // This recommendation only appears when tools DO return errors but WITHOUT codes
    });

    it("should handle timeout scenarios gracefully", async () => {
      // Mock timeout by delaying response beyond test timeout
      mockCallTool.mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(
              () =>
                resolve({
                  error: { code: -32603, message: "Request timeout" },
                }),
              200,
            ),
          ),
      );

      const result = await assessor.assess(mockContext);

      // Should complete assessment even with slow responses
      expect(result.metrics.testDetails).toBeDefined();
      expect(result.metrics.mcpComplianceScore).toBeDefined();
    });

    it("should properly categorize error response quality", async () => {
      // Test fair quality error messages (proper errors with codes)
      mockCallTool.mockResolvedValue({
        error: {
          code: -32602,
          message: "Detailed validation error with helpful context",
        },
      });

      let result = await assessor.assess(mockContext);
      expect(result.metrics.errorResponseQuality).toBe("fair");

      // Test poor quality (<50% pass rate)
      mockCallTool.mockResolvedValue({
        content: "Success despite invalid input",
      });

      assessor = new ErrorHandlingAssessor(mockConfig);
      result = await assessor.assess(mockContext);
      expect(result.metrics.errorResponseQuality).toBe("poor");
    });
  });

  describe("Error Code Recommendation Logic", () => {
    it("should NOT recommend error codes when no errors were triggered", async () => {
      // Setup: All tests pass without errors (tool accepts invalid input)
      mockCallTool.mockResolvedValue({
        content: [{ type: "text", text: "Success despite invalid input" }],
      });

      const result = await assessor.assess(mockContext);

      // Should NOT recommend error codes if no errors occurred
      // The issue is validation (tool accepted invalid input), not error codes
      expect(result.recommendations).not.toContain(
        "Implement consistent error codes for different error types",
      );
    });

    it("should recommend error codes when <50% of errors have codes", async () => {
      // Create multiple mock tools to generate multiple test results
      const multipleTools: Tool[] = Array(10)
        .fill(null)
        .map((_, i) => ({
          name: `testTool${i}`,
          description: "Test tool",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        }));

      const multiToolContext: AssessmentContext = {
        serverName: "test-server-multi",
        tools: multipleTools,
        callTool: mockCallTool,
        config: mockConfig,
      } as AssessmentContext;

      // Mock 4 responses with error codes (40%)
      // Mock 6 responses without error codes (60%)
      let callCount = 0;
      mockCallTool.mockImplementation(() => {
        callCount++;
        if (callCount <= 4) {
          // First 4 calls: errors WITH codes
          return Promise.resolve({
            error: { code: -32602, message: "Invalid params" },
          });
        } else {
          // Next 6 calls: errors WITHOUT codes
          return Promise.resolve({
            isError: true,
            content: [{ type: "text", text: "Error: Invalid input" }],
          });
        }
      });

      const result = await assessor.assess(multiToolContext);

      // Should recommend error codes when <50% have codes
      expect(result.recommendations).toContain(
        "Implement consistent error codes for different error types",
      );
    });

    // Note: Testing the ≥50% threshold with mocks is complex due to the assessor
    // running 4 test types per tool. The above two tests cover the critical scenarios:
    // 1. No errors triggered (validation issue, not error code issue)
    // 2. Errors exist but lack codes (error code issue)
    // These tests prevent the original bug from recurring.
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
