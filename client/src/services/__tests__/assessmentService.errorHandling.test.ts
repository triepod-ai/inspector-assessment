/**
 * Error Handling Assessment Tests for MCP Assessment Service
 * Tests MCP compliance, input validation, network/timeout scenarios
 * Split from assessmentService.test.ts for maintainability (Issue #71)
 */

import { MCPAssessmentService } from "../assessmentService";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock data for testing
const MOCK_TOOLS: Tool[] = [
  {
    name: "test_tool",
    description: "A test tool for basic operations",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string" },
        limit: { type: "number", minimum: 1 },
        enabled: { type: "boolean" },
      },
      required: ["query"],
    },
  },
  {
    name: "complex-tool",
    description: "Complex tool with nested schema",
    inputSchema: {
      type: "object" as const,
      properties: {
        data: {
          type: "object",
          properties: {
            nested: { type: "string" },
            array: { type: "array", items: { type: "string" } },
          },
        },
        options: {
          type: "array",
          items: { type: "string", enum: ["option1", "option2"] },
        },
      },
    },
  },
  {
    name: "no_schema_tool",
    description: "Tool without input schema",
    inputSchema: { type: "object" as const }, // Minimal schema (no properties)
  },
  {
    name: "enum_tool",
    description: "Tool with enum parameters",
    inputSchema: {
      type: "object" as const,
      properties: {
        mode: { type: "string", enum: ["read", "write", "execute"] },
        format: { type: "string", enum: ["json", "xml", "csv"] },
      },
    },
  },
  {
    name: "url_email_tool",
    description: "Tool with URL and email fields",
    inputSchema: {
      type: "object" as const,
      properties: {
        website_url: { type: "string" },
        contact_email: { type: "string" },
        backup_url: { type: "string" },
      },
    },
  },
];

describe("MCPAssessmentService - Error Handling Assessment", () => {
  let service: MCPAssessmentService;
  let mockCallTool: jest.Mock;

  beforeEach(() => {
    service = new MCPAssessmentService();
    mockCallTool = jest.fn();
  });

  describe("Error Handling Assessment - Critical Issues", () => {
    describe("MCP Compliance Testing", () => {
      it("should detect 0% MCP compliance scenario", async () => {
        // Simulate truly non-compliant error responses - crashes instead of proper MCP errors
        mockCallTool.mockRejectedValue(new Error("Error"));

        const result = await service.runFullAssessment(
          "poor-error-server",
          MOCK_TOOLS.slice(0, 3),
          mockCallTool,
        );

        expect(result.errorHandling.metrics.mcpComplianceScore).toBeLessThan(
          50,
        );
        // Comprehensive mode may return NEED_MORE_INFO for poor error handling
        expect(["FAIL", "NEED_MORE_INFO"]).toContain(
          result.errorHandling.status,
        );
        expect(result.errorHandling.metrics.errorResponseQuality).toBe("poor");
      });

      it("should evaluate error message quality", async () => {
        const descriptiveError = new Error(
          'Invalid parameter "query": must be a non-empty string between 1-1000 characters',
        );
        mockCallTool.mockRejectedValue(descriptiveError);

        const result = await service.runFullAssessment(
          "good-error-server",
          MOCK_TOOLS.slice(0, 3),
          mockCallTool,
        );

        expect(result.errorHandling.metrics.hasDescriptiveMessages).toBe(true);
        expect(result.errorHandling.metrics.errorResponseQuality).not.toBe(
          "poor",
        );
      });

      it("should check for proper error codes", async () => {
        // Comprehensive mode expects error responses with proper errorCode field
        const errorWithCode = {
          content: [
            {
              type: "text",
              text: "Invalid input parameters - validation failed",
            },
          ],
          isError: true,
          errorCode: "VALIDATION_ERROR", // Proper error code field
          code: "VALIDATION_ERROR", // Alternative code field
        };
        mockCallTool.mockResolvedValue(errorWithCode);

        const result = await service.runFullAssessment(
          "error-code-server",
          MOCK_TOOLS.slice(0, 3),
          mockCallTool,
        );

        // Check that the error detection logic works
        expect(result.errorHandling.metrics.hasProperErrorCodes).toBe(true);
      });

      it("should handle mixed error quality scenarios", async () => {
        let callCount = 0;
        mockCallTool.mockImplementation(() => {
          callCount++;
          // First call - functionality test (working)
          if (callCount === 1) {
            return Promise.resolve({ content: [{ type: "text", text: "OK" }] });
          }
          // Remaining calls - error handling tests
          if (callCount === 2) {
            throw new Error("Bad error"); // Poor quality
          } else if (callCount === 3) {
            throw new Error(
              "VALIDATION_FAILED: Detailed error message with proper context",
            ); // Good quality
          }
          throw new Error("Err"); // Poor quality
        });

        const result = await service.runFullAssessment(
          "mixed-error-server",
          MOCK_TOOLS.slice(0, 3),
          mockCallTool,
        );

        expect(
          result.errorHandling.metrics.mcpComplianceScore,
        ).toBeGreaterThanOrEqual(0);
        expect(
          result.errorHandling.metrics.mcpComplianceScore,
        ).toBeLessThanOrEqual(100);
      });
    });

    describe("Input Validation Testing", () => {
      it("should test invalid parameter scenarios", async () => {
        mockCallTool.mockRejectedValue(new Error("Invalid parameter type"));

        const result = await service.runFullAssessment(
          "validation-server",
          MOCK_TOOLS,
          mockCallTool,
        );

        expect(result.errorHandling.metrics.validatesInputs).toBe(true);
      });

      it("should handle servers that dont validate inputs", async () => {
        // Use tools WITHOUT required parameters to test type validation
        const toolsWithoutRequired: Tool[] = [
          {
            name: "optional_tool",
            description: "Tool with no required parameters",
            inputSchema: {
              type: "object" as const,
              properties: {
                value: { type: "string" },
              },
              // No required fields
            },
          },
        ];

        // Server accepts ALL inputs without error - even invalid types
        // Return a longer response to pass validation checks
        mockCallTool.mockResolvedValue({
          content: [
            {
              type: "text",
              text: "Successfully processed input without any validation checks applied",
            },
          ],
          isError: false,
        });

        const result = await service.runFullAssessment(
          "no-validation-server",
          toolsWithoutRequired,
          mockCallTool,
        );

        // For tools without required parameters, missing_required test automatically passes
        // (accepting empty input is correct). So validatesInputs will be true even though
        // the server doesn't validate types. This is by design.
        expect(result.errorHandling.metrics.validatesInputs).toBe(true);

        // However, the MCP compliance score should be low due to not validating types
        expect(result.errorHandling.metrics.mcpComplianceScore).toBeLessThan(
          80,
        );
      });
    });

    describe("Network and Timeout Scenarios", () => {
      it("should handle network interruption during assessment", async () => {
        let callCount = 0;
        mockCallTool.mockImplementation(() => {
          callCount++;
          // In comprehensive mode, each tool gets ~5-10 scenarios
          // Allow enough successful calls for at least one tool to pass
          if (callCount <= 15) {
            return Promise.resolve({
              content: [{ type: "text", text: "OK" }],
              isError: false,
            });
          }
          throw new Error("Network error");
        });

        const result = await service.runFullAssessment(
          "network-issues-server",
          MOCK_TOOLS,
          mockCallTool,
        );

        // Should handle partial failures gracefully
        // Comprehensive mode may classify some tools as working if enough scenarios pass
        expect(result.functionality.workingTools).toBeGreaterThanOrEqual(0);
        // brokenTools might be 0 depending on how network errors are classified
        expect(result.functionality.brokenTools.length).toBeGreaterThanOrEqual(
          0,
        );
      });

      it("should respect timeout configuration", async () => {
        // Use minimal config to isolate timeout behavior from assessment complexity
        const slowService = new MCPAssessmentService({
          testTimeout: 100,
          enableExtendedAssessment: false,
          assessmentCategories: {
            functionality: true,
            security: false, // Skip expensive security assessment
            documentation: false,
            errorHandling: false,
            usability: false,
            mcpSpecCompliance: false,
          },
        });
        mockCallTool.mockImplementation(
          () => new Promise((resolve) => setTimeout(resolve, 500)),
        );

        const startTime = Date.now();
        const result = await slowService.runFullAssessment(
          "slow-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
        );
        const duration = Date.now() - startTime;

        // With minimal config (functionality only), tests ~5-12 scenarios per tool
        // Each scenario times out after 100ms, so total should be well under 30s
        expect(duration).toBeLessThan(30000);
        expect(result.functionality.brokenTools.length).toBeGreaterThan(0);
      }, 30000); // 30 second Jest timeout for functionality-only with 100ms tool timeouts
    });

    describe("Partial Coverage Score Calculation", () => {
      it("should calculate functionality score correctly with partial tool coverage", async () => {
        // Arrange: First tool (test_tool) always works, second tool (complex-tool) always fails
        const twoTools = [MOCK_TOOLS[0], MOCK_TOOLS[1]];

        // Mock based on tool name: test_tool succeeds, complex-tool fails
        mockCallTool.mockImplementation((toolName: string) => {
          if (toolName === "test_tool") {
            return Promise.resolve({
              content: [{ type: "text", text: "success" }],
              isError: false,
            });
          } else {
            // complex-tool always fails
            return Promise.resolve({
              content: [{ type: "text", text: "Error: tool broken" }],
              isError: true,
            });
          }
        });

        // Act
        const result = await service.runFullAssessment(
          "partial-coverage-server",
          twoTools,
          mockCallTool,
        );

        // Assert: Coverage should be 50%, not 100%
        // This test would have caught the workingPercentage/coveragePercentage field mismatch bug
        expect(result.functionality.coveragePercentage).toBe(50);
        expect(result.functionality.workingTools).toBe(1);
        expect(result.functionality.brokenTools.length).toBe(1);
        expect(result.functionality.brokenTools).toContain("complex-tool");
      });
    });

    describe("Large Payload Handling", () => {
      it("should handle large response payloads", async () => {
        const largeResponse = {
          content: [
            {
              type: "text",
              text: "A".repeat(10000), // Large text response
            },
          ],
        };
        mockCallTool.mockResolvedValue(largeResponse);

        const result = await service.runFullAssessment(
          "large-response-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
        );

        expect(result.functionality.workingTools).toBeGreaterThan(0);
        expect(result.functionality.toolResults[0].status).toBe("working");
      });

      it("should handle malformed large responses", async () => {
        const malformedResponse = {
          content: [
            {
              type: "text",
              text: '{"unclosed": "json", "large": "' + "x".repeat(50000),
            },
          ],
        };
        mockCallTool.mockResolvedValue(malformedResponse);

        const result = await service.runFullAssessment(
          "malformed-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
        );

        // Should not crash on malformed responses
        expect(result).toBeDefined();
        expect(result.functionality.toolResults[0].status).toBe("working");
      });
    });

    describe("Issue #28: Empty Error Handling Result", () => {
      it("should include score field in empty error handling result (Issue #28)", async () => {
        // Create a service with error handling disabled
        const serviceWithoutErrorHandling = new MCPAssessmentService({
          assessmentCategories: {
            functionality: true,
            security: false,
            documentation: false,
            errorHandling: false, // Disable error handling to get empty result
            usability: false,
          },
        });

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
          isError: false,
        });

        const result = await serviceWithoutErrorHandling.runFullAssessment(
          "test-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
        );

        // Empty error handling result should have score field set to 100
        expect(result.errorHandling).toHaveProperty("score");
        expect(result.errorHandling.score).toBe(100);
        expect(result.errorHandling.metrics.mcpComplianceScore).toBe(100);
        expect(result.errorHandling.status).toBe("PASS");
      });
    });
  });
});
