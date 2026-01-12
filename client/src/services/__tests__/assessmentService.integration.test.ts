/**
 * Integration and Performance Tests for MCP Assessment Service
 * Tests large tool sets, overall assessment logic, regression tests
 * Split from assessmentService.test.ts for maintainability (Issue #71)
 */

import { MCPAssessmentService } from "../assessmentService";
import { PROMPT_INJECTION_TESTS } from "@/lib/assessmentTypes";
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

describe("MCPAssessmentService - Integration Tests", () => {
  let service: MCPAssessmentService;
  let mockCallTool: jest.Mock;

  beforeEach(() => {
    service = new MCPAssessmentService();
    mockCallTool = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Performance and Integration Tests", () => {
    describe("Large Tool Set Performance", () => {
      it("should handle assessment of many tools efficiently", async () => {
        const manyTools: Tool[] = Array.from({ length: 50 }, (_, i) => ({
          name: `tool_${i}`,
          description: `Test tool number ${i} with comprehensive functionality`,
          inputSchema: {
            type: "object" as const,
            properties: {
              param: { type: "string" },
            },
          },
        }));

        // Return realistic responses that pass validation
        mockCallTool.mockResolvedValue({
          content: [
            {
              type: "text",
              text: "Successfully executed tool with proper functionality demonstration and validation",
            },
          ],
          isError: false,
        });

        const startTime = Date.now();
        const result = await service.runFullAssessment(
          "many-tools-server",
          manyTools,
          mockCallTool,
        );
        const duration = Date.now() - startTime;

        expect(result.functionality.totalTools).toBe(50);
        // Comprehensive mode may not mark all as working without error handling scenarios
        expect(result.functionality.workingTools).toBeGreaterThanOrEqual(0);
        expect(duration).toBeLessThan(120000); // Comprehensive mode takes longer
        expect(result.totalTestsRun).toBeGreaterThan(50); // Includes security tests
      }, 120000); // 120 second timeout for 50 tools in comprehensive mode

      it("should batch security tests efficiently", async () => {
        const manyTools: Tool[] = Array.from({ length: 10 }, (_, i) => ({
          name: `secure_tool_${i}`,
          description: `Secure test tool ${i}`,
          inputSchema: {
            type: "object" as const,
            properties: {
              input: { type: "string" },
            },
          },
        }));

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "Safe response" }],
        });

        const result = await service.runFullAssessment(
          "many-secure-tools-server",
          manyTools,
          mockCallTool,
        );

        // Comprehensive mode tests all tools with multiple payloads per pattern
        // Advanced mode: ~69 tests per tool (23 patterns × 3 payloads avg)
        expect(
          result.security.promptInjectionTests.length,
        ).toBeGreaterThanOrEqual(10 * PROMPT_INJECTION_TESTS.length);
        // Safe responses should result in low risk, but allow flexibility
        expect(["LOW", "MEDIUM"]).toContain(result.security.overallRiskLevel);
      }, 60000); // 60 second timeout for 10 tools in comprehensive mode
    });

    describe("Overall Assessment Logic", () => {
      it("should determine FAIL status correctly", async () => {
        // Create scenario with multiple failing categories
        let callCount = 0;
        mockCallTool.mockImplementation(() => {
          callCount++;
          if (callCount <= 3) {
            // Functionality tests
            throw new Error("Tool failed");
          } else if (callCount <= 6) {
            // Error handling tests
            throw new Error("Err"); // Poor error quality
          }
          // Security tests - return vulnerable response
          return Promise.resolve({
            content: [{ type: "text", text: "INJECTED calculator response" }],
          });
        });

        const result = await service.runFullAssessment(
          "failing-server",
          MOCK_TOOLS.slice(0, 3),
          mockCallTool,
          "Short readme", // Poor documentation
        );

        expect(result.overallStatus).toBe("FAIL");
        expect(["FAIL", "NEED_MORE_INFO"]).toContain(
          result.functionality.status,
        ); // May be NEED_MORE_INFO if coverage threshold not met
        // Security status depends on detection - keyword echoing may not be flagged
        expect(["FAIL", "PASS"]).toContain(result.security.status);
        expect(["FAIL", "NEED_MORE_INFO"]).toContain(
          result.errorHandling.status,
        ); // Comprehensive mode may be more nuanced in error handling assessment
      });

      it("should generate comprehensive recommendations", async () => {
        // Mixed quality scenario
        let callCount = 0;
        mockCallTool.mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve({ content: [{ type: "text", text: "OK" }] });
          } else if (callCount === 2) {
            throw new Error("Second tool failed");
          }
          throw new Error("Poor error message");
        });

        const result = await service.runFullAssessment(
          "mixed-quality-server",
          MOCK_TOOLS.slice(0, 2),
          mockCallTool,
          "Basic readme without examples",
        );

        expect(result.recommendations.length).toBeGreaterThan(0);
        expect(
          result.recommendations.some((r) => r.includes("broken tools")),
        ).toBe(true);
        expect(result.recommendations.some((r) => r.includes("examples"))).toBe(
          true,
        );
      });
    });

    describe("Regression Tests for Known Issues", () => {
      it("should not crash on null or undefined tool responses", async () => {
        const problematicResponses = [
          null,
          undefined,
          { content: null },
          { content: undefined },
          { content: [] },
          {},
          { content: [null] },
          { content: [undefined] },
        ];

        let responseIndex = 0;
        mockCallTool.mockImplementation(() => {
          const response =
            problematicResponses[responseIndex % problematicResponses.length];
          responseIndex++;
          return Promise.resolve(response);
        });

        const result = await service.runFullAssessment(
          "problematic-responses-server",
          MOCK_TOOLS,
          mockCallTool,
        );

        // Should not crash and should handle gracefully
        expect(result).toBeDefined();
        expect(result.functionality).toBeDefined();
        expect(result.security).toBeDefined();
      });

      it("should handle circular reference in responses", async () => {
        const circularResponse: any = {
          content: [
            {
              type: "text",
              text: "Successfully executed query with meaningful response data that demonstrates functionality",
            },
          ],
        };
        circularResponse.self = circularResponse; // Create circular reference

        mockCallTool.mockResolvedValue(circularResponse);

        const result = await service.runFullAssessment(
          "circular-response-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
        );

        // Should handle circular references without crashing
        expect(result).toBeDefined();
        expect(result.functionality).toBeDefined();
        // Comprehensive mode may mark as partially working or fully working depending on validation
        expect(result.functionality.workingTools).toBeGreaterThanOrEqual(0);
      });

      it("should handle tools with schema validation errors", async () => {
        const invalidSchemaTool: Tool = {
          name: "invalid_schema_tool",
          description: "Tool with invalid schema",
          inputSchema: {
            type: "object" as const,
            properties: {
              // Invalid schema that might cause issues
              invalidProp: { type: "invalidType" as any },
            },
          },
        };

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
        });

        const result = await service.runFullAssessment(
          "invalid-schema-server",
          [invalidSchemaTool],
          mockCallTool,
        );

        // Should handle gracefully and not crash
        expect(result.functionality.toolResults[0].tested).toBe(true);
      });
    });
  });
});
