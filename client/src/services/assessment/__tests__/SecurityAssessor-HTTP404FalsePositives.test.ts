/**
 * Security Assessor - HTTP 404 False Positives Fix (Issue #26)
 *
 * Tests that HTTP error responses (404, 400, 500, etc.) are NOT flagged
 * as Calculator Injection vulnerabilities.
 *
 * Root cause: "404: Not Found" contains the digit "4", which was incorrectly
 * matched as the computed result of "2+2". This caused 100% false positive
 * rate when tools returned HTTP errors for invalid inputs.
 *
 * Key principle:
 * - HTTP error responses indicate tool rejection, not computation
 * - Only flag as vulnerable if response contains COMPUTED result without HTTP error context
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("SecurityAssessor - HTTP 404 False Positives Fix (Issue #26)", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  // Extend Jest timeout for all tests in this suite - SecurityAssessor runs many tests per tool
  jest.setTimeout(30000);

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true,
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("HTTP Error Responses (Should NOT be flagged)", () => {
    it("should NOT flag HTTP 404 Not Found as Calculator Injection", async () => {
      const tool: Tool = {
        name: "kintone_get_app",
        description: "Get Kintone app information",
        inputSchema: {
          type: "object",
          properties: {
            app_id: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Tool returns HTTP 404 error (from the issue report)
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "404: Not Found",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Calculator Injection tests should NOT be flagged as vulnerable
      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "kintone_get_app" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag HTTP 400 Bad Request as Calculator Injection", async () => {
      const tool: Tool = {
        name: "api_tool",
        description: "API endpoint tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "400 Bad Request: Invalid input format",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "api_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag HTTP 500 Internal Server Error as Calculator Injection", async () => {
      const tool: Tool = {
        name: "database_tool",
        description: "Database query tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "500 Internal Server Error",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "database_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag 'Not Found' error messages as Calculator Injection", async () => {
      const tool: Tool = {
        name: "resource_tool",
        description: "Resource lookup tool",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "Resource not found",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "resource_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag HTTP 502 Bad Gateway as Calculator Injection", async () => {
      // Note: We use 502 instead of 503 because "503 Service Unavailable" triggers
      // the transient error retry logic (TRANSIENT_ERROR_PATTERNS), which would
      // cause this test to timeout due to repeated retries across all attack patterns.
      const tool: Tool = {
        name: "external_api",
        description: "External API tool",
        inputSchema: {
          type: "object",
          properties: {
            request: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "502 Bad Gateway: Upstream server not responding",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "external_api" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });
  });

  describe("Actual Calculator Injection (SHOULD be flagged)", () => {
    it("should flag computed result without expression echo", async () => {
      const tool: Tool = {
        name: "vulnerable_calculator",
        description: "Calculator that evaluates expressions",
        inputSchema: {
          type: "object",
          properties: {
            expression: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Tool computes and returns ONLY the result (vulnerable behavior)
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "4", // Just the computed result, no original expression
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable for Calculator Injection
      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "vulnerable_calculator" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      // At least one Calculator Injection test should be flagged
      expect(calculatorTests.length).toBeGreaterThan(0);
    });

    it("should flag response with 'The answer is X' pattern", async () => {
      const tool: Tool = {
        name: "math_tool",
        description: "Math tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Tool returns computed result in natural language
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "The answer is 4",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable
      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "math_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBeGreaterThan(0);
    });
  });

  describe("Safe Reflection (Should NOT be flagged)", () => {
    it("should NOT flag tool that echoes expression without computing", async () => {
      const tool: Tool = {
        name: "safe_storage",
        description: "Stores expressions without evaluating",
        inputSchema: {
          type: "object",
          properties: {
            expression: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, params) => {
          // Tool echoes the expression (safe reflection)
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: `Stored expression: ${params.expression}`,
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable
      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "safe_storage" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });
  });

  describe("Edge Cases", () => {
    it("should handle JSON error responses with HTTP codes", async () => {
      const tool: Tool = {
        name: "json_api",
        description: "JSON API tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "Not Found",
                status: 404,
                message: "Resource does not exist",
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "json_api" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should handle mixed status responses with error context", async () => {
      const tool: Tool = {
        name: "verbose_api",
        description: "Verbose API tool",
        inputSchema: {
          type: "object",
          properties: {
            request: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "Error 404: The requested resource was not found on this server",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "verbose_api" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });
  });
});
