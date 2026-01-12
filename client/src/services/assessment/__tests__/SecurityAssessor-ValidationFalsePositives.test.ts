/**
 * Security Assessor - Validation False Positives Fix
 * Tests that proper input validation is not flagged as vulnerability
 *
 * These tests verify that tools which PROPERLY REJECT invalid inputs
 * are correctly identified as SECURE, not vulnerable.
 *
 * Key principle:
 * - SECURE: Tool rejects malicious input BEFORE processing (validation error)
 * - VULNERABLE: Tool gets error WHILE/AFTER processing malicious input (execution error)
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  expectSecureStatus,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { SecurityAssessment } from "@/lib/assessment/resultTypes";

describe("SecurityAssessor - Validation False Positives Fix", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true, // Enable advanced security testing
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("MCP Error Code -32602 (JSON-RPC Invalid Params)", () => {
    it("should recognize MCP -32602 as secure validation rejection", async () => {
      const tool: Tool = {
        name: "test_tool",
        description: "Test tool with validation",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", format: "uri" },
          },
          required: ["url"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "MCP error -32602: Tool 'test_tool' parameter validation failed: url: Invalid url",
            },
          ],
          // Simulate error object with code
          error: { code: -32602 },
        }),
      );

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable
      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);

      // All tests should pass with validation rejection evidence
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable,
      );
      expect(vulnerableTests.length).toBe(0);

      // Check evidence messages
      const testResults = result.promptInjectionTests.filter(
        (t) => t.toolName === "test_tool",
      );
      testResults.forEach((test) => {
        if (test.evidence) {
          expect(
            test.evidence.includes("MCP validation error") ||
              test.evidence.includes("properly rejected") ||
              test.evidence.includes("no input parameters"),
          ).toBe(true);
        }
      });
    });
  });

  describe("Parameter Validation Failed Messages", () => {
    it("should recognize 'parameter validation failed' as secure", async () => {
      const tool: Tool = {
        name: "firecrawl_scrape",
        description: "Scrape content from a single URL",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", format: "uri" },
          },
          required: ["url"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Tool 'firecrawl_scrape' execution failed: parameter validation failed: url: Invalid url",
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      // Should be marked as PASS (all tools properly validated)
      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);
    });

    it("should recognize schema validation errors as secure", async () => {
      const tool: Tool = {
        name: "validated_tool",
        description: "Tool with schema validation",
        inputSchema: {
          type: "object",
          properties: {
            email: { type: "string", format: "email" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Schema validation failed: email must be a valid email address",
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);
    });

    it("should recognize URL validation errors as secure", async () => {
      const tool: Tool = {
        name: "url_tool",
        description: "Tool that validates URLs",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid url: URL must have a valid top-level domain or be a valid path",
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);
    });
  });

  describe("Firecrawl Real-World Test Cases", () => {
    it("should pass all 4 Firecrawl validation scenarios", async () => {
      const tool: Tool = {
        name: "firecrawl_scrape",
        description: "Scrape content from a URL",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", format: "uri" },
          },
          required: ["url"],
        },
      };

      mockContext.tools = [tool];

      // Mock responses for different test payloads
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, _params) => {
          // All invalid inputs get the same validation error
          return Promise.resolve({
            isError: true,
            content: [
              {
                type: "text",
                text: "MCP error -32602: Tool 'firecrawl_scrape' parameter validation failed: url: Invalid url",
              },
            ],
            error: { code: -32602 },
          });
        });

      const result = await assessor.assess(mockContext);

      // ALL tests should pass - no vulnerabilities
      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);

      // Verify no tests are flagged as vulnerable
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable,
      );
      expect(vulnerableTests.length).toBe(0);

      // Verify we have test results for the tool
      const toolTests = result.promptInjectionTests.filter(
        (t) => t.toolName === "firecrawl_scrape",
      );
      expect(toolTests.length).toBeGreaterThan(0);

      // Verify no tests are vulnerable (most important check)
      toolTests.forEach((test) => {
        expect(test.vulnerable).toBe(false);
      });

      // Spot check: at least one test should have validation error evidence
      const validationEvidenceTests = toolTests.filter(
        (t) =>
          t.evidence &&
          (t.evidence.includes("validation error") ||
            t.evidence.includes("properly rejected")),
      );
      expect(validationEvidenceTests.length).toBeGreaterThan(0);
    });
  });

  describe("Distinguishing Validation from Execution Errors", () => {
    it("should detect actual execution errors as VULNERABLE", async () => {
      const tool: Tool = {
        name: "vulnerable_sql_tool",
        description: "Tool with SQL injection vulnerability",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, _params) => {
          // This tool EXECUTES the SQL and then gets an error
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: "SQL executed: syntax error near 'DROP TABLE users'",
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable (execution occurred)
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "vulnerable_sql_tool",
      );
      expect(vulnerableTests.length).toBeGreaterThan(0);

      // Should have execution evidence
      vulnerableTests.forEach((test) => {
        expect(test.evidence?.toLowerCase()).toContain("executed");
      });
    });

    it("should detect system-level execution errors as VULNERABLE", async () => {
      const tool: Tool = {
        name: "vulnerable_code_tool",
        description: "Tool that executes code",
        inputSchema: {
          type: "object",
          properties: {
            code: { type: "string" },
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
              text: "Code executed: NullPointerException at line 42 in executed code",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable (system error during execution)
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) =>
          t.vulnerable &&
          t.toolName === "vulnerable_code_tool" &&
          t.evidence?.includes("executed"),
      );
      expect(vulnerableTests.length).toBeGreaterThan(0);
    });

    it("should NOT flag validation errors as vulnerable even with error keywords", async () => {
      const tools: Tool[] = [
        {
          name: "secure_validated_tool",
          description: "Tool with proper validation",
          inputSchema: {
            type: "object",
            properties: {
              value: { type: "string" },
            },
          },
        },
        {
          name: "broken_execution_tool",
          description: "Tool with execution vulnerability",
          inputSchema: {
            type: "object",
            properties: {
              command: { type: "string" },
            },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, _params) => {
          if (toolName === "secure_validated_tool") {
            // Validation error (SECURE)
            return Promise.resolve({
              isError: true,
              content: [
                {
                  type: "text",
                  text: "Parameter validation failed: invalid type - expected number",
                },
              ],
            });
          } else {
            // Execution error (VULNERABLE)
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: "Command executed: type error in result - invalid syntax",
                },
              ],
            });
          }
        });

      const result = await assessor.assess(mockContext);

      // Only broken_execution_tool should be vulnerable
      const validatedToolTests = result.promptInjectionTests.filter(
        (t) => t.toolName === "secure_validated_tool" && t.vulnerable,
      );
      const brokenToolTests = result.promptInjectionTests.filter(
        (t) => t.toolName === "broken_execution_tool" && t.vulnerable,
      );

      expect(validatedToolTests.length).toBe(0); // Should be SECURE
      expect(brokenToolTests.length).toBeGreaterThan(0); // Should be VULNERABLE
    });
  });

  describe("Boundary Validation Errors", () => {
    it("should recognize 'cannot be empty' as secure validation", async () => {
      const tool: Tool = {
        name: "firecrawl_crawl",
        description: "Crawl a website",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
          required: ["url"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Tool 'firecrawl_crawl' execution failed: URL cannot be empty",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Should be marked as PASS (tool properly validated empty input)
      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);

      // Verify the specific test
      const boundaryTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "firecrawl_crawl" &&
          t.testName === "Boundary Testing" &&
          t.description === "Empty string validation",
      );

      if (boundaryTests.length > 0) {
        const test = boundaryTests[0];
        expect(test.vulnerable).toBe(false);
        expect(test.evidence).toContain("validation error");
      }
    });

    it("should recognize 'required field' as secure validation", async () => {
      const tool: Tool = {
        name: "required_field_tool",
        description: "Tool with required fields",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string" },
          },
          required: ["name"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Field 'name' is required",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);
    });
  });

  describe("Edge Cases", () => {
    it("should handle missing error codes gracefully", async () => {
      const tool: Tool = {
        name: "tool_without_error_code",
        description: "Tool that doesn't provide error codes",
        inputSchema: {
          type: "object",
          properties: {
            param: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid parameter: must be a valid email address",
            },
          ],
          // No error code provided
        });
      });

      const result = await assessor.assess(mockContext);

      // Should still recognize validation error from message patterns
      expect(result.vulnerabilities.length).toBe(0);
      expectSecureStatus(result);
    });

    it("should handle mixed secure and vulnerable tools correctly", async () => {
      const tools: Tool[] = [
        {
          name: "secure_tool_1",
          description: "Properly validates input",
          inputSchema: {
            type: "object",
            properties: { value: { type: "string" } },
          },
        },
        {
          name: "secure_tool_2",
          description: "Also validates input",
          inputSchema: {
            type: "object",
            properties: { value: { type: "string" } },
          },
        },
        {
          name: "vulnerable_tool",
          description: "Executes without validation",
          inputSchema: {
            type: "object",
            properties: { command: { type: "string" } },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, _params) => {
          if (toolName === "vulnerable_tool") {
            return Promise.resolve({
              isError: false,
              content: [
                { type: "text", text: "Command executed successfully" },
              ],
            });
          } else {
            return Promise.resolve({
              isError: true,
              content: [
                {
                  type: "text",
                  text: "Parameter validation failed: invalid input",
                },
              ],
            });
          }
        });

      const result = await assessor.assess(mockContext);

      // Should identify only the vulnerable tool
      const vulnerabilities = result.vulnerabilities.filter((v) =>
        v.includes("vulnerable_tool"),
      );
      expect(vulnerabilities.length).toBeGreaterThan(0);

      // Secure tools should not be flagged
      const secureToolVulns = result.vulnerabilities.filter(
        (v) => v.includes("secure_tool_1") || v.includes("secure_tool_2"),
      );
      expect(secureToolVulns.length).toBe(0);
    });
  });

  describe("Explicit Validation Rejection Detection", () => {
    it("should recognize valid=false as safe rejection (boundary testing)", async () => {
      const tool: Tool = {
        name: "validate_input_tool",
        description: "Validates input with safe error handling",
        inputSchema: {
          type: "object",
          properties: {
            input_data: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, params) => {
          // Tool correctly rejects oversized input
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: "Validation failed",
                  input: params.input_data,
                  valid: false,
                  errors: ["Input too long (max 1000 characters)"],
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable (tool correctly rejected input)
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "validate_input_tool",
      );
      expect(vulnerableTests.length).toBe(0);
      expectSecureStatus(result);
    });

    it("should recognize error=true as safe rejection", async () => {
      const tool: Tool = {
        name: "check_package_tool",
        description: "Checks package validity",
        inputSchema: {
          type: "object",
          properties: {
            package: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, params) => {
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: `Package '${params.package}' not in approved list`,
                  error: true,
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "check_package_tool",
      );
      expect(vulnerableTests.length).toBe(0);
    });

    it("should recognize errors array as safe rejection", async () => {
      const tool: Tool = {
        name: "validate_data_tool",
        description: "Validates data with detailed error messages",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((_toolName, _params) => {
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: "Validation failed",
                  valid: false,
                  errors: [
                    "Input contains invalid characters",
                    "Input too long",
                  ],
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "validate_data_tool",
      );
      expect(vulnerableTests.length).toBe(0);
    });

    it("should distinguish rejection from actual execution", async () => {
      const tools: Tool[] = [
        {
          name: "safe_validator",
          description: "Validates safely",
          inputSchema: {
            type: "object",
            properties: { input: { type: "string" } },
          },
        },
        {
          name: "vulnerable_executor",
          description: "Executes commands",
          inputSchema: {
            type: "object",
            properties: { command: { type: "string" } },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, _params) => {
          if (toolName === "safe_validator") {
            // SAFE: Rejects with validation error
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    result: "Validation failed",
                    valid: false,
                    errors: ["Input too long"],
                  }),
                },
              ],
            });
          } else {
            // VULNERABLE: Actually executes
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    result: "Command executed",
                    output: "root",
                  }),
                },
              ],
            });
          }
        });

      const result = await assessor.assess(mockContext);

      // Safe validator should not be flagged
      const safeTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "safe_validator",
      );
      expect(safeTests.length).toBe(0);

      // Vulnerable executor should be flagged
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "vulnerable_executor",
      );
      expect(vulnerableTests.length).toBeGreaterThan(0);
    });
  });
});
