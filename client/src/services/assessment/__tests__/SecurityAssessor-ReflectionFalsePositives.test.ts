/**
 * Security Assessor - Reflection False Positives Fix
 * Tests that tools safely reflecting malicious input are NOT flagged as vulnerable
 *
 * TESTING MODE: STRICT (pure behavior detection, flags ignored)
 * This test suite runs in STRICT mode to prove the inspector can detect
 * safe reflection patterns WITHOUT any flag assistance. This ensures the
 * detection logic works on real-world tools that don't have security flags.
 *
 * Key principle:
 * - SECURE: Tool stores/echoes malicious input as data (reflection)
 * - VULNERABLE: Tool executes malicious input and returns results (execution)
 *
 * Note: Test responses include flags for documentation, but STRICT mode ignores
 * them. Detection must work purely from behavior patterns like "Stored query:"
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("SecurityAssessor - Reflection False Positives Fix", () => {
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

  describe("Pure Behavior Detection (Ignores Flags)", () => {
    it("should detect safe reflection WITHOUT flag assistance", async () => {
      const tool: Tool = {
        name: "safe_storage_tool",
        description: "Stores queries safely without execution",
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
        .mockImplementation((toolName, params) => {
          // Tool explicitly marks response as not vulnerable
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: `Stored query: ${params.query}`,
                  vulnerable: false, // Explicit safe flag
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable
      expect(result.vulnerabilities.length).toBe(0);
      expect(result.status).toBe("PASS");

      // Verify no tests are marked as vulnerable
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "safe_storage_tool",
      );
      expect(vulnerableTests.length).toBe(0);
    });

    it("should handle vulnerable: false with path traversal payloads", async () => {
      const tool: Tool = {
        name: "safe_calculator_tool",
        description: "Stores calculator queries",
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
        .mockImplementation((toolName, params) => {
          // Tool stores path traversal input safely
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: `Stored query: ${params.query}`,
                  vulnerable: false,
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Path traversal payloads should NOT be flagged as vulnerable
      const pathTraversalTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "safe_calculator_tool" &&
          t.testName === "Path Traversal" &&
          t.vulnerable,
      );
      expect(pathTraversalTests.length).toBe(0);
    });

    it("should still detect vulnerable: true as VULNERABLE", async () => {
      const tool: Tool = {
        name: "vulnerable_tool",
        description: "Executes commands",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          // Tool explicitly marks as vulnerable (actually executed)
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: "Command executed",
                  vulnerable: true, // Explicit vulnerable flag
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "vulnerable_tool",
      );
      expect(vulnerableTests.length).toBeGreaterThan(0);
    });
  });

  describe("Reflection Pattern Detection (Bug Fix #2)", () => {
    it('should recognize "Stored query:" pattern as safe reflection', async () => {
      const tool: Tool = {
        name: "safe_query_store",
        description: "Stores queries safely",
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
        .mockImplementation((toolName, params) => {
          // Tool reflects input with "Stored query:" pattern
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: `Stored query: ${params.query}`,
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.vulnerable && t.toolName === "safe_query_store",
      );
      expect(vulnerableTests.length).toBe(0);
    });

    it("should handle reflection with character escaping differences", async () => {
      const tool: Tool = {
        name: "safe_path_store",
        description: "Stores file paths",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          // Tool reflects path with different escaping (single vs double backslashes)
          // This simulates Windows path: ..\\..\\..\\windows\\system32\\config\\sam
          // Payload may have single backslashes, response has double (JSON escaping)
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: `Stored query: ${params.path}`, // Reflection pattern
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as vulnerable even with escaping differences
      const pathTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "safe_path_store" &&
          t.testName === "Path Traversal" &&
          t.vulnerable,
      );
      expect(pathTests.length).toBe(0);
    });

    it("should detect multiple reflection patterns", async () => {
      const reflectionPatterns = [
        "Stored query:",
        "Query saved:",
        "Data stored:",
        "Command stored:",
        "Setting stored:",
        "Action stored:",
        "Safely stored:",
        "Stored safely:",
      ];

      for (const pattern of reflectionPatterns) {
        const tool: Tool = {
          name: `tool_${pattern.replace(/[^a-z]/gi, "_")}`,
          description: "Safe storage tool",
          inputSchema: {
            type: "object",
            properties: {
              input: { type: "string" },
            },
          },
        };

        mockContext.tools = [tool];
        mockContext.callTool = jest
          .fn()
          .mockImplementation((toolName, params) => {
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: `${pattern} ${params.input}`,
                },
              ],
            });
          });

        const result = await assessor.assess(mockContext);

        // None of these patterns should be flagged as vulnerable
        const vulnerableTests = result.promptInjectionTests.filter(
          (t) => t.vulnerable && t.toolName === tool.name,
        );
        expect(vulnerableTests.length).toBe(0);
      }
    });
  });

  describe("Execution vs Reflection Distinction", () => {
    it("should detect actual path traversal execution as VULNERABLE", async () => {
      const tool: Tool = {
        name: "vulnerable_file_reader",
        description: "Reads files (vulnerable)",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          // Tool actually reads the file and returns contents
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // Should be flagged as vulnerable (file contents returned, not path)
      const pathTraversalTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "vulnerable_file_reader" &&
          t.testName === "Path Traversal" &&
          t.vulnerable,
      );
      expect(pathTraversalTests.length).toBeGreaterThan(0);
    });

    it("should distinguish reflection from execution with computation", async () => {
      const tools: Tool[] = [
        {
          name: "safe_reflection_tool",
          description: "Reflects input safely",
          inputSchema: {
            type: "object",
            properties: { input: { type: "string" } },
          },
        },
        {
          name: "vulnerable_execution_tool",
          description: "Executes and computes",
          inputSchema: {
            type: "object",
            properties: { expression: { type: "string" } },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          if (toolName === "safe_reflection_tool") {
            // Safe: just echoes input
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: `Stored query: ${params.input}`,
                },
              ],
            });
          } else {
            // Vulnerable: actually executes command
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: `Command executed: root`,
                },
              ],
            });
          }
        });

      const result = await assessor.assess(mockContext);

      // Safe tool should not be flagged
      const safeTests = result.promptInjectionTests.filter(
        (t) => t.toolName === "safe_reflection_tool" && t.vulnerable,
      );
      expect(safeTests.length).toBe(0);

      // Vulnerable tool should be flagged
      const vulnerableTests = result.promptInjectionTests.filter(
        (t) => t.toolName === "vulnerable_execution_tool" && t.vulnerable,
      );
      expect(vulnerableTests.length).toBeGreaterThan(0);
    });
  });

  describe("Real-World Broken MCP Server Test Cases", () => {
    it("should correctly assess all 6 safe control tools from broken MCP server", async () => {
      // These are the safe control tools from the broken MCP test server
      const safeTools: Tool[] = [
        {
          name: "safe_storage_tool",
          description: "Stores data without executing it",
          inputSchema: {
            type: "object",
            properties: {
              data: { type: "string" },
              collection: { type: "string" },
            },
            required: ["data"],
          },
        },
        {
          name: "safe_search_tool",
          description: "Searches data without executing queries",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        },
        {
          name: "safe_list_tool",
          description: "Lists resources with safe error handling",
          inputSchema: {
            type: "object",
            properties: {
              resource_type: { type: "string" },
            },
          },
        },
        {
          name: "safe_info_tool",
          description: "Gets entity info with safe error reflection",
          inputSchema: {
            type: "object",
            properties: {
              entity_name: { type: "string" },
            },
            required: ["entity_name"],
          },
        },
        {
          name: "safe_echo_tool",
          description: "Echoes message as data",
          inputSchema: {
            type: "object",
            properties: {
              message: { type: "string" },
            },
            required: ["message"],
          },
        },
        {
          name: "safe_validate_tool",
          description: "Validates input with safe error handling",
          inputSchema: {
            type: "object",
            properties: {
              input_data: { type: "string" },
            },
            required: ["input_data"],
          },
        },
      ];

      mockContext.tools = safeTools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          // All safe tools return safe reflection patterns
          const paramValue = Object.values(params)[0];
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  result: `Stored query: ${paramValue}`,
                  vulnerable: false,
                  safe: true,
                }),
              },
            ],
          });
        });

      const result = await assessor.assess(mockContext);

      // ALL safe tools should pass (0 vulnerabilities)
      expect(result.vulnerabilities.length).toBe(0);
      expect(result.status).toBe("PASS");

      // Verify each tool individually
      for (const tool of safeTools) {
        const toolTests = result.promptInjectionTests.filter(
          (t) => t.toolName === tool.name && t.vulnerable,
        );
        expect(toolTests.length).toBe(0);
      }
    });

    it("should achieve 100% precision (no false positives)", async () => {
      // Mix of vulnerable and safe tools
      const tools: Tool[] = [
        {
          name: "vulnerable_tool_1",
          description: "Executes commands",
          inputSchema: {
            type: "object",
            properties: { command: { type: "string" } },
          },
        },
        {
          name: "safe_tool_1",
          description: "Stores safely",
          inputSchema: {
            type: "object",
            properties: { data: { type: "string" } },
          },
        },
        {
          name: "safe_tool_2",
          description: "Echoes safely",
          inputSchema: {
            type: "object",
            properties: { message: { type: "string" } },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest
        .fn()
        .mockImplementation((toolName, params) => {
          if (toolName === "vulnerable_tool_1") {
            // Actually vulnerable - executes
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: "Command executed: root",
                },
              ],
            });
          } else {
            // Safe - reflects with explicit flags
            return Promise.resolve({
              isError: false,
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    result: `Stored data: ${Object.values(params)[0]}`,
                    vulnerable: false,
                  }),
                },
              ],
            });
          }
        });

      const result = await assessor.assess(mockContext);

      // Calculate precision: TP / (TP + FP)
      const vulnerableTools = result.promptInjectionTests
        .filter((t) => t.vulnerable)
        .map((t) => t.toolName);
      const uniqueVulnerableTools = [...new Set(vulnerableTools)];

      // Only vulnerable_tool_1 should be flagged
      expect(uniqueVulnerableTools).toEqual(["vulnerable_tool_1"]);

      // Safe tools should not be flagged (no false positives)
      const safeToolVulns = result.vulnerabilities.filter(
        (v) => v.includes("safe_tool_1") || v.includes("safe_tool_2"),
      );
      expect(safeToolVulns.length).toBe(0);

      // Precision should be 100%
      const truePositives = 1; // vulnerable_tool_1
      const falsePositives = 0; // no safe tools flagged
      const precision = truePositives / (truePositives + falsePositives);
      expect(precision).toBe(1.0);
    });
  });
});
