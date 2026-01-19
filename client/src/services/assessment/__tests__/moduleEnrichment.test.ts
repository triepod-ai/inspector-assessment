/**
 * Module Enrichment Tests
 *
 * Tests for the shared module enrichment utilities used for
 * Stage B Claude validation (Issue #194).
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  inferToolCapabilities,
  buildToolInventory,
  generateFlagsForReview,
  buildPatternCoverage,
  truncateForTokens,
  CAPABILITY_KEYWORDS,
  SENSITIVE_CAPABILITIES,
  MAX_DESCRIPTION_LENGTH,
} from "../lib/moduleEnrichment";

describe("moduleEnrichment", () => {
  describe("inferToolCapabilities", () => {
    it("should detect file_system capabilities", () => {
      const tool: Tool = {
        name: "read_file",
        description: "Reads a file from the filesystem",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("file_system");
    });

    it("should detect network capabilities", () => {
      const tool: Tool = {
        name: "fetch_url",
        description: "Fetches content from an HTTP URL",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("network");
    });

    it("should detect exec capabilities", () => {
      const tool: Tool = {
        name: "run_command",
        description: "Executes a shell command",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("exec");
    });

    it("should detect database capabilities", () => {
      const tool: Tool = {
        name: "query_db",
        description: "Executes a SQL query on the database",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("database");
    });

    it("should detect auth capabilities", () => {
      const tool: Tool = {
        name: "get_token",
        description: "Retrieves authentication token",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("auth");
    });

    it("should detect multiple capabilities", () => {
      const tool: Tool = {
        name: "api_request",
        description:
          "Makes an HTTP request to an API endpoint with authentication",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("network");
      expect(capabilities).toContain("auth");
    });

    it("should return unknown for tools without recognizable capabilities", () => {
      const tool: Tool = {
        name: "calculator",
        description: "Performs basic math operations",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("unknown");
    });

    it("should detect capabilities from tool name even without description", () => {
      const tool: Tool = {
        name: "execute_shell",
        inputSchema: { type: "object" },
      };
      const capabilities = inferToolCapabilities(tool);
      expect(capabilities).toContain("exec");
    });

    describe("underscore name handling (Issue #194 - GAP-4)", () => {
      it("should detect capabilities in tools with underscore prefixes", () => {
        const tool: Tool = {
          name: "_read_file",
          description: "Reads a file from the filesystem",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("file_system");
      });

      it("should detect capabilities in tools with multiple underscores", () => {
        const tool: Tool = {
          name: "__execute__command__",
          description: "Executes a shell command",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("exec");
      });

      it("should detect capabilities from description when name has underscores", () => {
        const tool: Tool = {
          name: "_tool_name_",
          description: "Makes HTTP requests to APIs",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("network");
      });

      it("should handle tool names with only underscores", () => {
        const tool: Tool = {
          name: "___",
          description: "Database query tool",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("database");
      });

      it("should detect network capability from snake_case names", () => {
        const tool: Tool = {
          name: "fetch_http_data",
          description: "Fetches data",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("network");
      });

      it("should handle underscore-prefixed exec tools", () => {
        const tool: Tool = {
          name: "_system_execute",
          description: "System execution tool",
          inputSchema: { type: "object" },
        };
        const capabilities = inferToolCapabilities(tool);
        expect(capabilities).toContain("exec");
      });
    });
  });

  describe("buildToolInventory", () => {
    it("should build inventory from tools array", () => {
      const tools: Tool[] = [
        {
          name: "read_file",
          description: "Reads a file",
          inputSchema: { type: "object" },
        },
        {
          name: "run_command",
          description: "Runs a command",
          inputSchema: { type: "object" },
        },
      ];

      const inventory = buildToolInventory(tools);

      expect(inventory).toHaveLength(2);
      expect(inventory[0].name).toBe("read_file");
      expect(inventory[0].description).toBe("Reads a file");
      expect(inventory[0].capabilities).toContain("file_system");
      expect(inventory[1].name).toBe("run_command");
      expect(inventory[1].capabilities).toContain("exec");
    });

    it("should truncate long descriptions", () => {
      const longDescription = "A".repeat(500);
      const tools: Tool[] = [
        {
          name: "test_tool",
          description: longDescription,
          inputSchema: { type: "object" },
        },
      ];

      const inventory = buildToolInventory(tools);

      expect(inventory[0].description.length).toBeLessThanOrEqual(
        MAX_DESCRIPTION_LENGTH,
      );
      expect(inventory[0].description.endsWith("...")).toBe(true);
    });

    it("should handle tools without descriptions", () => {
      const tools: Tool[] = [
        {
          name: "no_desc_tool",
          inputSchema: { type: "object" },
        },
      ];

      const inventory = buildToolInventory(tools);

      expect(inventory[0].name).toBe("no_desc_tool");
      expect(inventory[0].description).toBe("");
    });

    describe("edge cases (Issue #194 - GAP-5)", () => {
      it("should handle empty tools array", () => {
        const tools: Tool[] = [];

        const inventory = buildToolInventory(tools);

        expect(inventory).toEqual([]);
        expect(inventory).toHaveLength(0);
      });

      it("should handle tools with underscore names", () => {
        const tools: Tool[] = [
          {
            name: "_private_tool",
            description: "A private tool that executes shell commands",
            inputSchema: { type: "object" },
          },
          {
            name: "__dunder_method__",
            description: "Reads files from filesystem",
            inputSchema: { type: "object" },
          },
        ];

        const inventory = buildToolInventory(tools);

        expect(inventory).toHaveLength(2);
        expect(inventory[0].name).toBe("_private_tool");
        expect(inventory[0].capabilities).toContain("exec");
        expect(inventory[1].name).toBe("__dunder_method__");
        expect(inventory[1].capabilities).toContain("file_system");
      });

      it("should handle single tool array", () => {
        const tools: Tool[] = [
          {
            name: "single_tool",
            description: "Single tool",
            inputSchema: { type: "object" },
          },
        ];

        const inventory = buildToolInventory(tools);

        expect(inventory).toHaveLength(1);
        expect(inventory[0].name).toBe("single_tool");
      });

      it("should handle large arrays efficiently", () => {
        const tools: Tool[] = Array.from({ length: 100 }, (_, i) => ({
          name: `tool_${i}`,
          description: `Tool ${i} description`,
          inputSchema: { type: "object" },
        }));

        const inventory = buildToolInventory(tools);

        expect(inventory).toHaveLength(100);
        expect(inventory[0].name).toBe("tool_0");
        expect(inventory[99].name).toBe("tool_99");
      });
    });
  });

  describe("generateFlagsForReview", () => {
    it("should flag tools with exec capabilities", () => {
      const inventory = [
        {
          name: "run_command",
          description: "Runs a shell command",
          capabilities: ["exec" as const],
        },
      ];

      const flags = generateFlagsForReview(inventory);

      expect(flags).toHaveLength(1);
      expect(flags[0].toolName).toBe("run_command");
      expect(flags[0].capabilities).toContain("exec");
      expect(flags[0].confidence).toBe("low");
    });

    it("should flag tools with auth capabilities", () => {
      const inventory = [
        {
          name: "get_credentials",
          description: "Gets authentication credentials",
          capabilities: ["auth" as const],
        },
      ];

      const flags = generateFlagsForReview(inventory);

      expect(flags).toHaveLength(1);
      expect(flags[0].toolName).toBe("get_credentials");
      expect(flags[0].reason).toContain("Authentication");
    });

    it("should not flag tools without sensitive capabilities", () => {
      const inventory = [
        {
          name: "calculator",
          description: "Does math",
          capabilities: ["unknown" as const],
        },
        {
          name: "read_file",
          description: "Reads files",
          capabilities: ["file_system" as const],
        },
      ];

      const flags = generateFlagsForReview(inventory);

      // file_system is not in SENSITIVE_CAPABILITIES
      expect(flags).toHaveLength(0);
    });

    it("should include all sensitive capabilities in flag", () => {
      const inventory = [
        {
          name: "admin_tool",
          description: "Admin tool with multiple capabilities",
          capabilities: ["exec" as const, "auth" as const, "system" as const],
        },
      ];

      const flags = generateFlagsForReview(inventory);

      expect(flags).toHaveLength(1);
      expect(flags[0].capabilities).toContain("exec");
      expect(flags[0].capabilities).toContain("auth");
      expect(flags[0].capabilities).toContain("system");
    });
  });

  describe("buildPatternCoverage", () => {
    it("should return pattern coverage metadata", () => {
      const coverage = buildPatternCoverage();

      expect(coverage.totalPatterns).toBeGreaterThan(0);
      expect(coverage.categoriesCovered.length).toBeGreaterThan(0);
      expect(coverage.samplePatterns.length).toBeGreaterThan(0);
      expect(coverage.samplePatterns.length).toBeLessThanOrEqual(5);
    });

    it("should include severity breakdown", () => {
      const coverage = buildPatternCoverage();

      expect(coverage.severityBreakdown).toHaveProperty("critical");
      expect(coverage.severityBreakdown).toHaveProperty("high");
      expect(coverage.severityBreakdown).toHaveProperty("medium");
      expect(coverage.severityBreakdown).toHaveProperty("flag");
    });

    it("should cover AUP categories A-N", () => {
      const coverage = buildPatternCoverage();
      const expectedCategories = [
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
      ];

      for (const category of expectedCategories) {
        expect(coverage.categoriesCovered).toContain(category);
      }
    });
  });

  describe("truncateForTokens", () => {
    it("should not truncate short strings", () => {
      const short = "Hello, world!";
      expect(truncateForTokens(short, 100)).toBe(short);
    });

    it("should truncate long strings with ellipsis", () => {
      const long = "A".repeat(200);
      const truncated = truncateForTokens(long, 100);

      expect(truncated.length).toBe(100);
      expect(truncated.endsWith("...")).toBe(true);
    });

    it("should handle exactly max length", () => {
      const exact = "A".repeat(100);
      expect(truncateForTokens(exact, 100)).toBe(exact);
    });
  });

  describe("constants", () => {
    it("CAPABILITY_KEYWORDS should have patterns for each category", () => {
      const categories = Object.keys(CAPABILITY_KEYWORDS);
      expect(categories).toContain("file_system");
      expect(categories).toContain("network");
      expect(categories).toContain("exec");
      expect(categories).toContain("database");
      expect(categories).toContain("auth");
      expect(categories).toContain("crypto");
      expect(categories).toContain("system");
      expect(categories).toContain("unknown");
    });

    it("SENSITIVE_CAPABILITIES should include high-risk categories", () => {
      expect(SENSITIVE_CAPABILITIES).toContain("exec");
      expect(SENSITIVE_CAPABILITIES).toContain("auth");
      expect(SENSITIVE_CAPABILITIES).toContain("system");
      expect(SENSITIVE_CAPABILITIES).toContain("crypto");
    });
  });
});
