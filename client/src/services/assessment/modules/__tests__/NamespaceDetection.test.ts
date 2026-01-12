/**
 * Namespace Detection Tests (Issue #142)
 *
 * Tests for the namespace/prefix detection feature in DeveloperExperienceAssessor.
 * This feature helps identify intentional naming patterns in MCP tools to
 * reduce false positives for "naming conflicts" in downstream analyzers.
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import { DeveloperExperienceAssessor } from "../DeveloperExperienceAssessor";
import { AssessmentContext } from "../../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";

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
    documentation: true,
    errorHandling: false,
    usability: true,
  },
  ...overrides,
});

describe("DeveloperExperienceAssessor - Namespace Detection (Issue #142)", () => {
  let assessor: DeveloperExperienceAssessor;

  beforeEach(() => {
    assessor = new DeveloperExperienceAssessor(createConfig());
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Helper to create minimal context with tools
  function createContext(
    tools: Tool[],
    serverName?: string,
  ): AssessmentContext {
    return {
      tools,
      serverInfo: serverName
        ? { name: serverName, version: "1.0.0" }
        : undefined,
      readmeContent: "",
      sourceCodeFiles: new Map(),
      config: createConfig(),
    } as unknown as AssessmentContext;
  }

  // Helper to create mock tools
  function createTools(names: string[]): Tool[] {
    return names.map((name) => ({
      name,
      description: `Test tool: ${name}`,
      inputSchema: { type: "object" as const },
    }));
  }

  describe("Snake_case prefix detection", () => {
    it("should detect 'calc' namespace from calc_add, calc_subtract, calc_multiply", async () => {
      const tools = createTools([
        "calc_add",
        "calc_subtract",
        "calc_multiply",
        "calc_divide",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection).toBeDefined();
      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("calc");
      expect(result.namespaceDetection?.confidence).toBe("high");
      expect(result.namespaceDetection?.toolsCovered).toBe(4);
      expect(result.namespaceDetection?.matchPattern).toBe("prefix");
    });

    it("should detect 'file' namespace from file_read, file_write, file_delete", async () => {
      const tools = createTools(["file_read", "file_write", "file_delete"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("file");
      expect(result.namespaceDetection?.confidence).toBe("high");
    });

    it("should detect 'vulnerable' namespace from testbed tools", async () => {
      const tools = createTools([
        "vulnerable_calculator_tool",
        "vulnerable_system_exec_tool",
        "vulnerable_file_read_tool",
        "safe_calculator_tool",
        "safe_echo_tool",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("vulnerable");
      expect(result.namespaceDetection?.toolsCovered).toBe(3);
    });
  });

  describe("CamelCase prefix detection", () => {
    it("should detect 'calc' namespace from calcAdd, calcSubtract, calcMultiply", async () => {
      const tools = createTools([
        "calcAdd",
        "calcSubtract",
        "calcMultiply",
        "calcDivide",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("calc");
      expect(result.namespaceDetection?.confidence).toBe("high");
    });

    it("should detect 'file' namespace from fileRead, fileWrite, fileList", async () => {
      const tools = createTools(["fileRead", "fileWrite", "fileList"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("file");
    });
  });

  describe("Server name prefix detection", () => {
    it("should detect server name 'myserver' as namespace", async () => {
      const tools = createTools([
        "myserver_tool1",
        "myserver_tool2",
        "myserver_utility",
        "other_thing",
      ]);
      const context = createContext(tools, "myserver");

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("myserver");
      expect(result.namespaceDetection?.matchPattern).toBe("serverName");
      expect(result.namespaceDetection?.confidence).toBe("high");
    });

    it("should handle server names in tool prefixes", async () => {
      // Server named "calculator", tools named "calculator_*"
      const tools = createTools([
        "calculator_add",
        "calculator_subtract",
        "calculator_multiply",
        "random_tool",
      ]);
      const context = createContext(tools, "calculator");

      const result = await assessor.assess(context);

      // Should detect "calculator" as namespace (3/4 = 75%)
      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("calculator");
    });

    it("should handle camelCase tool names with server prefix", async () => {
      const tools = createTools(["mcpToolRead", "mcpToolWrite", "mcpToolList"]);
      const context = createContext(tools, "mcp");

      const result = await assessor.assess(context);

      // Should detect either server name or prefix pattern
      expect(result.namespaceDetection?.detected).toBe(true);
    });
  });

  describe("No namespace detection", () => {
    it("should not detect namespace for random tool names", async () => {
      const tools = createTools([
        "read_data",
        "write_output",
        "process_info",
        "get_status",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(false);
      expect(result.namespaceDetection?.matchPattern).toBe("none");
    });

    it("should not detect namespace for single-word tools", async () => {
      const tools = createTools(["read", "write", "delete", "list"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(false);
    });
  });

  describe("Edge cases", () => {
    it("should handle single tool (cannot detect namespace)", async () => {
      const tools = createTools(["calc_add"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(false);
      expect(result.namespaceDetection?.totalTools).toBe(1);
    });

    it("should handle empty tools array", async () => {
      const context = createContext([]);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(false);
      expect(result.namespaceDetection?.totalTools).toBe(0);
    });

    it("should handle mixed naming conventions", async () => {
      const tools = createTools([
        "calc_add",
        "calcSubtract", // camelCase mixed in
        "calc_multiply",
        "random_tool",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      // Should still detect "calc" namespace
      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("calc");
    });

    it("should require minimum prefix length of 3 characters", async () => {
      const tools = createTools(["ab_one", "ab_two", "ab_three"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      // "ab" is only 2 chars, should not be detected as namespace
      expect(result.namespaceDetection?.detected).toBe(false);
    });

    it("should detect 3-character prefixes", async () => {
      const tools = createTools(["abc_one", "abc_two", "abc_three"]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("abc");
    });
  });

  describe("Confidence levels", () => {
    it("should return HIGH confidence when >=50% of tools share prefix", async () => {
      const tools = createTools([
        "calc_add",
        "calc_subtract",
        "calc_multiply",
        "other_tool",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.confidence).toBe("high");
      expect(result.namespaceDetection?.toolsCovered).toBe(3);
    });

    it("should return MEDIUM confidence when 30-50% of tools share prefix", async () => {
      // 2 calc tools out of 6 = 33% (medium confidence)
      // Use unique tool names that don't share any prefix
      const tools = createTools([
        "calc_add",
        "calc_subtract",
        "read", // single word, no prefix
        "write", // single word
        "execute", // single word
        "listAll", // camelCase but different prefix
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.detected).toBe(true);
      expect(result.namespaceDetection?.namespace).toBe("calc");
      expect(result.namespaceDetection?.confidence).toBe("medium");
    });

    it("should not detect namespace when <30% of tools share prefix", async () => {
      // 1 calc tool out of 8 = 12.5% (below threshold)
      // Use unique tool names that don't share any common prefix
      const tools = createTools([
        "calc_add",
        "read", // single word
        "write",
        "execute",
        "process",
        "render",
        "compile",
        "deploy",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      // "calc" has only 1/8 = 12.5% coverage, below 30% threshold
      // No other prefix meets the minimum 2-tool requirement
      expect(result.namespaceDetection?.detected).toBe(false);
    });
  });

  describe("Evidence field", () => {
    it("should include sample tool names as evidence", async () => {
      const tools = createTools([
        "calc_add",
        "calc_subtract",
        "calc_multiply",
        "calc_divide",
        "calc_power",
        "calc_root",
      ]);
      const context = createContext(tools);

      const result = await assessor.assess(context);

      expect(result.namespaceDetection?.evidence).toBeDefined();
      expect(result.namespaceDetection?.evidence?.length).toBeLessThanOrEqual(
        5,
      );
      expect(result.namespaceDetection?.evidence).toContain("calc_add");
    });
  });
});
