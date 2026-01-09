/**
 * TestDataGenerator - Scenario Generation Tests
 *
 * Tests for test scenario generation including error cases, edge cases,
 * happy paths, and category-aware generation.
 *
 * Related test files:
 * - TestDataGenerator.test.ts - Core functionality & configuration
 * - TestDataGenerator.stringFields.test.ts - String field detection
 * - TestDataGenerator.numberFields.test.ts - Number field detection
 * - TestDataGenerator.typeHandlers.test.ts - Boolean/Array/Object/Enum handling
 * - TestDataGenerator.dataPool.test.ts - Data pool validation
 * - TestDataGenerator.boundary.test.ts - Boundary scenario optimization
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator, TestScenario } from "../TestDataGenerator";

// Helper to access private static methods
const getPrivateStaticMethod = (methodName: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (TestDataGenerator as any)[methodName].bind(TestDataGenerator);
};

// Tool factory - uses type assertion for flexibility with test schemas
const createTool = (
  name: string,
  properties: Record<string, object> = {},
  required: string[] = [],
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties,
    required,
  },
});

describe("TestDataGenerator - Scenario Generation", () => {
  // ===========================================================================
  // Error Scenario Generation
  // ===========================================================================
  describe("generateErrorScenario", () => {
    const generateErrorScenario = getPrivateStaticMethod(
      "generateErrorScenario",
    );

    it("should return empty params for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
      expect(result.category).toBe("error_case");
    });

    it("should return empty params for non-object schema", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: { type: "array" } as any,
      };
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
    });

    it("should return empty params for tool with no properties", () => {
      const tool = createTool("test", {});
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
    });

    it("should provide number for string field", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.name).toBe(123);
    });

    it("should provide string for number field", () => {
      const tool = createTool("test", { count: { type: "number" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.count).toBe("not_a_number");
    });

    it("should provide string for integer field", () => {
      const tool = createTool("test", { count: { type: "integer" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.count).toBe("not_a_number");
    });

    it("should provide string for boolean field", () => {
      const tool = createTool("test", { enabled: { type: "boolean" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.enabled).toBe("not_a_boolean");
    });

    it("should provide string for array field", () => {
      const tool = createTool("test", { items: { type: "array" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.items).toBe("not_an_array");
    });

    it("should provide string for object field", () => {
      const tool = createTool("test", { config: { type: "object" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.config).toBe("not_an_object");
    });

    it("should provide null for unknown type", () => {
      const tool = createTool("test", { custom: { type: "custom" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.custom).toBe(null);
    });

    it("should only set wrong type for first property", () => {
      const tool = createTool("test", {
        first: { type: "string" },
        second: { type: "string" },
        third: { type: "string" },
      });
      const result = generateErrorScenario(tool) as TestScenario;

      // Only one property should be set
      expect(Object.keys(result.params).length).toBe(1);
    });
  });

  // ===========================================================================
  // Edge Case Scenario Generation
  // ===========================================================================
  describe("generateEdgeCaseScenarios", () => {
    const generateEdgeCaseScenarios = getPrivateStaticMethod(
      "generateEdgeCaseScenarios",
    );

    it("should generate 2 scenarios for tool without string inputs", () => {
      const tool = createTool("test", {
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      // Empty values + Maximum values (no special chars since no strings)
      expect(result.length).toBe(2);
      expect(result[0].name).toBe("Edge Case - Empty Values");
      expect(result[1].name).toBe("Edge Case - Maximum Values");
    });

    it("should generate 3 scenarios for tool with string inputs", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
      });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      // Empty values + Maximum values + Special characters
      expect(result.length).toBe(3);
      expect(result[2].name).toBe("Edge Case - Special Characters");
    });

    it("should set all scenarios to edge_case category", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      result.forEach((scenario) => {
        expect(scenario.category).toBe("edge_case");
      });
    });
  });

  // ===========================================================================
  // Happy Path Scenario Generation
  // ===========================================================================
  describe("generateHappyPathScenario", () => {
    const generateHappyPathScenario = getPrivateStaticMethod(
      "generateHappyPathScenario",
    );

    it("should generate happy_path category", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.category).toBe("happy_path");
    });

    it("should use typical variant for params", () => {
      const tool = createTool("test", { email: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.params.email).toMatch(/@.*\./);
    });

    it("should include tool name in description", () => {
      const tool = createTool("my_special_tool", { name: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.description).toContain("my_special_tool");
    });
  });

  // ===========================================================================
  // Category-Aware Generation
  // ===========================================================================
  describe("generateValueForCategory", () => {
    it("should return math expression for calculator category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "expression",
        { type: "string" },
        "calculator",
      );
      expect(result).toBe("2+2");
    });

    it("should return search query for search_retrieval category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "query",
        { type: "string" },
        "search_retrieval",
      );
      expect(result).toBe("hello world");
    });

    it("should return shell command for system_exec category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "command",
        { type: "string" },
        "system_exec",
      );
      expect(result).toBe("echo hello");
    });

    it("should return URL for url_fetcher category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "target",
        { type: "string" },
        "url_fetcher",
      );
      expect(result).toBe("https://api.github.com");
    });

    it("should use field-name detection for URL field even with category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "url",
        { type: "string" },
        "calculator",
      );
      // URL field should override calculator category
      expect(result).toMatch(/^https?:\/\//);
    });

    it("should use field-name detection for email field even with category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "email",
        { type: "string" },
        "system_exec",
      );
      // Email field should override system_exec category
      expect(result).toMatch(/@.*\./);
    });

    it("should fall back to field-name for unknown category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "name",
        { type: "string" },
        "unknown_category",
      );
      expect(typeof result).toBe("string");
    });

    it("should fall back to field-name for GENERIC category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "name",
        { type: "string" },
        "GENERIC",
      );
      expect(typeof result).toBe("string");
    });
  });

  // ===========================================================================
  // TOOL_CATEGORY_DATA
  // ===========================================================================
  describe("TOOL_CATEGORY_DATA", () => {
    it("should have calculator category with math expressions", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.calculator).toBeDefined();
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.calculator.default).toContain(
        "2+2",
      );
    });

    it("should have search_retrieval category with search queries", () => {
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.search_retrieval,
      ).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.search_retrieval.default,
      ).toContain("hello world");
    });

    it("should have system_exec category with shell commands", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.system_exec).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.system_exec.default,
      ).toContain("echo hello");
    });

    it("should have url_fetcher category with URLs", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.url_fetcher).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.url_fetcher.default[0],
      ).toMatch(/^https?:\/\//);
    });
  });
});
