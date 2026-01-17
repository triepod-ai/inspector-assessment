/**
 * TestDataGenerator Test Suite - Core Functionality
 *
 * Tests for core configuration, integration, and Claude bridge functionality.
 * This is the main test file for TestDataGenerator.
 *
 * Related test files (split for maintainability - Issue #73):
 * - TestDataGenerator.stringFields.test.ts - String field detection (URL, Email, Path, etc.)
 * - TestDataGenerator.numberFields.test.ts - Number field detection (port, timeout, etc.)
 * - TestDataGenerator.typeHandlers.test.ts - Boolean/Array/Object/Enum handling
 * - TestDataGenerator.scenarios.test.ts - Scenario generation (error, edge, happy path)
 * - TestDataGenerator.dataPool.test.ts - Data pool validation
 * - TestDataGenerator.boundary.test.ts - Boundary scenario optimization
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator } from "../TestDataGenerator";
import { PartialToolSchema } from "@/test/utils/testUtils";
import type { ClaudeCodeBridge } from "@/services/assessment/lib/claudeCodeBridge";

// Helper to access private static methods (Issue #186)
type StaticMethodAccessor = Record<string, (...args: unknown[]) => unknown>;
const getPrivateStaticMethod = (methodName: string) => {
  return (TestDataGenerator as unknown as StaticMethodAccessor)[
    methodName
  ].bind(TestDataGenerator);
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

// Mock Claude Bridge factory
const createMockClaudeBridge = (overrides: Record<string, unknown> = {}) => ({
  isFeatureEnabled: jest.fn().mockReturnValue(true),
  generateTestParameters: jest
    .fn()
    .mockResolvedValue([
      { param1: "claude-value-1" },
      { param1: "claude-value-2" },
    ]),
  ...overrides,
});

describe("TestDataGenerator", () => {
  beforeEach(() => {
    // Reset Claude bridge before each test
    TestDataGenerator.setClaudeBridge(null);
    jest.restoreAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // Claude Bridge Configuration
  // ===========================================================================
  describe("Claude Bridge Configuration", () => {
    it("should return false when no bridge is set", () => {
      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });

    it("should return false when bridge is set but feature disabled", () => {
      const mockBridge = createMockClaudeBridge({
        isFeatureEnabled: jest.fn().mockReturnValue(false),
      });
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });

    it("should return true when bridge is set and feature enabled", () => {
      const mockBridge = createMockClaudeBridge();
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      expect(TestDataGenerator.isClaudeEnabled()).toBe(true);
      expect(mockBridge.isFeatureEnabled).toHaveBeenCalledWith(
        "intelligentTestGeneration",
      );
    });

    it("should allow setting bridge to null", () => {
      const mockBridge = createMockClaudeBridge();
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );
      expect(TestDataGenerator.isClaudeEnabled()).toBe(true);

      TestDataGenerator.setClaudeBridge(null);
      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });
  });

  // ===========================================================================
  // Logger Configuration (BC Tests for Issue #32)
  // ===========================================================================
  describe("Logger Configuration", () => {
    beforeEach(() => {
      TestDataGenerator.setLogger(null);
    });

    it("should work without logger set (backwards compatible)", () => {
      // All existing generateTestScenarios tests verify this
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });

    it("should accept logger via setLogger", () => {
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        child: jest.fn().mockReturnThis(),
        isLevelEnabled: jest.fn().mockReturnValue(true),
      };

      // Should not throw
      TestDataGenerator.setLogger(mockLogger);

      // Functionality still works
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });

    it("should allow clearing logger with null", () => {
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        child: jest.fn().mockReturnThis(),
        isLevelEnabled: jest.fn().mockReturnValue(true),
      };

      TestDataGenerator.setLogger(mockLogger);
      TestDataGenerator.setLogger(null);

      // Functionality still works after clearing
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // generateRealisticParams
  // ===========================================================================
  describe("generateRealisticParams", () => {
    it("should return empty object for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });

    it("should return empty object for non-object schema type", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: {
          type: "array",
        } as PartialToolSchema as Tool["inputSchema"],
      };
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });

    it("should generate params for all properties", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");

      expect(typeof result.name).toBe("string");
      expect(typeof result.count).toBe("number");
      expect(typeof result.enabled).toBe("boolean");
    });

    it("should handle empty properties", () => {
      const tool = createTool("test", {});
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });
  });

  // ===========================================================================
  // generateSingleValue (Backward Compatibility)
  // ===========================================================================
  describe("generateSingleValue", () => {
    it("should call generateRealisticValue with typical variant", () => {
      const result = TestDataGenerator.generateSingleValue("email", {
        type: "string",
      });
      expect(result).toMatch(/@.*\./);
    });

    it("should handle various field types", () => {
      expect(
        TestDataGenerator.generateSingleValue("url", { type: "string" }),
      ).toMatch(/^https?:\/\//);
      expect(
        typeof TestDataGenerator.generateSingleValue("count", {
          type: "number",
        }),
      ).toBe("number");
      expect(
        typeof TestDataGenerator.generateSingleValue("enabled", {
          type: "boolean",
        }),
      ).toBe("boolean");
    });
  });

  // ===========================================================================
  // hasStringInputs
  // ===========================================================================
  describe("hasStringInputs", () => {
    const hasStringInputs = getPrivateStaticMethod("hasStringInputs");

    it("should return false for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return false for non-object schema", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: {
          type: "array",
        } as PartialToolSchema as Tool["inputSchema"],
      };
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return false for tool with no string properties", () => {
      const tool = createTool("test", {
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return true for tool with string property", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
      });
      expect(hasStringInputs(tool)).toBe(true);
    });

    it("should return true for tool with only string properties", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        email: { type: "string" },
      });
      expect(hasStringInputs(tool)).toBe(true);
    });

    it("should return false for tool with empty properties", () => {
      const tool = createTool("test", {});
      expect(hasStringInputs(tool)).toBe(false);
    });
  });

  // ===========================================================================
  // generateTestScenarios (Integration)
  // ===========================================================================
  describe("generateTestScenarios", () => {
    it("should include happy path scenario", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const happyPath = scenarios.find((s) => s.category === "happy_path");
      expect(happyPath).toBeDefined();
    });

    it("should include edge case scenarios", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const edgeCases = scenarios.filter((s) => s.category === "edge_case");
      expect(edgeCases.length).toBeGreaterThan(0);
    });

    it("should include error case scenario", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const errorCase = scenarios.find((s) => s.category === "error_case");
      expect(errorCase).toBeDefined();
    });

    it("should have at least 4 scenarios for simple tool", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      // happy path + 3 edge cases + error case = 5
      expect(scenarios.length).toBeGreaterThanOrEqual(4);
    });

    it("should include boundary scenarios when constraints exist", () => {
      const tool = createTool("test", {
        age: { type: "number", minimum: 0, maximum: 100 },
      });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const boundaryScenarios = scenarios.filter(
        (s) => s.category === "boundary",
      );
      expect(boundaryScenarios.length).toBe(2);
    });
  });

  // ===========================================================================
  // generateTestScenariosAsync (Claude Integration)
  // ===========================================================================
  describe("generateTestScenariosAsync", () => {
    it("should use schema-based when Claude disabled", async () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should use Claude-generated when Claude enabled and returns data", async () => {
      const mockBridge = createMockClaudeBridge();
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      // Should have Claude-generated + 1 error case (schema-based)
      const claudeScenarios = scenarios.filter(
        (s) => s.source === "claude-generated",
      );
      const schemaScenarios = scenarios.filter(
        (s) => s.source === "schema-based",
      );

      expect(claudeScenarios.length).toBe(2);
      expect(schemaScenarios.length).toBe(1); // Error case
    });

    it("should fall back to schema-based when Claude returns empty", async () => {
      const mockBridge = createMockClaudeBridge({
        generateTestParameters: jest.fn().mockResolvedValue([]),
      });
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should fall back to schema-based when Claude throws error", async () => {
      const mockBridge = createMockClaudeBridge({
        generateTestParameters: jest
          .fn()
          .mockRejectedValue(new Error("Claude error")),
      });
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should add error case to Claude scenarios", async () => {
      const mockBridge = createMockClaudeBridge();
      TestDataGenerator.setClaudeBridge(
        mockBridge as unknown as ClaudeCodeBridge,
      );

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      const errorCase = scenarios.find((s) => s.category === "error_case");
      expect(errorCase).toBeDefined();
      expect(errorCase?.source).toBe("schema-based");
    });
  });

  // ===========================================================================
  // Claude Scenario Naming
  // ===========================================================================
  describe("Claude Scenario Naming", () => {
    const getClaudeScenarioName = getPrivateStaticMethod(
      "getClaudeScenarioName",
    );
    const getClaudeScenarioCategory = getPrivateStaticMethod(
      "getClaudeScenarioCategory",
    );

    it("should return Happy Path for index 0", () => {
      expect(getClaudeScenarioName(0)).toBe("Happy Path - Typical Usage");
    });

    it("should return Edge Case for index 1", () => {
      expect(getClaudeScenarioName(1)).toBe("Edge Case - Boundary Values");
    });

    it("should return Minimal Input for index 2", () => {
      expect(getClaudeScenarioName(2)).toBe(
        "Minimal Input - Required Fields Only",
      );
    });

    it("should return Test Case N for index beyond defined names", () => {
      expect(getClaudeScenarioName(10)).toBe("Test Case 11");
    });

    it("should return happy_path category for index 0", () => {
      expect(getClaudeScenarioCategory(0)).toBe("happy_path");
    });

    it("should return edge_case category for index 1", () => {
      expect(getClaudeScenarioCategory(1)).toBe("edge_case");
    });

    it("should return boundary category for index 2", () => {
      expect(getClaudeScenarioCategory(2)).toBe("boundary");
    });

    it("should return happy_path category for index beyond defined", () => {
      expect(getClaudeScenarioCategory(10)).toBe("happy_path");
    });
  });
});
