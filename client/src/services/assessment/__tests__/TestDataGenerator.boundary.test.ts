/**
 * Tests for conditional boundary scenario generation
 * Verifies Phase 2 optimization: only generate boundary tests when constraints exist
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator } from "../TestDataGenerator";

describe("TestDataGenerator - Boundary Scenario Optimization", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("generateBoundaryScenarios", () => {
    it("should return empty array for tool without boundary constraints", () => {
      // Tool with no min/max constraints
      const toolWithoutConstraints: Tool = {
        name: "simple_tool",
        description: "A simple tool without constraints",
        inputSchema: {
          type: "object",
          properties: {
            message: {
              type: "string",
              description: "A message",
            },
            count: {
              type: "number",
              description: "A count",
            },
            enabled: {
              type: "boolean",
              description: "Enabled flag",
            },
          },
          required: ["message"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithoutConstraints,
      );

      expect(scenarios).toEqual([]);
      expect(scenarios.length).toBe(0);
    });

    it("should generate boundary scenarios for tool with minimum constraint", () => {
      const toolWithMinimum: Tool = {
        name: "bounded_tool",
        description: "A tool with minimum constraint",
        inputSchema: {
          type: "object",
          properties: {
            age: {
              type: "number",
              description: "Age in years",
              minimum: 0,
            },
          },
          required: ["age"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithMinimum,
      );

      expect(scenarios.length).toBeGreaterThan(0);
      expect(scenarios[0].name).toBe("Boundary - age at minimum");
      expect(scenarios[0].params.age).toBe(0);
    });

    it("should generate boundary scenarios for tool with maximum constraint", () => {
      const toolWithMaximum: Tool = {
        name: "bounded_tool",
        description: "A tool with maximum constraint",
        inputSchema: {
          type: "object",
          properties: {
            percentage: {
              type: "number",
              description: "Percentage value",
              maximum: 100,
            },
          },
          required: ["percentage"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithMaximum,
      );

      expect(scenarios.length).toBeGreaterThan(0);
      expect(scenarios[0].name).toBe("Boundary - percentage at maximum");
      expect(scenarios[0].params.percentage).toBe(100);
    });

    it("should generate boundary scenarios for tool with string length constraints", () => {
      const toolWithStringLengths: Tool = {
        name: "string_tool",
        description: "A tool with string length constraints",
        inputSchema: {
          type: "object",
          properties: {
            username: {
              type: "string",
              description: "Username",
              minLength: 3,
              maxLength: 20,
            },
          },
          required: ["username"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithStringLengths,
      );

      expect(scenarios.length).toBe(2); // min and max length
      expect(
        scenarios.some((s) => s.name === "Boundary - username at min length"),
      ).toBe(true);
      expect(
        scenarios.some((s) => s.name === "Boundary - username at max length"),
      ).toBe(true);
    });

    it("should generate scenarios for mixed tool (some fields with constraints, some without)", () => {
      const mixedTool: Tool = {
        name: "mixed_tool",
        description: "A tool with mixed constraints",
        inputSchema: {
          type: "object",
          properties: {
            // No constraints
            message: {
              type: "string",
              description: "A message",
            },
            // Has constraints
            priority: {
              type: "number",
              description: "Priority level",
              minimum: 1,
              maximum: 10,
            },
            // No constraints
            enabled: {
              type: "boolean",
              description: "Enabled flag",
            },
          },
          required: ["message", "priority"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        mixedTool,
      );

      expect(scenarios.length).toBe(2); // min and max for priority field only
      expect(scenarios.every((s) => s.name.includes("priority"))).toBe(true);
    });

    it("should return empty array for tool with no properties in schema", () => {
      const toolWithoutProperties: Tool = {
        name: "no_properties_tool",
        description: "A tool without properties",
        inputSchema: {
          type: "object",
        },
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithoutProperties,
      );

      expect(scenarios).toEqual([]);
    });

    it("should return empty array for tool with non-object schema", () => {
      const toolWithNonObjectSchema: Tool = {
        name: "array_tool",
        description: "A tool with array schema",
        inputSchema: {
          type: "array",
        } as any,
      };

      const scenarios = (TestDataGenerator as any).generateBoundaryScenarios(
        toolWithNonObjectSchema,
      );

      expect(scenarios).toEqual([]);
    });
  });

  describe("generateTestScenarios - Integration", () => {
    it("should not include boundary scenarios for tool without constraints", () => {
      const simpleToolWithoutConstraints: Tool = {
        name: "simple_tool",
        description: "A simple tool",
        inputSchema: {
          type: "object",
          properties: {
            message: {
              type: "string",
              description: "A message",
            },
          },
          required: ["message"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateTestScenarios(
        simpleToolWithoutConstraints,
      );

      // Should have: happy path, edge cases, error case
      // Should NOT have: boundary scenarios
      const boundaryScenarios = scenarios.filter(
        (s: any) => s.category === "boundary",
      );
      expect(boundaryScenarios.length).toBe(0);
    });

    it("should include boundary scenarios for tool with constraints", () => {
      const toolWithConstraints: Tool = {
        name: "bounded_tool",
        description: "A tool with constraints",
        inputSchema: {
          type: "object",
          properties: {
            age: {
              type: "number",
              description: "Age",
              minimum: 0,
              maximum: 150,
            },
          },
          required: ["age"],
        },
      };

      const scenarios = (TestDataGenerator as any).generateTestScenarios(
        toolWithConstraints,
      );

      // Should have: happy path, edge cases, boundary scenarios, error case
      const boundaryScenarios = scenarios.filter(
        (s: any) => s.category === "boundary",
      );
      expect(boundaryScenarios.length).toBe(2); // min and max
    });
  });
});
