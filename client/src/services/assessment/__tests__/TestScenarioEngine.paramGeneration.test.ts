/**
 * TestScenarioEngine Parameter Generation Tests
 *
 * Tests for generateMinimalParams, generateSimpleParams, and generateMinimalValue methods
 */

import { TestScenarioEngine } from "../TestScenarioEngine";
import { TestDataGenerator } from "../TestDataGenerator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Helper to access private methods
const getPrivateMethod = <T>(instance: T, methodName: string) => {
  return (instance as any)[methodName].bind(instance);
};

// Mock tool factory
const createTool = (
  name: string,
  schema: Record<string, unknown> = {},
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties: {},
    required: [],
    ...schema,
  },
});

describe("TestScenarioEngine", () => {
  describe("generateMinimalParams", () => {
    let engine: TestScenarioEngine;
    let generateMinimalParams: (tool: Tool) => Record<string, unknown>;

    beforeEach(() => {
      engine = new TestScenarioEngine();
      generateMinimalParams = getPrivateMethod(engine, "generateMinimalParams");
    });

    it("should return empty object for tool without inputSchema", () => {
      const tool: Tool = {
        name: "no_schema",
        description: "Tool without schema",
        inputSchema: undefined as any,
      };
      const result = generateMinimalParams(tool);
      expect(result).toEqual({});
    });

    it("should return empty object for non-object schema type", () => {
      const tool = createTool("array_schema", { type: "array" });
      const result = generateMinimalParams(tool);
      expect(result).toEqual({});
    });

    it("should only include required fields", () => {
      const tool = createTool("test_tool", {
        properties: {
          required_field: { type: "string" },
          optional_field: { type: "string" },
        },
        required: ["required_field"],
      });
      const result = generateMinimalParams(tool);
      expect(result).toHaveProperty("required_field");
      expect(result).not.toHaveProperty("optional_field");
    });

    it("should generate 'test' for string fields", () => {
      const tool = createTool("test_tool", {
        properties: { name: { type: "string" } },
        required: ["name"],
      });
      const result = generateMinimalParams(tool);
      expect(result.name).toBe("test");
    });

    it("should use first enum value for enum string fields", () => {
      const tool = createTool("test_tool", {
        properties: {
          status: { type: "string", enum: ["active", "inactive"] },
        },
        required: ["status"],
      });
      const result = generateMinimalParams(tool);
      expect(result.status).toBe("active");
    });

    it("should generate minimum or 1 for number fields", () => {
      const tool = createTool("test_tool", {
        properties: {
          count: { type: "number" },
          limit: { type: "number", minimum: 10 },
        },
        required: ["count", "limit"],
      });
      const result = generateMinimalParams(tool);
      expect(result.count).toBe(1);
      expect(result.limit).toBe(10);
    });

    it("should generate minimum or 1 for integer fields", () => {
      const tool = createTool("test_tool", {
        properties: {
          page: { type: "integer" },
          size: { type: "integer", minimum: 5 },
        },
        required: ["page", "size"],
      });
      const result = generateMinimalParams(tool);
      expect(result.page).toBe(1);
      expect(result.size).toBe(5);
    });

    it("should generate true for boolean fields", () => {
      const tool = createTool("test_tool", {
        properties: { active: { type: "boolean" } },
        required: ["active"],
      });
      const result = generateMinimalParams(tool);
      expect(result.active).toBe(true);
    });

    it("should generate empty array for array fields", () => {
      const tool = createTool("test_tool", {
        properties: { items: { type: "array" } },
        required: ["items"],
      });
      const result = generateMinimalParams(tool);
      expect(result.items).toEqual([]);
    });

    it("should generate empty object for object fields", () => {
      const tool = createTool("test_tool", {
        properties: { config: { type: "object" } },
        required: ["config"],
      });
      const result = generateMinimalParams(tool);
      expect(result.config).toEqual({});
    });

    it("should handle unknown types with null", () => {
      const tool = createTool("test_tool", {
        properties: { custom: { type: "custom_type" } },
        required: ["custom"],
      });
      const result = generateMinimalParams(tool);
      expect(result.custom).toBeNull();
    });

    it("should return empty object when no required array", () => {
      const tool = createTool("test_tool", {
        properties: { field: { type: "string" } },
        // No required array
      });
      const result = generateMinimalParams(tool);
      expect(result).toEqual({});
    });
  });

  describe("generateSimpleParams", () => {
    let engine: TestScenarioEngine;
    let generateSimpleParams: (tool: Tool) => Record<string, unknown>;

    beforeEach(() => {
      engine = new TestScenarioEngine();
      generateSimpleParams = getPrivateMethod(engine, "generateSimpleParams");
    });

    it("should return empty object for tool without inputSchema", () => {
      const tool: Tool = {
        name: "no_schema",
        description: "Tool without schema",
        inputSchema: undefined as any,
      };
      const result = generateSimpleParams(tool);
      expect(result).toEqual({});
    });

    it("should return empty object for non-object schema type", () => {
      const tool = createTool("array_schema", { type: "array" });
      const result = generateSimpleParams(tool);
      expect(result).toEqual({});
    });

    it("should only include required fields", () => {
      const tool = createTool("test_tool", {
        properties: {
          required_field: { type: "string" },
          optional_field: { type: "string" },
        },
        required: ["required_field"],
      });
      const result = generateSimpleParams(tool);
      expect(result).toHaveProperty("required_field");
      expect(result).not.toHaveProperty("optional_field");
    });

    it("should use TestDataGenerator.generateSingleValue for values", () => {
      const spy = jest.spyOn(TestDataGenerator, "generateSingleValue");
      const tool = createTool("test_tool", {
        properties: { name: { type: "string" } },
        required: ["name"],
      });
      generateSimpleParams(tool);
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it("should handle missing required array gracefully", () => {
      const tool = createTool("test_tool", {
        properties: { field: { type: "string" } },
      });
      const result = generateSimpleParams(tool);
      expect(result).toEqual({});
    });

    it("should handle missing properties gracefully", () => {
      const tool = createTool("test_tool", {
        required: ["field"],
        // No properties
      });
      const result = generateSimpleParams(tool);
      expect(result).toEqual({});
    });

    it("should generate context-aware values based on field names", () => {
      const tool = createTool("test_tool", {
        properties: {
          email: { type: "string" },
          url: { type: "string" },
        },
        required: ["email", "url"],
      });
      const result = generateSimpleParams(tool);
      // TestDataGenerator should generate appropriate values
      expect(result).toHaveProperty("email");
      expect(result).toHaveProperty("url");
    });
  });

  describe("generateMinimalValue", () => {
    let engine: TestScenarioEngine;
    let generateMinimalValue: (schema: any) => unknown;

    beforeEach(() => {
      engine = new TestScenarioEngine();
      generateMinimalValue = getPrivateMethod(engine, "generateMinimalValue");
    });

    it("should return first enum value for string with enum", () => {
      const schema = { type: "string", enum: ["first", "second", "third"] };
      expect(generateMinimalValue(schema)).toBe("first");
    });

    it("should return 'test' for plain string", () => {
      const schema = { type: "string" };
      expect(generateMinimalValue(schema)).toBe("test");
    });

    it("should return minimum value for number with minimum", () => {
      const schema = { type: "number", minimum: 5 };
      expect(generateMinimalValue(schema)).toBe(5);
    });

    it("should return 1 for number without minimum", () => {
      const schema = { type: "number" };
      expect(generateMinimalValue(schema)).toBe(1);
    });

    it("should return minimum value for integer with minimum", () => {
      const schema = { type: "integer", minimum: 10 };
      expect(generateMinimalValue(schema)).toBe(10);
    });

    it("should return 1 for integer without minimum", () => {
      const schema = { type: "integer" };
      expect(generateMinimalValue(schema)).toBe(1);
    });

    it("should return true for boolean", () => {
      const schema = { type: "boolean" };
      expect(generateMinimalValue(schema)).toBe(true);
    });

    it("should return empty array for array type", () => {
      const schema = { type: "array" };
      expect(generateMinimalValue(schema)).toEqual([]);
    });

    it("should return empty object for object type", () => {
      const schema = { type: "object" };
      expect(generateMinimalValue(schema)).toEqual({});
    });

    it("should return null for unknown type", () => {
      const schema = { type: "custom_unknown" };
      expect(generateMinimalValue(schema)).toBeNull();
    });
  });
});
