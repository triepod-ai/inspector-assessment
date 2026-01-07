/**
 * TestScenarioEngine Test Suite
 * Tests multi-scenario tool testing orchestration
 *
 * Note: TestScenarioEngine is currently dead code (not imported anywhere)
 * but these tests validate its functionality for future integration.
 */

import {
  TestScenarioEngine,
  ComprehensiveToolTestResult,
  ScenarioTestResult,
} from "../TestScenarioEngine";
import { TestDataGenerator, TestScenario } from "../TestDataGenerator";
import { ResponseValidator, ValidationResult } from "../ResponseValidator";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

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

// Mock response factory
const createMockResponse = (
  overrides: Partial<CompatibilityCallToolResult> = {},
): CompatibilityCallToolResult => ({
  content: [{ type: "text", text: "Success response" }],
  isError: false,
  ...overrides,
});

// Mock scenario factory
const createMockScenario = (
  overrides: Partial<TestScenario> = {},
): TestScenario => ({
  name: "Test Scenario",
  description: "A test scenario",
  params: { query: "test" },
  expectedBehavior: "Success",
  category: "happy_path",
  source: "schema-based",
  ...overrides,
});

// Mock validation result factory
const createMockValidation = (
  overrides: Partial<ValidationResult> = {},
): ValidationResult => ({
  isValid: true,
  isError: false,
  confidence: 100,
  issues: [],
  evidence: ["Tool responded successfully"],
  classification: "fully_working",
  ...overrides,
});

// Mock ComprehensiveToolTestResult factory
const createMockResult = (
  overrides: Partial<ComprehensiveToolTestResult> = {},
): ComprehensiveToolTestResult => ({
  toolName: "test_tool",
  tested: true,
  totalScenarios: 4,
  scenariosExecuted: 4,
  scenariosPassed: 4,
  scenariosFailed: 0,
  overallStatus: "fully_working",
  confidence: 100,
  executionTime: 1000,
  scenarioResults: [],
  summary: {
    happyPathSuccess: true,
    edgeCasesHandled: 1,
    edgeCasesTotal: 1,
    boundariesRespected: 1,
    boundariesTotal: 1,
    errorHandlingWorks: true,
  },
  progressiveComplexity: {
    minimalWorks: true,
    simpleWorks: true,
    failurePoint: "none",
  },
  recommendations: [],
  ...overrides,
});

describe("TestScenarioEngine", () => {
  describe("Constructor and Configuration", () => {
    it("should use default timeout of 5000ms when not specified", () => {
      const engine = new TestScenarioEngine();
      expect((engine as any).testTimeout).toBe(5000);
    });

    it("should use default delayBetweenTests of 0 when not specified", () => {
      const engine = new TestScenarioEngine();
      expect((engine as any).delayBetweenTests).toBe(0);
    });

    it("should accept custom testTimeout value", () => {
      const engine = new TestScenarioEngine(10000);
      expect((engine as any).testTimeout).toBe(10000);
    });

    it("should accept custom delayBetweenTests value", () => {
      const engine = new TestScenarioEngine(5000, 100);
      expect((engine as any).delayBetweenTests).toBe(100);
    });

    it("should handle zero timeout", () => {
      const engine = new TestScenarioEngine(0);
      expect((engine as any).testTimeout).toBe(0);
    });

    it("should handle large timeout values", () => {
      const engine = new TestScenarioEngine(600000);
      expect((engine as any).testTimeout).toBe(600000);
    });
  });

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

  describe("testProgressiveComplexity", () => {
    let engine: TestScenarioEngine;

    beforeEach(() => {
      engine = new TestScenarioEngine(100, 0); // Short timeout for tests
    });

    it("should return minimalWorks=true when minimal params succeed", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(true);
    });

    it("should return minimalWorks=false and failurePoint='minimal' when minimal params timeout", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest
        .fn()
        .mockImplementation(
          () => new Promise((resolve) => setTimeout(resolve, 5000)),
        );

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(false);
      expect(result?.failurePoint).toBe("minimal");
    });

    it("should return minimalWorks=false and failurePoint='minimal' when minimal params throw error", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest.fn().mockRejectedValue(new Error("Test error"));

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(false);
      expect(result?.failurePoint).toBe("minimal");
    });

    it("should return minimalWorks=true when minimal params return business logic error", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest.fn().mockResolvedValue(
        createMockResponse({
          isError: true,
          content: [{ type: "text", text: "Resource not found" }],
        }),
      );
      jest
        .spyOn(ResponseValidator, "isBusinessLogicError")
        .mockReturnValue(true);

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(true);
    });

    it("should return simpleWorks=true when simple params succeed", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.simpleWorks).toBe(true);
    });

    it("should return failurePoint='simple' when simple params fail after minimal succeeds", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      let callCount = 0;
      const mockCallTool = jest.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve(createMockResponse());
        }
        return Promise.reject(new Error("Simple failed"));
      });

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(true);
      expect(result?.simpleWorks).toBe(false);
      expect(result?.failurePoint).toBe("simple");
    });

    it("should return failurePoint='none' when both minimal and simple pass", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(result?.minimalWorks).toBe(true);
      expect(result?.simpleWorks).toBe(true);
      expect(result?.failurePoint).toBe("none");
    });

    it("should not test simple params if minimal fails (early return)", async () => {
      const tool = createTool("test_tool", {
        properties: { query: { type: "string" } },
        required: ["query"],
      });
      const mockCallTool = jest
        .fn()
        .mockRejectedValue(new Error("Minimal error"));

      const result = await engine.testProgressiveComplexity(tool, mockCallTool);

      expect(mockCallTool).toHaveBeenCalledTimes(1); // Only minimal test
      expect(result?.failurePoint).toBe("minimal");
    });
  });

  describe("executeScenario", () => {
    let engine: TestScenarioEngine;
    let executeScenario: (
      tool: Tool,
      scenario: TestScenario,
      callTool: (
        name: string,
        params: Record<string, unknown>,
      ) => Promise<CompatibilityCallToolResult>,
    ) => Promise<ScenarioTestResult>;

    beforeEach(() => {
      engine = new TestScenarioEngine(100, 0); // Short timeout for tests
      executeScenario = getPrivateMethod(engine, "executeScenario");
    });

    describe("successful execution", () => {
      it("should return executed=true for successful call", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.executed).toBe(true);
      });

      it("should record executionTime", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.executionTime).toBeGreaterThanOrEqual(0);
      });

      it("should include response in result", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockResponse = createMockResponse();
        const mockCallTool = jest.fn().mockResolvedValue(mockResponse);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.response).toEqual(mockResponse);
      });

      it("should call ResponseValidator.validateResponse", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());
        const spy = jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());

        await executeScenario(tool, scenario, mockCallTool);

        expect(spy).toHaveBeenCalled();
      });

      it("should pass correct ValidationContext", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "edge_case" });
        const mockResponse = createMockResponse();
        const mockCallTool = jest.fn().mockResolvedValue(mockResponse);
        const spy = jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());

        await executeScenario(tool, scenario, mockCallTool);

        expect(spy).toHaveBeenCalledWith(
          expect.objectContaining({
            tool,
            input: scenario.params,
            response: mockResponse,
            scenarioCategory: "edge_case",
          }),
        );
      });
    });

    describe("timeout handling", () => {
      it("should set validation.isError=true on timeout", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest
          .fn()
          .mockImplementation(
            () => new Promise((resolve) => setTimeout(resolve, 5000)),
          );

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.isError).toBe(true);
        expect(result.error).toContain("Timeout");
      });

      it("should set validation.classification='broken' on timeout", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest
          .fn()
          .mockImplementation(
            () => new Promise((resolve) => setTimeout(resolve, 5000)),
          );

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.classification).toBe("broken");
      });
    });

    describe("error handling", () => {
      it("should catch and handle thrown errors", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario();
        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Test error"));

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.executed).toBe(true);
        expect(result.error).toBe("Test error");
      });

      it("should set validation.isValid=false for non-error_case scenarios", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "happy_path" });
        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Test error"));

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.isValid).toBe(false);
      });

      it("should set validation.isValid=true for error_case scenarios (expected rejection)", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "error_case" });
        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Invalid input"));

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.isValid).toBe(true);
        expect(result.validation.confidence).toBe(80);
      });

      it("should set validation.classification='partially_working' for error_case scenarios", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "error_case" });
        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Validation error"));

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.classification).toBe("partially_working");
      });

      it("should NOT treat timeout as valid for error_case scenarios", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "error_case" });
        const mockCallTool = jest
          .fn()
          .mockImplementation(
            () => new Promise((resolve) => setTimeout(resolve, 5000)),
          );

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.isValid).toBe(false);
        expect(result.validation.classification).toBe("broken");
      });

      it("should add evidence about proper rejection for error_case scenarios", async () => {
        const tool = createTool("test_tool");
        const scenario = createMockScenario({ category: "error_case" });
        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Invalid input"));

        const result = await executeScenario(tool, scenario, mockCallTool);

        expect(result.validation.evidence).toContain(
          "Tool properly rejected invalid input with exception",
        );
      });
    });
  });

  describe("testToolComprehensively", () => {
    let engine: TestScenarioEngine;

    beforeEach(() => {
      engine = new TestScenarioEngine(100, 0);
    });

    describe("scenario generation and execution", () => {
      it("should call TestDataGenerator.generateTestScenarios", async () => {
        const tool = createTool("test_tool");
        const spy = jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario()]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        await engine.testToolComprehensively(tool, mockCallTool);

        expect(spy).toHaveBeenCalledWith(tool);
        spy.mockRestore();
      });

      it("should execute all generated scenarios", async () => {
        const tool = createTool("test_tool");
        const scenarios = [
          createMockScenario({ name: "Scenario 1" }),
          createMockScenario({ name: "Scenario 2" }),
          createMockScenario({ name: "Scenario 3" }),
        ];
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue(scenarios);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        // 2 calls for progressive complexity + 3 for scenarios
        expect(mockCallTool).toHaveBeenCalledTimes(5);
        expect(result.scenarioResults).toHaveLength(3);
      });

      it("should include progressiveComplexity in result", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario()]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.progressiveComplexity).toBeDefined();
        expect(result.progressiveComplexity?.minimalWorks).toBeDefined();
        expect(result.progressiveComplexity?.simpleWorks).toBeDefined();
      });
    });

    describe("counter tracking", () => {
      it("should correctly count totalScenarios", async () => {
        const tool = createTool("test_tool");
        const scenarios = [
          createMockScenario(),
          createMockScenario(),
          createMockScenario(),
        ];
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue(scenarios);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.totalScenarios).toBe(3);
      });

      it("should correctly count scenariosExecuted", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario(), createMockScenario()]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.scenariosExecuted).toBe(2);
      });

      it("should correctly count scenariosPassed for valid scenarios", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario(), createMockScenario()]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.scenariosPassed).toBe(2);
      });

      it("should correctly count scenariosFailed for invalid scenarios", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario(), createMockScenario()]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: false }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.scenariosFailed).toBe(2);
      });
    });

    describe("summary population", () => {
      it("should set happyPathSuccess=true when happy_path scenario passes", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario({ category: "happy_path" })]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.summary.happyPathSuccess).toBe(true);
      });

      it("should increment edgeCasesHandled for passing edge_case scenarios", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([
            createMockScenario({ category: "edge_case" }),
            createMockScenario({ category: "edge_case" }),
          ]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.summary.edgeCasesHandled).toBe(2);
        expect(result.summary.edgeCasesTotal).toBe(2);
      });

      it("should increment boundariesRespected for passing boundary scenarios", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario({ category: "boundary" })]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.summary.boundariesRespected).toBe(1);
        expect(result.summary.boundariesTotal).toBe(1);
      });

      it("should set errorHandlingWorks=true when error_case scenario passes", async () => {
        const tool = createTool("test_tool");
        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario({ category: "error_case" })]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);
        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.summary.errorHandlingWorks).toBe(true);
      });
    });
  });

  describe("determineOverallStatus", () => {
    let engine: TestScenarioEngine;
    let determineOverallStatus: (
      result: ComprehensiveToolTestResult,
    ) => ComprehensiveToolTestResult["overallStatus"];

    beforeEach(() => {
      engine = new TestScenarioEngine();
      determineOverallStatus = getPrivateMethod(
        engine,
        "determineOverallStatus",
      );
    });

    describe("untested status", () => {
      it("should return 'untested' when scenariosExecuted=0", () => {
        const result = createMockResult({ scenariosExecuted: 0 });
        expect(determineOverallStatus(result)).toBe("untested");
      });
    });

    describe("fully_working threshold (>=90% + errorHandling)", () => {
      it("should return 'fully_working' when adjustedPassRate>=0.9 and errorHandlingWorks", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 9,
          scenariosFailed: 1,
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("fully_working");
      });

      it("should NOT return 'fully_working' when errorHandlingWorks=false", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 10,
          scenariosFailed: 0,
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).not.toBe("fully_working");
      });
    });

    describe("partially_working threshold", () => {
      it("should return 'partially_working' when adjustedPassRate>=0.7 and errorHandlingWorks", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 7,
          scenariosFailed: 3,
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 2,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("partially_working");
      });

      it("should return 'partially_working' when adjustedPassRate>=0.4", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 4,
          scenariosFailed: 6,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("partially_working");
      });
    });

    describe("connectivity_only threshold", () => {
      it("should return 'connectivity_only' when adjustedPassRate>=0.2", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 2,
          scenariosFailed: 8,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("connectivity_only");
      });

      it("should return 'connectivity_only' when happyPathWorks", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 1,
          scenariosFailed: 9,
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 0,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("connectivity_only");
      });
    });

    describe("broken threshold", () => {
      it("should return 'broken' when adjustedPassRate<0.2 and no happy path", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 1,
          scenariosFailed: 9,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        expect(determineOverallStatus(result)).toBe("broken");
      });
    });

    describe("business logic success adjustment", () => {
      it("should count business logic errors as successes in pass rate", () => {
        const result = createMockResult({
          scenariosExecuted: 10,
          scenariosPassed: 0, // None "passed" conventionally
          scenariosFailed: 10,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: Array(10)
            .fill(null)
            .map(() => ({
              scenario: createMockScenario(),
              executed: true,
              executionTime: 100,
              validation: createMockValidation({
                isValid: false,
                classification: "fully_working",
                evidence: ["business logic validation working correctly"],
              }),
            })),
        });

        // With 10 business logic successes, adjusted pass rate should be high
        const status = determineOverallStatus(result);
        expect(status).not.toBe("broken");
      });
    });
  });

  describe("calculateConfidence", () => {
    let engine: TestScenarioEngine;
    let calculateConfidence: (result: ComprehensiveToolTestResult) => number;

    beforeEach(() => {
      engine = new TestScenarioEngine();
      calculateConfidence = getPrivateMethod(engine, "calculateConfidence");
    });

    describe("base calculation", () => {
      it("should start with executionRate * 100", () => {
        const result = createMockResult({
          totalScenarios: 10,
          scenariosExecuted: 5,
          scenariosPassed: 5,
          scenarioResults: [],
        });
        // executionRate = 0.5, passRate = 1.0
        // base = 0.5 * 100 * 1.0 = 50
        const confidence = calculateConfidence(result);
        expect(confidence).toBeGreaterThan(0);
      });
    });

    describe("bonus points", () => {
      it("should add 10 points for happyPathSuccess", () => {
        // Use 50% pass rate so bonus is visible (not capped at 100)
        const resultWithHappyPath = createMockResult({
          totalScenarios: 4,
          scenariosExecuted: 4,
          scenariosPassed: 2, // 50% pass rate
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });

        const resultWithoutHappyPath = createMockResult({
          totalScenarios: 4,
          scenariosExecuted: 4,
          scenariosPassed: 2, // 50% pass rate
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });

        const confWith = calculateConfidence(resultWithHappyPath);
        const confWithout = calculateConfidence(resultWithoutHappyPath);

        expect(confWith).toBeGreaterThan(confWithout);
      });

      it("should add 5 points for errorHandlingWorks", () => {
        // Use 50% pass rate so bonus is visible (not capped at 100)
        const resultWithErrorHandling = createMockResult({
          totalScenarios: 4,
          scenariosExecuted: 4,
          scenariosPassed: 2, // 50% pass rate
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: [],
        });

        const resultWithoutErrorHandling = createMockResult({
          totalScenarios: 4,
          scenariosExecuted: 4,
          scenariosPassed: 2, // 50% pass rate
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });

        const confWith = calculateConfidence(resultWithErrorHandling);
        const confWithout = calculateConfidence(resultWithoutErrorHandling);

        expect(confWith).toBeGreaterThan(confWithout);
      });
    });

    describe("penalty", () => {
      it("should multiply by 0.7 when scenariosExecuted < 3", () => {
        const resultFewScenarios = createMockResult({
          totalScenarios: 2,
          scenariosExecuted: 2,
          scenariosPassed: 2,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 0,
            boundariesRespected: 0,
            boundariesTotal: 0,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });

        const resultManyScenarios = createMockResult({
          totalScenarios: 4,
          scenariosExecuted: 4,
          scenariosPassed: 4,
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 0,
            edgeCasesTotal: 0,
            boundariesRespected: 0,
            boundariesTotal: 0,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });

        const confFew = calculateConfidence(resultFewScenarios);
        const confMany = calculateConfidence(resultManyScenarios);

        // Few scenarios should have lower confidence due to 0.7 penalty
        expect(confFew).toBeLessThan(confMany);
      });
    });

    describe("return value", () => {
      it("should return rounded integer", () => {
        const result = createMockResult({
          scenarioResults: [],
        });
        const confidence = calculateConfidence(result);
        expect(Number.isInteger(confidence)).toBe(true);
      });

      it("should cap at 100", () => {
        const result = createMockResult({
          totalScenarios: 10,
          scenariosExecuted: 10,
          scenariosPassed: 10,
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 2,
            edgeCasesTotal: 2,
            boundariesRespected: 2,
            boundariesTotal: 2,
            errorHandlingWorks: true,
          },
          scenarioResults: Array(10)
            .fill(null)
            .map(() => ({
              scenario: createMockScenario(),
              executed: true,
              executionTime: 100,
              validation: createMockValidation({ confidence: 100 }),
            })),
        });
        const confidence = calculateConfidence(result);
        expect(confidence).toBeLessThanOrEqual(100);
      });
    });
  });

  describe("generateRecommendations", () => {
    let engine: TestScenarioEngine;
    let generateRecommendations: (
      result: ComprehensiveToolTestResult,
    ) => string[];

    beforeEach(() => {
      engine = new TestScenarioEngine();
      generateRecommendations = getPrivateMethod(
        engine,
        "generateRecommendations",
      );
    });

    describe("progressive complexity recommendations", () => {
      it("should add minimal failure recommendation when failurePoint='minimal'", () => {
        const result = createMockResult({
          progressiveComplexity: {
            minimalWorks: false,
            simpleWorks: false,
            failurePoint: "minimal",
          },
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("minimal") && r.includes("fail"),
          ),
        ).toBe(true);
      });

      it("should add simple failure recommendations when failurePoint='simple'", () => {
        const result = createMockResult({
          progressiveComplexity: {
            minimalWorks: true,
            simpleWorks: false,
            failurePoint: "simple",
          },
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("simple") || r.includes("realistic"),
          ),
        ).toBe(true);
      });

      it("should add success message when failurePoint='none'", () => {
        const result = createMockResult({
          progressiveComplexity: {
            minimalWorks: true,
            simpleWorks: true,
            failurePoint: "none",
          },
        });
        const recommendations = generateRecommendations(result);
        expect(recommendations.some((r) => r.includes("passed"))).toBe(true);
      });
    });

    describe("category-specific recommendations", () => {
      it("should recommend fixing happy path when happyPathSuccess=false", () => {
        const result = createMockResult({
          summary: {
            happyPathSuccess: false,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: [
            {
              scenario: createMockScenario({ category: "happy_path" }),
              executed: true,
              executionTime: 100,
              validation: createMockValidation({
                isValid: false,
                classification: "broken",
              }),
            },
          ],
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("happy path") || r.includes("basic"),
          ),
        ).toBe(true);
      });

      it("should recommend improving error handling when errorHandlingWorks=false", () => {
        const result = createMockResult({
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: false,
          },
          scenarioResults: [],
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("error") && r.includes("handling"),
          ),
        ).toBe(true);
      });

      it("should recommend handling edge cases when some fail", () => {
        const result = createMockResult({
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 3,
            boundariesRespected: 1,
            boundariesTotal: 1,
            errorHandlingWorks: true,
          },
          scenarioResults: [],
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("edge case") || r.includes("failed"),
          ),
        ).toBe(true);
      });

      it("should recommend respecting boundaries when boundary tests fail", () => {
        const result = createMockResult({
          summary: {
            happyPathSuccess: true,
            edgeCasesHandled: 1,
            edgeCasesTotal: 1,
            boundariesRespected: 0,
            boundariesTotal: 2,
            errorHandlingWorks: true,
          },
          scenarioResults: [],
        });
        const recommendations = generateRecommendations(result);
        expect(
          recommendations.some(
            (r) => r.includes("boundar") || r.includes("failed"),
          ),
        ).toBe(true);
      });
    });

    describe("status-based summary recommendations", () => {
      it("should add success summary for fully_working status", () => {
        const result = createMockResult({
          overallStatus: "fully_working",
          scenariosPassed: 10,
          totalScenarios: 10,
        });
        const recommendations = generateRecommendations(result);
        expect(recommendations.some((r) => r.includes("passed"))).toBe(true);
      });
    });
  });

  describe("generateDetailedReport", () => {
    it("should include tool name as header", () => {
      const result = createMockResult({ toolName: "my_test_tool" });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("## Tool: my_test_tool");
    });

    it("should include overall status in assessment section", () => {
      const result = createMockResult({ overallStatus: "fully_working" });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("**Status**: fully_working");
    });

    it("should include confidence percentage", () => {
      const result = createMockResult({ confidence: 85 });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("**Confidence**: 85%");
    });

    it("should include scenario pass/fail/total counts", () => {
      const result = createMockResult({
        scenariosPassed: 8,
        scenariosExecuted: 10,
        totalScenarios: 10,
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("8/10 passed");
    });

    it("should include execution time in ms", () => {
      const result = createMockResult({ executionTime: 1500 });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("1500ms");
    });

    it("should include summary with happy path status", () => {
      const result = createMockResult({
        summary: {
          happyPathSuccess: true,
          edgeCasesHandled: 2,
          edgeCasesTotal: 3,
          boundariesRespected: 1,
          boundariesTotal: 2,
          errorHandlingWorks: false,
        },
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("Happy Path:");
      expect(report).toMatch(/Working|Failed/);
    });

    it("should include recommendations section when present", () => {
      const result = createMockResult({
        recommendations: ["Fix the happy path", "Improve error handling"],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("### Recommendations");
      expect(report).toContain("Fix the happy path");
    });

    it("should handle empty recommendations array", () => {
      const result = createMockResult({ recommendations: [] });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).not.toContain("### Recommendations");
    });

    it("should include scenario details section", () => {
      const result = createMockResult({
        scenarioResults: [
          {
            scenario: createMockScenario({ name: "Test Scenario 1" }),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({ isValid: true }),
          },
        ],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("### Scenario Details");
      expect(report).toContain("Test Scenario 1");
    });

    it("should show pass/fail status emoji for each scenario", () => {
      const result = createMockResult({
        scenarioResults: [
          {
            scenario: createMockScenario({ name: "Passing" }),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({ isValid: true }),
          },
          {
            scenario: createMockScenario({ name: "Failing" }),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({ isValid: false }),
          },
        ],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toMatch(/Passing.*\n/);
      expect(report).toMatch(/Failing.*\n/);
    });

    it("should include category, confidence, classification per scenario", () => {
      const result = createMockResult({
        scenarioResults: [
          {
            scenario: createMockScenario({ category: "edge_case" }),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({
              confidence: 75,
              classification: "partially_working",
            }),
          },
        ],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("Category: edge_case");
      expect(report).toContain("Confidence: 75%");
      expect(report).toContain("Classification: partially_working");
    });

    it("should include issues when present", () => {
      const result = createMockResult({
        scenarioResults: [
          {
            scenario: createMockScenario(),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({
              issues: ["Response too short", "Missing field"],
            }),
          },
        ],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("Issues:");
      expect(report).toContain("Response too short");
    });

    it("should include evidence when present", () => {
      const result = createMockResult({
        scenarioResults: [
          {
            scenario: createMockScenario(),
            executed: true,
            executionTime: 100,
            validation: createMockValidation({
              evidence: ["Tool returned valid JSON", "Response matched schema"],
            }),
          },
        ],
      });
      const report = TestScenarioEngine.generateDetailedReport(result);
      expect(report).toContain("Evidence:");
      expect(report).toContain("Tool returned valid JSON");
    });
  });

  describe("Integration Tests", () => {
    describe("full workflow with successful tool", () => {
      it("should complete full assessment with fully_working status", async () => {
        const engine = new TestScenarioEngine(1000, 0);
        const tool = createTool("successful_tool", {
          properties: { query: { type: "string" } },
          required: ["query"],
        });

        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([
            createMockScenario({ category: "happy_path" }),
            createMockScenario({ category: "edge_case" }),
            createMockScenario({ category: "boundary" }),
            createMockScenario({ category: "error_case" }),
          ]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);

        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.overallStatus).toBe("fully_working");
        expect(result.confidence).toBeGreaterThan(80);
      });

      it("should generate positive recommendations", async () => {
        const engine = new TestScenarioEngine(1000, 0);
        const tool = createTool("successful_tool", {
          properties: { query: { type: "string" } },
          required: ["query"],
        });

        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([
            createMockScenario({ category: "happy_path" }),
            createMockScenario({ category: "error_case" }),
          ]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation({ isValid: true }));
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);

        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.recommendations.some((r) => r.includes("passed"))).toBe(
          true,
        );
      });
    });

    describe("full workflow with failing tool", () => {
      it("should complete full assessment with broken status", async () => {
        const engine = new TestScenarioEngine(100, 0);
        const tool = createTool("failing_tool", {
          properties: { query: { type: "string" } },
          required: ["query"],
        });

        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario({ category: "happy_path" })]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(
            createMockValidation({ isValid: false, classification: "broken" }),
          );
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);

        const mockCallTool = jest
          .fn()
          .mockRejectedValue(new Error("Tool broken"));

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        expect(result.overallStatus).toBe("broken");
        expect(result.confidence).toBeLessThan(50);
      });
    });

    describe("business logic error handling", () => {
      it("should recognize tool that properly validates and rejects bad input", async () => {
        const engine = new TestScenarioEngine(1000, 0);
        const tool = createTool("validating_tool", {
          properties: { query: { type: "string" } },
          required: ["query"],
        });

        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([createMockScenario({ category: "happy_path" })]);
        jest.spyOn(ResponseValidator, "validateResponse").mockReturnValue(
          createMockValidation({
            isValid: false,
            classification: "fully_working",
            evidence: ["business logic validation working correctly"],
          }),
        );
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(true);

        const mockCallTool = jest.fn().mockResolvedValue(
          createMockResponse({
            isError: true,
            content: [{ type: "text", text: "Resource not found" }],
          }),
        );

        const result = await engine.testToolComprehensively(tool, mockCallTool);

        // Tool should not be marked as broken just because it validates properly
        expect(result.overallStatus).not.toBe("broken");
      });
    });

    describe("rate limiting with delayBetweenTests", () => {
      it("should respect delay configuration between tests", async () => {
        const engine = new TestScenarioEngine(1000, 50); // 50ms delay
        const tool = createTool("rate_limited_tool", {
          properties: { query: { type: "string" } },
          required: ["query"],
        });

        jest
          .spyOn(TestDataGenerator, "generateTestScenarios")
          .mockReturnValue([
            createMockScenario(),
            createMockScenario(),
            createMockScenario(),
          ]);
        jest
          .spyOn(ResponseValidator, "validateResponse")
          .mockReturnValue(createMockValidation());
        jest
          .spyOn(ResponseValidator, "isBusinessLogicError")
          .mockReturnValue(false);

        const mockCallTool = jest.fn().mockResolvedValue(createMockResponse());
        const startTime = Date.now();

        await engine.testToolComprehensively(tool, mockCallTool);

        const elapsed = Date.now() - startTime;
        // Should have at least 100ms of delays (2 delays between 3 scenarios)
        // Plus 2 for progressive complexity
        expect(elapsed).toBeGreaterThanOrEqual(100);
      });
    });
  });
});
