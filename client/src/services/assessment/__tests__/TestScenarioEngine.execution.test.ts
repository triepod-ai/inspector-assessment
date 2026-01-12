/**
 * TestScenarioEngine Execution Tests
 *
 * Tests for testProgressiveComplexity, executeScenario, and testToolComprehensively methods
 */

import { TestScenarioEngine, ScenarioTestResult } from "../TestScenarioEngine";
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

describe("TestScenarioEngine", () => {
  describe("testProgressiveComplexity", () => {
    let engine: TestScenarioEngine;

    beforeEach(() => {
      engine = new TestScenarioEngine(100, 0); // Short timeout for tests
    });

    afterEach(() => {
      jest.clearAllMocks();
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
});
