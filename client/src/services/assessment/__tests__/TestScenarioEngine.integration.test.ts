/**
 * TestScenarioEngine Integration Tests
 *
 * End-to-end workflow tests for TestScenarioEngine
 */

import { TestScenarioEngine } from "../TestScenarioEngine";
import { TestDataGenerator, TestScenario } from "../TestDataGenerator";
import { ResponseValidator, ValidationResult } from "../ResponseValidator";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

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
  afterEach(() => {
    jest.restoreAllMocks();
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
