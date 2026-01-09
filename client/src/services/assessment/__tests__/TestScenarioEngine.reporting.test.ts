/**
 * TestScenarioEngine Reporting Tests
 *
 * Tests for generateDetailedReport static method
 */

import {
  TestScenarioEngine,
  ComprehensiveToolTestResult,
} from "../TestScenarioEngine";
import { TestScenario } from "../TestDataGenerator";
import { ValidationResult } from "../ResponseValidator";

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
});
