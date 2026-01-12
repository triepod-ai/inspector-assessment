/**
 * TestScenarioEngine Status Tests
 *
 * Tests for determineOverallStatus, calculateConfidence, and generateRecommendations methods
 */

import {
  TestScenarioEngine,
  ComprehensiveToolTestResult,
} from "../TestScenarioEngine";
import { TestScenario } from "../TestDataGenerator";
import { ValidationResult } from "../ResponseValidator";

// Helper to access private methods
const getPrivateMethod = <T>(instance: T, methodName: string) => {
  return (instance as any)[methodName].bind(instance);
};

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

    afterEach(() => {
      jest.clearAllMocks();
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
});
