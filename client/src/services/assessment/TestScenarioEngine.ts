/**
 * Test Scenario Engine for Multi-Scenario MCP Tool Testing
 * Orchestrates comprehensive testing with multiple scenarios per tool
 */

import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator, TestScenario } from "./TestDataGenerator";
import {
  ResponseValidator,
  ValidationResult,
  ValidationContext,
} from "./ResponseValidator";

export interface ScenarioTestResult {
  scenario: TestScenario;
  executed: boolean;
  executionTime: number;
  response?: CompatibilityCallToolResult;
  error?: string;
  validation: ValidationResult;
}

export interface ComprehensiveToolTestResult {
  toolName: string;
  tested: boolean;
  totalScenarios: number;
  scenariosExecuted: number;
  scenariosPassed: number;
  scenariosFailed: number;
  overallStatus:
    | "fully_working"
    | "partially_working"
    | "connectivity_only"
    | "broken"
    | "untested";
  confidence: number; // 0-100
  executionTime: number;
  scenarioResults: ScenarioTestResult[];
  summary: {
    happyPathSuccess: boolean;
    edgeCasesHandled: number;
    edgeCasesTotal: number;
    boundariesRespected: number;
    boundariesTotal: number;
    errorHandlingWorks: boolean;
  };
  // Progressive complexity analysis (diagnostic testing only)
  // Note: Typical and complex scenarios validated separately in multi-scenario testing
  progressiveComplexity?: {
    minimalWorks: boolean;
    simpleWorks: boolean;
    failurePoint?: "minimal" | "simple" | "none";
  };
  recommendations: string[];
}

export class TestScenarioEngine {
  private testTimeout: number;
  private delayBetweenTests: number;

  constructor(testTimeout: number = 5000, delayBetweenTests: number = 0) {
    this.testTimeout = testTimeout;
    this.delayBetweenTests = delayBetweenTests;
  }

  /**
   * Sleep for specified milliseconds (for rate limiting)
   */
  private async sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Test tool with progressive complexity to identify failure points
   */
  async testProgressiveComplexity(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ComprehensiveToolTestResult["progressiveComplexity"]> {
    const result: ComprehensiveToolTestResult["progressiveComplexity"] = {
      minimalWorks: false,
      simpleWorks: false,
      failurePoint: undefined,
    };

    // Test 1: Minimal complexity - absolute minimum params
    const minimalParams = this.generateMinimalParams(tool);
    try {
      const minimalResult = await Promise.race([
        callTool(tool.name, minimalParams),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Timeout")), this.testTimeout),
        ),
      ]);

      // Tool works if it returns successfully OR if it returns a business logic error
      // (business logic errors indicate the tool is validating correctly)
      const isBusinessError = minimalResult.isError
        ? ResponseValidator.isBusinessLogicError({
            tool,
            input: minimalParams,
            response: minimalResult,
            scenarioCategory: "happy_path",
          } as ValidationContext)
        : false;

      result.minimalWorks = !minimalResult.isError || isBusinessError;
    } catch {
      result.minimalWorks = false;
      result.failurePoint = "minimal";
      return result; // Stop if minimal fails
    }

    // Test 2: Simple complexity - one required param with simple value
    const simpleParams = this.generateSimpleParams(tool);
    try {
      const simpleResult = await Promise.race([
        callTool(tool.name, simpleParams),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Timeout")), this.testTimeout),
        ),
      ]);

      // Tool works if it returns successfully OR if it returns a business logic error
      const isBusinessError = simpleResult.isError
        ? ResponseValidator.isBusinessLogicError({
            tool,
            input: simpleParams,
            response: simpleResult,
            scenarioCategory: "happy_path",
          } as ValidationContext)
        : false;

      result.simpleWorks = !simpleResult.isError || isBusinessError;
    } catch {
      result.simpleWorks = false;
      result.failurePoint = "simple";
      return result;
    }

    // Test 3 & 4: REMOVED (redundant with Happy Path and Edge Case scenarios)
    // - Typical test duplicates Happy Path scenario (both use generateRealisticParams("typical"))
    // - Maximum test duplicates Edge Case - Maximum Values scenario
    // Progressive complexity now focuses on diagnostic testing (minimal → simple)
    // Full coverage provided by multi-scenario testing with validation
    result.failurePoint = "none"; // Passed minimal and simple tests

    return result;
  }

  /**
   * Generate minimal parameters (only absolutely required fields)
   */
  private generateMinimalParams(tool: Tool): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!tool.inputSchema || tool.inputSchema.type !== "object") {
      return params;
    }

    // Only include required fields with minimal values
    if (tool.inputSchema.required && tool.inputSchema.properties) {
      for (const requiredField of tool.inputSchema.required) {
        const schema = tool.inputSchema.properties[requiredField];
        if (schema) {
          params[requiredField] = this.generateMinimalValue(schema as any);
        }
      }
    }

    return params;
  }

  /**
   * Generate simple parameters (required fields with simple values)
   */
  private generateSimpleParams(tool: Tool): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!tool.inputSchema || tool.inputSchema.type !== "object") {
      return params;
    }

    // Include required fields with simple realistic values
    if (tool.inputSchema.required && tool.inputSchema.properties) {
      for (const requiredField of tool.inputSchema.required) {
        const schema = tool.inputSchema.properties[requiredField];
        if (schema) {
          params[requiredField] = TestDataGenerator.generateSingleValue(
            requiredField,
            schema as any,
          );
        }
      }
    }

    return params;
  }

  /**
   * Generate minimal value for a schema
   */
  private generateMinimalValue(schema: any): unknown {
    switch (schema.type) {
      case "string":
        return schema.enum ? schema.enum[0] : "test";
      case "number":
      case "integer":
        return schema.minimum ?? 1;
      case "boolean":
        return true;
      case "array":
        return [];
      case "object":
        return {};
      default:
        return null;
    }
  }

  /**
   * Run comprehensive testing for a tool with multiple scenarios
   */
  async testToolComprehensively(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ComprehensiveToolTestResult> {
    const startTime = Date.now();

    // First, run progressive complexity testing
    const progressiveComplexity = await this.testProgressiveComplexity(
      tool,
      callTool,
    );

    // Generate test scenarios
    const scenarios = TestDataGenerator.generateTestScenarios(tool);

    // Initialize result
    const result: ComprehensiveToolTestResult = {
      toolName: tool.name,
      tested: true,
      totalScenarios: scenarios.length,
      scenariosExecuted: 0,
      scenariosPassed: 0,
      scenariosFailed: 0,
      overallStatus: "untested",
      confidence: 0,
      executionTime: 0,
      scenarioResults: [],
      summary: {
        happyPathSuccess: false,
        edgeCasesHandled: 0,
        edgeCasesTotal: 0,
        boundariesRespected: 0,
        boundariesTotal: 0,
        errorHandlingWorks: false,
      },
      progressiveComplexity, // Add progressive complexity analysis
      recommendations: [],
    };

    // Execute each scenario
    for (const scenario of scenarios) {
      const scenarioResult = await this.executeScenario(
        tool,
        scenario,
        callTool,
      );
      result.scenarioResults.push(scenarioResult);

      // Add delay between tests to avoid rate limiting
      if (this.delayBetweenTests > 0) {
        await this.sleep(this.delayBetweenTests);
      }

      if (scenarioResult.executed) {
        result.scenariosExecuted++;

        // Update counters based on validation
        if (scenarioResult.validation.isValid) {
          result.scenariosPassed++;

          // Update summary based on category
          switch (scenario.category) {
            case "happy_path":
              result.summary.happyPathSuccess = true;
              break;
            case "edge_case":
              result.summary.edgeCasesHandled++;
              break;
            case "boundary":
              result.summary.boundariesRespected++;
              break;
            case "error_case":
              result.summary.errorHandlingWorks = true;
              break;
          }
        } else {
          result.scenariosFailed++;
        }

        // Count totals for categories
        switch (scenario.category) {
          case "edge_case":
            result.summary.edgeCasesTotal++;
            break;
          case "boundary":
            result.summary.boundariesTotal++;
            break;
        }
      }
    }

    // Calculate overall status and confidence
    result.executionTime = Date.now() - startTime;
    result.overallStatus = this.determineOverallStatus(result);
    result.confidence = this.calculateConfidence(result);
    result.recommendations = this.generateRecommendations(result);

    return result;
  }

  /**
   * Execute a single test scenario
   */
  private async executeScenario(
    tool: Tool,
    scenario: TestScenario,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ScenarioTestResult> {
    const startTime = Date.now();

    try {
      // Call tool with timeout
      const response = await Promise.race([
        callTool(tool.name, scenario.params),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Timeout")), this.testTimeout),
        ),
      ]);

      // Validate response
      const validationContext: ValidationContext = {
        tool,
        input: scenario.params,
        response,
        scenarioCategory: scenario.category,
      };

      const validation = ResponseValidator.validateResponse(validationContext);

      return {
        scenario,
        executed: true,
        executionTime: Date.now() - startTime,
        response,
        validation,
      };
    } catch (error) {
      // Handle execution errors
      const errorMessage =
        error instanceof Error ? error.message : String(error);

      // Create error validation result
      const validation: ValidationResult = {
        isValid: false,
        isError: true,
        confidence: 0,
        issues: [`Execution error: ${errorMessage}`],
        evidence: [],
        classification: "broken",
      };

      // For error scenarios, exceptions might be expected
      if (
        scenario.category === "error_case" &&
        !errorMessage.includes("Timeout")
      ) {
        validation.isValid = true;
        validation.confidence = 80;
        validation.classification = "partially_working";
        validation.evidence.push(
          "Tool properly rejected invalid input with exception",
        );
      }

      return {
        scenario,
        executed: true,
        executionTime: Date.now() - startTime,
        error: errorMessage,
        validation,
      };
    }
  }

  /**
   * Determine overall status based on scenario results
   */
  private determineOverallStatus(
    result: ComprehensiveToolTestResult,
  ): ComprehensiveToolTestResult["overallStatus"] {
    // If no scenarios executed, it's untested
    if (result.scenariosExecuted === 0) {
      return "untested";
    }

    // Check how many "failures" are actually business logic validation (tool working correctly)
    const businessLogicSuccesses = result.scenarioResults.filter(
      (sr) =>
        sr.validation.classification === "fully_working" &&
        sr.validation.evidence.some((e) => e.includes("business logic")),
    ).length;

    // Adjust pass rate to include business logic validation as successes
    const actualPasses = result.scenariosPassed + businessLogicSuccesses;
    const adjustedPassRate = Math.min(
      1,
      actualPasses / result.scenariosExecuted,
    );

    // Check critical scenarios
    const happyPathResult = result.scenarioResults.find(
      (sr) => sr.scenario.category === "happy_path",
    );
    const happyPathWorks =
      result.summary.happyPathSuccess ||
      happyPathResult?.validation.classification === "fully_working";
    const errorHandlingWorks = result.summary.errorHandlingWorks;

    // Determine status based on adjusted metrics
    if (adjustedPassRate >= 0.9 && errorHandlingWorks) {
      return "fully_working";
    } else if (adjustedPassRate >= 0.7 && errorHandlingWorks) {
      return "partially_working";
    } else if (
      adjustedPassRate >= 0.4 ||
      (errorHandlingWorks && businessLogicSuccesses > 0)
    ) {
      return "partially_working"; // Tool validates correctly even if test data is invalid
    } else if (
      adjustedPassRate >= 0.2 ||
      happyPathWorks ||
      businessLogicSuccesses > 0
    ) {
      return "connectivity_only";
    } else {
      return "broken";
    }
  }

  /**
   * Calculate confidence score based on test coverage and results
   */
  private calculateConfidence(result: ComprehensiveToolTestResult): number {
    // Base confidence on execution rate
    const executionRate = result.scenariosExecuted / result.totalScenarios;
    let confidence = executionRate * 100;

    // Adjust based on pass rate
    const passRate =
      result.scenariosExecuted > 0
        ? result.scenariosPassed / result.scenariosExecuted
        : 0;
    confidence *= passRate;

    // Bonus for critical scenarios
    if (result.summary.happyPathSuccess) {
      confidence = Math.min(100, confidence + 10);
    }
    if (result.summary.errorHandlingWorks) {
      confidence = Math.min(100, confidence + 5);
    }

    // Penalty for low test coverage
    if (result.scenariosExecuted < 3) {
      confidence *= 0.7;
    }

    // Consider validation confidence from individual scenarios
    if (result.scenarioResults.length > 0) {
      const avgValidationConfidence =
        result.scenarioResults
          .map((sr) => sr.validation.confidence)
          .reduce((a, b) => a + b, 0) / result.scenarioResults.length;

      // Weighted average with execution confidence
      confidence = confidence * 0.6 + avgValidationConfidence * 0.4;
    }

    return Math.round(confidence);
  }

  /**
   * Generate recommendations based on test results
   */
  private generateRecommendations(
    result: ComprehensiveToolTestResult,
  ): string[] {
    const recommendations: string[] = [];

    // Add progressive complexity insights
    if (result.progressiveComplexity) {
      const pc = result.progressiveComplexity;
      if (pc.failurePoint) {
        switch (pc.failurePoint) {
          case "minimal":
            recommendations.push(
              "⚠️ Tool fails with minimal parameters - check basic connectivity and required field handling",
            );
            break;
          case "simple":
            recommendations.push(
              "Tool works with minimal params but fails with simple realistic data",
            );
            recommendations.push(
              "Check parameter validation and type handling",
            );
            break;
          case "none":
            recommendations.push(
              "✅ Progressive complexity tests passed - see scenario results for typical and edge case coverage",
            );
            break;
        }
      }
    }

    // Check if most failures are business logic errors
    const businessErrorCount = result.scenarioResults.filter(
      (sr) =>
        sr.validation.classification === "fully_working" &&
        sr.validation.evidence.some((e) => e.includes("business logic")),
    ).length;

    if (businessErrorCount > result.scenariosFailed * 0.7) {
      // Most failures are actually business logic validation - tool is working!
      recommendations.push(
        "✅ Tool properly validates business logic and rejects invalid resources",
      );
      recommendations.push(
        "Note: Test failures are due to synthetic test data, not tool malfunction",
      );
      return recommendations;
    }

    // Check happy path
    if (!result.summary.happyPathSuccess) {
      // Check if happy path failed due to business logic
      const happyPathResult = result.scenarioResults.find(
        (sr) => sr.scenario.category === "happy_path",
      );
      if (happyPathResult?.validation.classification === "fully_working") {
        recommendations.push(
          "Tool works correctly but requires valid resource IDs (test data uses synthetic IDs)",
        );
      } else {
        recommendations.push(
          "Fix basic functionality - happy path scenario is failing",
        );
      }
    }

    // Check error handling
    if (!result.summary.errorHandlingWorks) {
      recommendations.push(
        "Improve error handling - tool doesn't properly validate inputs",
      );
    }

    // Check edge cases
    if (
      result.summary.edgeCasesTotal > 0 &&
      result.summary.edgeCasesHandled < result.summary.edgeCasesTotal
    ) {
      const failedEdgeCases =
        result.summary.edgeCasesTotal - result.summary.edgeCasesHandled;
      // Check if edge case failures are business logic errors
      const edgeCaseBusinessErrors = result.scenarioResults.filter(
        (sr) =>
          sr.scenario.category === "edge_case" &&
          sr.validation.classification === "fully_working",
      ).length;

      if (edgeCaseBusinessErrors > 0) {
        recommendations.push(
          `Edge cases properly validate business rules (${edgeCaseBusinessErrors} validation checks working)`,
        );
      } else {
        recommendations.push(
          `Handle edge cases better - ${failedEdgeCases} edge case(s) failed`,
        );
      }
    }

    // Check boundaries
    if (
      result.summary.boundariesTotal > 0 &&
      result.summary.boundariesRespected < result.summary.boundariesTotal
    ) {
      const failedBoundaries =
        result.summary.boundariesTotal - result.summary.boundariesRespected;
      recommendations.push(
        `Respect schema boundaries - ${failedBoundaries} boundary test(s) failed`,
      );
    }

    // Analyze specific validation issues
    const allIssues = new Set<string>();
    const allEvidence = new Set<string>();

    for (const scenarioResult of result.scenarioResults) {
      scenarioResult.validation.issues.forEach((issue) => allIssues.add(issue));
      scenarioResult.validation.evidence.forEach((evidence) =>
        allEvidence.add(evidence),
      );
    }

    // Add specific recommendations based on common issues
    if (allIssues.has("Response appears to just echo input")) {
      recommendations.push(
        "Implement actual functionality - tool is just echoing inputs",
      );
    }

    if (allIssues.has("Response content is too short to be meaningful")) {
      recommendations.push(
        "Return more substantial responses with actual data",
      );
    }

    if (allIssues.has("Response doesn't demonstrate clear functionality")) {
      recommendations.push(
        "Ensure responses clearly demonstrate the tool's intended purpose",
      );
    }

    // Add evidence-based assessment summary
    if (result.overallStatus === "fully_working") {
      recommendations.push(
        `✅ All test categories passed: ${result.scenariosPassed}/${result.totalScenarios} scenarios verified (happy path, edge cases, boundaries, error handling)`,
      );
    } else if (result.overallStatus === "partially_working") {
      const failedCount = result.scenariosFailed;
      const categories: string[] = [];
      if (!result.summary.happyPathSuccess) categories.push("happy path");
      if (result.summary.edgeCasesHandled < result.summary.edgeCasesTotal)
        categories.push("edge cases");
      if (result.summary.boundariesRespected < result.summary.boundariesTotal)
        categories.push("boundaries");
      if (!result.summary.errorHandlingWorks) categories.push("error handling");

      recommendations.push(
        `⚠️ Partial functionality: ${result.scenariosPassed}/${result.totalScenarios} scenarios passed, ${failedCount} failed. Issues in: ${categories.join(", ")}`,
      );
    }

    return recommendations;
  }

  /**
   * Generate a detailed report for a tool test
   */
  static generateDetailedReport(result: ComprehensiveToolTestResult): string {
    const lines: string[] = [
      `## Tool: ${result.toolName}`,
      ``,
      `### Overall Assessment`,
      `- **Status**: ${result.overallStatus}`,
      `- **Confidence**: ${result.confidence}%`,
      `- **Scenarios**: ${result.scenariosPassed}/${result.scenariosExecuted} passed (${result.totalScenarios} total)`,
      `- **Execution Time**: ${result.executionTime}ms`,
      ``,
      `### Summary`,
      `- Happy Path: ${result.summary.happyPathSuccess ? "✅ Working" : "❌ Failed"}`,
      `- Edge Cases: ${result.summary.edgeCasesHandled}/${result.summary.edgeCasesTotal} handled`,
      `- Boundaries: ${result.summary.boundariesRespected}/${result.summary.boundariesTotal} respected`,
      `- Error Handling: ${result.summary.errorHandlingWorks ? "✅ Working" : "❌ Failed"}`,
      ``,
    ];

    if (result.recommendations.length > 0) {
      lines.push(`### Recommendations`);
      result.recommendations.forEach((rec) => {
        lines.push(`- ${rec}`);
      });
      lines.push(``);
    }

    // Add scenario details
    lines.push(`### Scenario Details`);
    for (const scenarioResult of result.scenarioResults) {
      const status = scenarioResult.validation.isValid ? "✅" : "❌";
      lines.push(`- **${scenarioResult.scenario.name}** ${status}`);
      lines.push(`  - Category: ${scenarioResult.scenario.category}`);
      lines.push(`  - Confidence: ${scenarioResult.validation.confidence}%`);
      lines.push(
        `  - Classification: ${scenarioResult.validation.classification}`,
      );

      if (scenarioResult.validation.issues.length > 0) {
        lines.push(`  - Issues:`);
        scenarioResult.validation.issues.forEach((issue) => {
          lines.push(`    - ${issue}`);
        });
      }

      if (scenarioResult.validation.evidence.length > 0) {
        lines.push(`  - Evidence:`);
        scenarioResult.validation.evidence.forEach((evidence) => {
          lines.push(`    - ${evidence}`);
        });
      }
    }

    return lines.join("\n");
  }
}
