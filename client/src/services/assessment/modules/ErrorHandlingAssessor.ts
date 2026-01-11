/**
 * Error Handling Assessor Module
 * Tests error handling and input validation
 */

import {
  ErrorHandlingAssessment,
  ErrorHandlingMetrics,
  ErrorTestDetail,
  AssessmentStatus,
  JSONSchema7,
} from "@/lib/assessmentTypes";
import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { createConcurrencyLimit } from "../lib/concurrencyLimit";
import { ExecutionArtifactDetector } from "./securityTests/ExecutionArtifactDetector";
import { SafeResponseDetector } from "./securityTests/SafeResponseDetector";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

export class ErrorHandlingAssessor extends BaseAssessor {
  private executionDetector: ExecutionArtifactDetector;
  private safeResponseDetector: SafeResponseDetector;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.executionDetector = new ExecutionArtifactDetector();
    this.safeResponseDetector = new SafeResponseDetector();
  }

  async assess(context: AssessmentContext): Promise<ErrorHandlingAssessment> {
    this.logger.info("Starting error handling assessment");

    const testDetails: ErrorTestDetail[] = [];
    let passedTests = 0;

    // Test a sample of tools for error handling
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Parallel tool testing with concurrency limit
    const concurrency = this.config.maxParallelTests ?? 5;
    const limit = createConcurrencyLimit(concurrency, this.logger);

    this.logger.info(
      `Testing ${toolsToTest.length} tools for error handling with concurrency limit of ${concurrency}`,
    );

    const allToolTests = await Promise.all(
      toolsToTest.map((tool) =>
        limit(async () => {
          const toolTests = await this.testToolErrorHandling(
            tool,
            context.callTool,
          );

          // Add delay between tests to avoid rate limiting
          if (
            this.config.delayBetweenTests &&
            this.config.delayBetweenTests > 0
          ) {
            await this.sleep(this.config.delayBetweenTests);
          }

          return toolTests;
        }),
      ),
    );

    // Post-process results after parallel execution
    for (const toolTests of allToolTests) {
      testDetails.push(...toolTests);
      passedTests += toolTests.filter((t) => t.passed).length;
    }

    this.testCount = testDetails.length;

    const metrics = this.calculateMetrics(testDetails, passedTests);
    const status = this.determineErrorHandlingStatus(
      metrics,
      testDetails.length,
    );
    const explanation = this.generateExplanation(metrics, testDetails);
    const recommendations = this.generateRecommendations(metrics, testDetails);

    return {
      metrics,
      errorTests: testDetails,
      status,
      // Issue #28: Provide score at top level for downstream consumers (e.g., mcp-auditor)
      score: Math.round(metrics.mcpComplianceScore),
      explanation,
      recommendations,
    };
  }

  private selectToolsForTesting(tools: Tool[]): Tool[] {
    // Prefer new selectedToolsForTesting configuration
    // Note: undefined/null means "test all" (default), empty array [] means "test none" (explicit)
    if (this.config.selectedToolsForTesting !== undefined) {
      // Warn if deprecated maxToolsToTestForErrors is also set
      if (this.config.maxToolsToTestForErrors !== undefined) {
        this.logger.info(
          `Warning: Both selectedToolsForTesting and maxToolsToTestForErrors are set. ` +
            `Using selectedToolsForTesting (maxToolsToTestForErrors is deprecated).`,
        );
      }
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      const selectedTools = tools.filter((tool) =>
        selectedNames.has(tool.name),
      );

      // Empty array means user explicitly selected 0 tools
      if (this.config.selectedToolsForTesting.length === 0) {
        this.logger.info(
          `User selected 0 tools for error handling - skipping tests`,
        );
        return [];
      }

      // If no tools matched the names (config out of sync), log warning but respect selection
      if (selectedTools.length === 0) {
        this.logger.info(
          `Warning: No tools matched selection (${this.config.selectedToolsForTesting.join(", ")})`,
        );
        return [];
      }

      this.logger.info(
        `Testing ${selectedTools.length} selected tools out of ${tools.length} for error handling`,
      );
      return selectedTools;
    }

    // Backward compatibility: use old maxToolsToTestForErrors configuration
    const configLimit = this.config.maxToolsToTestForErrors;

    // If -1, test all tools
    if (configLimit === -1) {
      this.logger.info(`Testing all ${tools.length} tools for error handling`);
      return tools;
    }

    // Otherwise use the configured limit (default to 5 if not set)
    const maxTools = Math.min(configLimit ?? 5, tools.length);
    this.logger.info(
      `Testing ${maxTools} out of ${tools.length} tools for error handling`,
    );
    return tools.slice(0, maxTools);
  }

  private async testToolErrorHandling(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorTestDetail[]> {
    const tests: ErrorTestDetail[] = [];

    // Scored tests first (affect compliance score)
    // Test 1: Missing required parameters
    tests.push(await this.testMissingParameters(tool, callTool));

    // Test 2: Wrong parameter types
    tests.push(await this.testWrongTypes(tool, callTool));

    // Test 3: Excessive input size
    tests.push(await this.testExcessiveInput(tool, callTool));

    // Informational tests last (do not affect compliance score)
    // Test 4: Invalid parameter values (edge case handling)
    tests.push(await this.testInvalidValues(tool, callTool));

    return tests;
  }

  private async testMissingParameters(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorTestDetail> {
    const testInput = {}; // Empty params

    // Check if tool has any required parameters
    const schema = this.getToolSchema(tool);
    const hasRequiredParams =
      schema?.required &&
      Array.isArray(schema.required) &&
      schema.required.length > 0;

    // If no required parameters, this test should pass (empty input is valid)
    if (!hasRequiredParams) {
      return {
        toolName: tool.name,
        testType: "missing_required",
        testInput,
        expectedError: "Missing required parameters",
        actualResponse: {
          isError: false,
          errorMessage: undefined,
          rawResponse: "Skipped - no required parameters",
        },
        passed: true,
        reason: "No required parameters (tool correctly accepts empty input)",
      };
    }

    try {
      const response = await this.executeWithTimeout(
        callTool(tool.name, testInput),
        5000,
      );

      const isError = this.isErrorResponse(response);
      const errorInfo = this.extractErrorInfo(response);

      // More intelligent pattern matching for missing parameter errors
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const hasValidError =
        isError &&
        (messageLower.includes("required") ||
          messageLower.includes("missing") ||
          messageLower.includes("must provide") ||
          messageLower.includes("must be provided") ||
          messageLower.includes("is required") ||
          messageLower.includes("cannot be empty") ||
          messageLower.includes("must specify") ||
          // Also accept field-specific errors (even better!)
          /\b(query|field|parameter|argument|value|input)\b/i.test(
            errorInfo.message ?? "",
          ));

      return {
        toolName: tool.name,
        testType: "missing_required",
        testInput,
        expectedError: "Missing required parameters",
        actualResponse: {
          isError,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: response,
        },
        passed: hasValidError,
        reason: isError ? undefined : "Tool did not reject missing parameters",
      };
    } catch (error) {
      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("required") ||
        messageLower.includes("missing") ||
        messageLower.includes("parameter") ||
        messageLower.includes("must") ||
        messageLower.includes("invalid") ||
        messageLower.includes("validation") ||
        (errorInfo.message?.length ?? 0) > 20; // Longer messages are likely intentional

      return {
        toolName: tool.name,
        testType: "missing_required",
        testInput,
        expectedError: "Missing required parameters",
        actualResponse: {
          isError: true,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: error,
        },
        passed: isMeaningfulError,
        reason: isMeaningfulError ? undefined : "Generic unhandled exception",
      };
    }
  }

  private async testWrongTypes(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorTestDetail> {
    const schema = this.getToolSchema(tool);
    const testInput = this.generateWrongTypeParams(schema);

    try {
      const response = await this.executeWithTimeout(
        callTool(tool.name, testInput),
        5000,
      );

      const isError = this.isErrorResponse(response);
      const errorInfo = this.extractErrorInfo(response);

      // More intelligent pattern matching for type errors
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const hasValidError =
        isError &&
        (messageLower.includes("type") ||
          messageLower.includes("invalid") ||
          messageLower.includes("expected") ||
          messageLower.includes("must be") ||
          messageLower.includes("should be") ||
          messageLower.includes("cannot be") ||
          messageLower.includes("not a") ||
          messageLower.includes("received") ||
          messageLower.includes("string") ||
          messageLower.includes("number") ||
          messageLower.includes("boolean") ||
          messageLower.includes("array") ||
          messageLower.includes("object") ||
          // Also accept validation framework messages
          /\b(validation|validate|schema|format)\b/i.test(
            errorInfo.message ?? "",
          ));

      return {
        toolName: tool.name,
        testType: "wrong_type",
        testInput,
        expectedError: "Type validation error",
        actualResponse: {
          isError,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: response,
        },
        passed: hasValidError,
        reason: isError ? undefined : "Tool accepted wrong parameter types",
      };
    } catch (error) {
      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("type") ||
        messageLower.includes("invalid") ||
        messageLower.includes("expected") ||
        messageLower.includes("must be") ||
        messageLower.includes("validation") ||
        messageLower.includes("string") ||
        messageLower.includes("number") ||
        (errorInfo.message?.length ?? 0) > 20; // Longer messages are likely intentional

      return {
        toolName: tool.name,
        testType: "wrong_type",
        testInput,
        expectedError: "Type validation error",
        actualResponse: {
          isError: true,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: error,
        },
        passed: isMeaningfulError,
        reason: isMeaningfulError ? undefined : "Generic unhandled exception",
      };
    }
  }

  private async testInvalidValues(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorTestDetail> {
    const schema = this.getToolSchema(tool);
    const testInput = this.generateInvalidValueParams(schema);

    try {
      const response = await this.executeWithTimeout(
        callTool(tool.name, testInput),
        5000,
      );

      const isError = this.isErrorResponse(response);
      const errorInfo = this.extractErrorInfo(response);

      // For invalid values, any error response is good
      // The server is validating inputs properly
      return {
        toolName: tool.name,
        testType: "invalid_values",
        testInput,
        expectedError: "Invalid parameter values",
        actualResponse: {
          isError,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: response,
        },
        passed: isError,
        reason: isError ? undefined : "Tool accepted invalid values",
      };
    } catch (error) {
      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("invalid") ||
        messageLower.includes("not allowed") ||
        messageLower.includes("must") ||
        messageLower.includes("cannot") ||
        messageLower.includes("validation") ||
        messageLower.includes("error") ||
        (errorInfo.message?.length ?? 0) > 15; // Even shorter messages OK for invalid values

      return {
        toolName: tool.name,
        testType: "invalid_values",
        testInput,
        expectedError: "Invalid parameter values",
        actualResponse: {
          isError: true,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: error,
        },
        passed: isMeaningfulError,
        reason: isMeaningfulError ? undefined : "Generic unhandled exception",
      };
    }
  }

  private async testExcessiveInput(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorTestDetail> {
    const largeString = "x".repeat(100000); // 100KB string
    const testInput = this.generateParamsWithValue(tool, largeString);

    try {
      const response = await this.executeWithTimeout(
        callTool(tool.name, testInput),
        5000,
      );

      const isError = this.isErrorResponse(response);
      const errorInfo = this.extractErrorInfo(response);

      return {
        toolName: tool.name,
        testType: "excessive_input",
        testInput: { ...testInput, value: "[100KB string]" }, // Don't store huge string
        expectedError: "Input size limit exceeded",
        actualResponse: {
          isError,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: response ? "[response omitted]" : undefined,
        },
        passed: isError || response !== null, // Either error or handled gracefully
        reason:
          !isError && !response ? "Tool crashed on large input" : undefined,
      };
    } catch (error) {
      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("size") ||
        messageLower.includes("large") ||
        messageLower.includes("limit") ||
        messageLower.includes("exceed") ||
        messageLower.includes("too") ||
        messageLower.includes("maximum") ||
        (errorInfo.message?.length ?? 0) > 10; // Short messages OK for size limits

      return {
        toolName: tool.name,
        testType: "excessive_input",
        testInput: { value: "[100KB string]" },
        expectedError: "Input size limit exceeded",
        actualResponse: {
          isError: true,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: "[error details omitted]",
        },
        passed: isMeaningfulError,
        reason: isMeaningfulError ? undefined : "Generic unhandled exception",
      };
    }
  }

  private getToolSchema(tool: Tool): JSONSchema7 | null {
    if (!tool.inputSchema) return null;
    return typeof tool.inputSchema === "string"
      ? (this.safeJsonParse(tool.inputSchema) as JSONSchema7 | null)
      : (tool.inputSchema as JSONSchema7);
  }

  private generateWrongTypeParams(
    schema: JSONSchema7 | null,
  ): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!schema?.properties) return { value: 123 }; // Default wrong type

    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, JSONSchema7>,
    )) {
      // Intentionally use wrong types
      switch (prop.type) {
        case "string":
          params[key] = 123; // Number instead of string
          break;
        case "number":
        case "integer":
          params[key] = "not a number"; // String instead of number
          break;
        case "boolean":
          params[key] = "yes"; // String instead of boolean
          break;
        case "array":
          params[key] = "not an array"; // String instead of array
          break;
        case "object":
          params[key] = "not an object"; // String instead of object
          break;
      }
    }

    return params;
  }

  private generateInvalidValueParams(
    schema: JSONSchema7 | null,
  ): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!schema?.properties) return { value: null };

    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, JSONSchema7>,
    )) {
      if (prop.type === "string") {
        if (prop.enum) {
          params[key] = "not_in_enum"; // Value not in enum
        } else if (prop.format === "email") {
          params[key] = "invalid-email"; // Invalid email
        } else if (prop.format === "uri") {
          params[key] = "not://a/valid/uri"; // Invalid URI
        } else {
          params[key] = ""; // Empty string
        }
      } else if (prop.type === "number" || prop.type === "integer") {
        if (prop.minimum !== undefined) {
          params[key] = prop.minimum - 1; // Below minimum
        } else if (prop.maximum !== undefined) {
          params[key] = prop.maximum + 1; // Above maximum
        } else {
          params[key] = -999999; // Extreme value
        }
      }
    }

    return params;
  }

  private generateParamsWithValue(
    tool: Tool,
    value: unknown,
  ): Record<string, unknown> {
    const schema = this.getToolSchema(tool);
    const params: Record<string, unknown> = {};

    if (schema?.properties) {
      // Find first string parameter
      for (const [key, prop] of Object.entries(
        schema.properties as Record<string, JSONSchema7>,
      )) {
        if (prop.type === "string") {
          params[key] = value;
          break;
        }
      }
    }

    if (Object.keys(params).length === 0) {
      params.value = value; // Default parameter name
    }

    return params;
  }

  // isErrorResponse and extractErrorInfo moved to BaseAssessor for reuse across all assessors

  /**
   * Analyze invalid_values response to determine scoring impact
   * Issue #99: Contextual empty string validation scoring
   *
   * Classifications:
   * - safe_rejection: Tool rejected with error (no penalty)
   * - safe_reflection: Tool stored/echoed without executing (no penalty)
   * - defensive_programming: Tool handled gracefully (no penalty)
   * - execution_detected: Tool executed input (penalty)
   * - unknown: Cannot determine (partial penalty)
   */
  private analyzeInvalidValuesResponse(test: ErrorTestDetail): {
    shouldPenalize: boolean;
    penaltyAmount: number;
    classification: string;
    reason: string;
  } {
    const responseText = this.extractResponseTextSafe(
      test.actualResponse.rawResponse,
    );

    // Case 1: Tool rejected with error - best case (no penalty)
    if (test.actualResponse.isError) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_rejection",
        reason: "Tool properly rejected invalid input",
      };
    }

    // Case 2: Defensive programming patterns (no penalty)
    // Check BEFORE execution detection because patterns like "query returned 0"
    // might match execution indicators but are actually safe
    if (this.isDefensiveProgrammingResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "defensive_programming",
        reason: "Tool handled empty input defensively",
      };
    }

    // Case 3: Safe reflection patterns (no penalty)
    if (this.safeResponseDetector.isReflectionResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_reflection",
        reason: "Tool safely reflected input without execution",
      };
    }

    // Case 4: Check for execution evidence - VULNERABLE (full penalty)
    if (
      this.executionDetector.hasExecutionEvidence(responseText) ||
      this.executionDetector.detectExecutionArtifacts(responseText)
    ) {
      return {
        shouldPenalize: true,
        penaltyAmount: 100,
        classification: "execution_detected",
        reason: "Tool executed input without validation",
      };
    }

    // Case 5: Unknown - partial penalty for manual review
    return {
      shouldPenalize: true,
      penaltyAmount: 25,
      classification: "unknown",
      reason: "Unable to determine safety - manual review recommended",
    };
  }

  /**
   * Safely extract response text from various response formats
   */
  private extractResponseTextSafe(rawResponse: unknown): string {
    if (typeof rawResponse === "string") return rawResponse;
    if (rawResponse && typeof rawResponse === "object") {
      const resp = rawResponse as Record<string, unknown>;
      if (resp.content && Array.isArray(resp.content)) {
        return (resp.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" ? c.text : ""))
          .join(" ");
      }
      return JSON.stringify(rawResponse);
    }
    return String(rawResponse || "");
  }

  /**
   * Check for defensive programming patterns - tool accepted but caused no harm
   * Examples: "Deleted 0 keys", "No results found", "Query returned 0"
   */
  private isDefensiveProgrammingResponse(responseText: string): boolean {
    // Patterns for safe "no-op" responses where tool handled empty input gracefully
    // Use word boundaries (\b) to avoid matching numbers like "10" or "15"
    const patterns = [
      /deleted\s+0\s+(keys?|records?|rows?|items?)/i,
      /no\s+(results?|matches?|items?)\s+found/i,
      /\b0\s+items?\s+(deleted|updated|processed)/i, // \b prevents matching "10 items"
      /nothing\s+to\s+(delete|update|process)/i,
      /empty\s+(result|response|query)/i,
      /no\s+action\s+taken/i,
      /query\s+returned\s+0\b/i, // \b prevents matching "query returned 05" etc.
    ];
    return patterns.some((p) => p.test(responseText));
  }

  private calculateMetrics(
    tests: ErrorTestDetail[],
    _passed: number, // parameter kept for API compatibility
  ): ErrorHandlingMetrics {
    // Calculate enhanced score with bonus points for quality
    let enhancedScore = 0;
    let maxPossibleScore = 0;

    tests.forEach((test) => {
      // Issue #99: Contextual scoring for invalid_values tests
      // Instead of blanket exclusion, analyze response patterns to determine if
      // the tool safely handled empty strings (defensive programming, reflection)
      // or if it executed without validation (security concern).
      if (test.testType === "invalid_values") {
        const analysis = this.analyzeInvalidValuesResponse(test);
        if (!analysis.shouldPenalize) {
          // Safe response (rejection, reflection, or defensive programming)
          // Skip scoring to preserve backward compatibility for well-behaved tools
          return;
        }
        // Execution detected or unknown - include in scoring with penalty
        maxPossibleScore += 100;
        const scoreEarned = 100 * (1 - analysis.penaltyAmount / 100);
        enhancedScore += test.passed ? scoreEarned : 0;
        return;
      }

      maxPossibleScore += 100; // Base score for each test

      if (test.passed) {
        enhancedScore += 100; // Base points for passing

        // Extra points for specific field names in error
        if (
          /\b(query|field|parameter|argument|prop|key)\b/i.test(
            test.actualResponse.errorMessage ?? "",
          )
        ) {
          enhancedScore += 10;
          maxPossibleScore += 10;
        }

        // Extra points for helpful context
        if (
          test.actualResponse.errorMessage &&
          test.actualResponse.errorMessage.length > 30
        ) {
          enhancedScore += 5;
          maxPossibleScore += 5;
        }

        // Extra points for proper error codes
        if (test.actualResponse.errorCode) {
          enhancedScore += 5;
          maxPossibleScore += 5;
        }
      }
    });

    const score =
      maxPossibleScore > 0 ? (enhancedScore / maxPossibleScore) * 100 : 0;

    // Determine quality rating based on enhanced score
    let quality: ErrorHandlingMetrics["errorResponseQuality"];
    if (score >= 85) quality = "excellent";
    else if (score >= 70) quality = "good";
    else if (score >= 50) quality = "fair";
    else quality = "poor";

    // Check for proper error codes and messages (only among actual errors)
    const actualErrors = tests.filter((t) => t.actualResponse.isError);
    const errorsWithCodes = actualErrors.filter(
      (t) => t.actualResponse.errorCode !== undefined,
    ).length;
    const errorsWithMessages = actualErrors.filter(
      (t) =>
        t.actualResponse.errorMessage &&
        t.actualResponse.errorMessage.length > 10,
    ).length;

    // Handle case when no tests were run
    // Don't claim "Yes" for error codes/messages when we didn't test anything
    const hasProperErrorCodes =
      tests.length === 0
        ? false // No tests = can't assess
        : actualErrors.length === 0
          ? true // Tests run but no errors triggered = can't assess, assume OK
          : errorsWithCodes / actualErrors.length >= 0.5;

    const hasDescriptiveMessages =
      tests.length === 0
        ? false // No tests = can't assess
        : actualErrors.length === 0
          ? true // Tests run but no errors triggered = can't assess, assume OK
          : errorsWithMessages / actualErrors.length >= 0.5;

    const validatesInputs = tests
      .filter((t) => ["missing_required", "wrong_type"].includes(t.testType))
      .some((t) => t.passed);

    return {
      mcpComplianceScore: score,
      errorResponseQuality: quality,
      hasProperErrorCodes,
      hasDescriptiveMessages,
      validatesInputs,
      testDetails: tests,
    };
  }

  private determineErrorHandlingStatus(
    metrics: ErrorHandlingMetrics,
    testCount: number,
  ): AssessmentStatus {
    // If no tests were run, we can't determine error handling status
    if (testCount === 0) return "NEED_MORE_INFO";

    // More lenient thresholds that recognize good error handling
    if (metrics.mcpComplianceScore >= 70) return "PASS";
    if (metrics.mcpComplianceScore >= 40) return "NEED_MORE_INFO";
    return "FAIL";
  }

  private generateExplanation(
    metrics: ErrorHandlingMetrics,
    tests: ErrorTestDetail[],
  ): string {
    // Handle case when no tools were tested
    if (tests.length === 0) {
      return "No tools selected for error handling testing. Select tools to run error handling assessments.";
    }

    const parts: string[] = [];

    // Filter out invalid_values for scoring context
    const scoredTests = tests.filter((t) => t.testType !== "invalid_values");
    const passedScoredTests = scoredTests.filter((t) => t.passed).length;
    const totalScoredTests = scoredTests.length;

    parts.push(
      `Error handling compliance score: ${metrics.mcpComplianceScore.toFixed(1)}% (${passedScoredTests}/${totalScoredTests} scored tests passed).`,
    );

    // Count how many types of validation are working (only scored tests)
    const validationTypes: string[] = [];
    if (tests.some((t) => t.testType === "missing_required" && t.passed)) {
      validationTypes.push("missing parameter validation");
    }
    if (tests.some((t) => t.testType === "wrong_type" && t.passed)) {
      validationTypes.push("type validation");
    }
    if (tests.some((t) => t.testType === "excessive_input" && t.passed)) {
      validationTypes.push("input size validation");
    }

    // Add informational note about invalid_values tests
    const invalidValuesTests = tests.filter(
      (t) => t.testType === "invalid_values",
    );
    if (invalidValuesTests.length > 0) {
      const passedInvalidValues = invalidValuesTests.filter(
        (t) => t.passed,
      ).length;
      validationTypes.push(
        `edge case handling (${passedInvalidValues}/${invalidValuesTests.length} - informational only)`,
      );
    }

    if (validationTypes.length > 0) {
      const scoredValidationCount = validationTypes.filter(
        (v) => !v.includes("informational only"),
      ).length;
      parts.push(
        `Implements ${scoredValidationCount}/3 validation types (scored): ${validationTypes.join(", ")}.`,
      );
    } else {
      parts.push("No input validation detected.");
    }

    parts.push(
      `${metrics.hasDescriptiveMessages ? "Has" : "Missing"} descriptive error messages,`,
      `${metrics.hasProperErrorCodes ? "uses" : "missing"} proper error codes.`,
    );

    // Count tools tested
    const toolsTested = [...new Set(tests.map((t) => t.toolName))].length;
    const totalTests = tests.length;
    parts.push(
      `Tested ${toolsTested} tools with ${totalScoredTests} scored scenarios (${totalTests} total including informational).`,
    );

    return parts.join(" ");
  }

  private generateRecommendations(
    metrics: ErrorHandlingMetrics,
    tests: ErrorTestDetail[],
  ): string[] {
    const recommendations: string[] = [];

    if (!metrics.hasProperErrorCodes) {
      recommendations.push(
        "Implement consistent error codes for different error types",
      );
    }

    if (!metrics.hasDescriptiveMessages) {
      recommendations.push(
        "Provide descriptive error messages that help users understand the issue",
      );
    }

    if (!metrics.validatesInputs) {
      recommendations.push(
        "Implement proper input validation for all parameters",
      );
    }

    const failedTypes = [
      ...new Set(tests.filter((t) => !t.passed).map((t) => t.testType)),
    ];

    if (failedTypes.includes("missing_required")) {
      recommendations.push("Validate and report missing required parameters");
    }

    if (failedTypes.includes("wrong_type")) {
      recommendations.push("Implement type checking for all parameters");
    }

    if (failedTypes.includes("excessive_input")) {
      recommendations.push(
        "Implement input size limits and handle large inputs gracefully",
      );
    }

    return recommendations;
  }
}
