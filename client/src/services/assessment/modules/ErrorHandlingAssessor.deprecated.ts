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
import { ValidationSummaryProgress } from "@/lib/assessment/progressTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { createConcurrencyLimit } from "../lib/concurrencyLimit";
import { ExecutionArtifactDetector } from "./securityTests/ExecutionArtifactDetector";
import { SafeResponseDetector } from "./securityTests/SafeResponseDetector";
import { ErrorClassifier } from "./securityTests/ErrorClassifier";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

export class ErrorHandlingAssessor extends BaseAssessor {
  private executionDetector: ExecutionArtifactDetector;
  private safeResponseDetector: SafeResponseDetector;
  private errorClassifier: ErrorClassifier;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.executionDetector = new ExecutionArtifactDetector();
    this.safeResponseDetector = new SafeResponseDetector();
    this.errorClassifier = new ErrorClassifier();
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
            context,
          );

          // Emit per-tool validation summary for auditor UI (Phase 7)
          if (context.onProgress) {
            // Count failures by test type (failed = tool didn't reject invalid input)
            const wrongType = toolTests.filter(
              (t) => t.testType === "wrong_type" && !t.passed,
            ).length;
            const missingRequired = toolTests.filter(
              (t) => t.testType === "missing_required" && !t.passed,
            ).length;
            const invalidValues = toolTests.filter(
              (t) => t.testType === "invalid_values" && !t.passed,
            ).length;

            const summaryEvent: ValidationSummaryProgress = {
              type: "validation_summary",
              tool: tool.name,
              wrongType,
              missingRequired,
              extraParams: 0, // Not tested in current implementation
              nullValues: 0, // Not tested explicitly
              invalidValues,
            };
            context.onProgress(summaryEvent);
          }

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

    // Issue #153: Calculate test execution metadata for score validation
    // Count connection errors from test results (tests with isConnectionError flag)
    const connectionErrorTests = testDetails.filter((t) => t.isConnectionError);
    const connectionErrorCount = connectionErrorTests.length;
    const validTestsCompleted = testDetails.length - connectionErrorCount;
    const totalTestsAttempted = testDetails.length;
    const testCoveragePercent =
      totalTestsAttempted > 0
        ? Math.round((validTestsCompleted / totalTestsAttempted) * 100)
        : 0;

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
      // Issue #153: Test execution metadata for score validation
      testExecutionMetadata: {
        totalTestsAttempted,
        validTestsCompleted,
        connectionErrorCount,
        testCoveragePercent,
      },
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
    context: AssessmentContext,
  ): Promise<ErrorTestDetail[]> {
    const tests: ErrorTestDetail[] = [];

    // Issue #168: Check if tool depends on external API
    const isExternalAPI =
      context.externalAPIDependencies?.toolsWithExternalAPIDependency.has(
        tool.name,
      ) ?? false;

    // Scored tests first (affect compliance score)
    // Test 1: Missing required parameters
    tests.push(await this.testMissingParameters(tool, callTool, isExternalAPI));

    // Test 2: Wrong parameter types
    tests.push(await this.testWrongTypes(tool, callTool, isExternalAPI));

    // Test 3: Excessive input size
    tests.push(await this.testExcessiveInput(tool, callTool, isExternalAPI));

    // Informational tests last (do not affect compliance score)
    // Test 4: Invalid parameter values (edge case handling)
    tests.push(await this.testInvalidValues(tool, callTool, isExternalAPI));

    return tests;
  }

  private async testMissingParameters(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    isExternalAPI: boolean = false,
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

      // Issue #168: For external API tools, check if error is an external service error
      // External service errors should be treated as passed (validation can't be tested)
      if (isExternalAPI && isError && this.isExternalServiceError(errorInfo)) {
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
          passed: true,
          reason:
            "External API service error (validation cannot be tested when service unavailable)",
        };
      }

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
      // Issue #153: Check for connection errors first - these should NOT count as passed
      if (this.errorClassifier.isConnectionErrorFromException(error)) {
        const errorInfo = this.extractErrorInfo(error);
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
          passed: false,
          reason: "Connection error - unable to test",
          isConnectionError: true,
        };
      }

      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("required") ||
        messageLower.includes("missing") ||
        messageLower.includes("parameter") ||
        messageLower.includes("must") ||
        messageLower.includes("invalid") ||
        messageLower.includes("validation");
      // Removed: (errorInfo.message?.length ?? 0) > 20 - this was causing false positives

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
    isExternalAPI: boolean = false,
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

      // Issue #168: For external API tools, check if error is an external service error
      if (isExternalAPI && isError && this.isExternalServiceError(errorInfo)) {
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
          passed: true,
          reason:
            "External API service error (validation cannot be tested when service unavailable)",
        };
      }

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
      // Issue #153: Check for connection errors first - these should NOT count as passed
      if (this.errorClassifier.isConnectionErrorFromException(error)) {
        const errorInfo = this.extractErrorInfo(error);
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
          passed: false,
          reason: "Connection error - unable to test",
          isConnectionError: true,
        };
      }

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
        messageLower.includes("number");
      // Removed: (errorInfo.message?.length ?? 0) > 20 - this was causing false positives

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
    isExternalAPI: boolean = false,
  ): Promise<ErrorTestDetail> {
    const schema = this.getToolSchema(tool);
    // Issue #173: Destructure metadata from new return type
    const {
      params: testInput,
      testedParameter,
      parameterIsRequired,
    } = this.generateInvalidValueParams(schema);

    try {
      const response = await this.executeWithTimeout(
        callTool(tool.name, testInput),
        5000,
      );

      const isError = this.isErrorResponse(response);
      const errorInfo = this.extractErrorInfo(response);
      const responseText = this.extractResponseTextSafe(response);

      // Issue #173: Detect suggestions in response
      const { hasSuggestions, suggestions } =
        this.detectSuggestionPatterns(responseText);

      // Issue #168: For external API tools, check if error is an external service error
      if (isExternalAPI && isError && this.isExternalServiceError(errorInfo)) {
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
          passed: true,
          reason:
            "External API service error (validation cannot be tested when service unavailable)",
          // Issue #173 metadata
          testedParameter,
          parameterIsRequired,
          hasSuggestions,
          suggestions: suggestions.length > 0 ? suggestions : undefined,
        };
      }

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
        // Issue #173 metadata
        testedParameter,
        parameterIsRequired,
        hasSuggestions,
        suggestions: suggestions.length > 0 ? suggestions : undefined,
      };
    } catch (error) {
      // Issue #153: Check for connection errors first - these should NOT count as passed
      if (this.errorClassifier.isConnectionErrorFromException(error)) {
        const errorInfo = this.extractErrorInfo(error);
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
          passed: false,
          reason: "Connection error - unable to test",
          isConnectionError: true,
          // Issue #173 metadata
          testedParameter,
          parameterIsRequired,
        };
      }

      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("invalid") ||
        messageLower.includes("not allowed") ||
        messageLower.includes("must") ||
        messageLower.includes("cannot") ||
        messageLower.includes("validation") ||
        messageLower.includes("error");
      // Removed: (errorInfo.message?.length ?? 0) > 15 - this was causing false positives

      // Issue #173: Detect suggestions in error message
      const { hasSuggestions, suggestions } =
        this.detectSuggestionPatterns(messageLower);

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
        // Issue #173 metadata
        testedParameter,
        parameterIsRequired,
        hasSuggestions,
        suggestions: suggestions.length > 0 ? suggestions : undefined,
      };
    }
  }

  private async testExcessiveInput(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    isExternalAPI: boolean = false,
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

      // Issue #168: For external API tools, check if error is an external service error
      if (isExternalAPI && isError && this.isExternalServiceError(errorInfo)) {
        return {
          toolName: tool.name,
          testType: "excessive_input",
          testInput: { ...testInput, value: "[100KB string]" },
          expectedError: "Input size limit exceeded",
          actualResponse: {
            isError,
            errorCode: errorInfo.code,
            errorMessage: errorInfo.message,
            rawResponse: response ? "[response omitted]" : undefined,
          },
          passed: true,
          reason:
            "External API service error (validation cannot be tested when service unavailable)",
        };
      }

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
      // Issue #153: Check for connection errors first - these should NOT count as passed
      if (this.errorClassifier.isConnectionErrorFromException(error)) {
        const errorInfo = this.extractErrorInfo(error);
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
          passed: false,
          reason: "Connection error - unable to test",
          isConnectionError: true,
        };
      }

      // Check if the error message is meaningful (not just a generic crash)
      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("size") ||
        messageLower.includes("large") ||
        messageLower.includes("limit") ||
        messageLower.includes("exceed") ||
        messageLower.includes("too") ||
        messageLower.includes("maximum");
      // Removed: (errorInfo.message?.length ?? 0) > 10 - this was causing false positives

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

  /**
   * Issue #173: Return type for generateInvalidValueParams with metadata
   * Tracks which parameter is being tested and whether it's required
   */
  private generateInvalidValueParams(schema: JSONSchema7 | null): {
    params: Record<string, unknown>;
    testedParameter: string;
    parameterIsRequired: boolean;
  } {
    const params: Record<string, unknown> = {};
    let testedParameter = "value";
    let parameterIsRequired = false;

    if (!schema?.properties) {
      return { params: { value: null }, testedParameter, parameterIsRequired };
    }

    const requiredSet = new Set(schema.required ?? []);
    let firstParamSet = false;

    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, JSONSchema7>,
    )) {
      // Track the first parameter being tested (for contextual scoring)
      if (!firstParamSet) {
        testedParameter = key;
        parameterIsRequired = requiredSet.has(key);
        firstParamSet = true;
      }

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

    return { params, testedParameter, parameterIsRequired };
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
   * Issue #173: Bonus points for suggestions and graceful degradation
   *
   * Classifications:
   * - safe_rejection: Tool rejected with error (no penalty)
   * - safe_reflection: Tool stored/echoed without executing (no penalty)
   * - defensive_programming: Tool handled gracefully (no penalty)
   * - graceful_degradation: Optional param handled with neutral response (no penalty + bonus)
   * - execution_detected: Tool executed input (penalty)
   * - unknown: Cannot determine (partial penalty)
   */
  private analyzeInvalidValuesResponse(test: ErrorTestDetail): {
    shouldPenalize: boolean;
    penaltyAmount: number;
    classification: string;
    reason: string;
    bonusPoints: number; // Issue #173
  } {
    const responseText = this.extractResponseTextSafe(
      test.actualResponse.rawResponse,
    );

    // Case 1: Tool rejected with error - best case (no penalty)
    if (test.actualResponse.isError) {
      // Issue #173: Check for suggestions bonus
      const suggestionBonus = test.hasSuggestions ? 10 : 0;
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_rejection",
        reason: "Tool properly rejected invalid input",
        bonusPoints: suggestionBonus,
      };
    }

    // Issue #173 Case 2: Graceful degradation for OPTIONAL parameters
    // If the parameter is optional and the response is neutral (empty results),
    // this is valid graceful degradation behavior, not a failure
    if (
      test.parameterIsRequired === false &&
      this.isNeutralGracefulResponse(responseText)
    ) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "graceful_degradation",
        reason:
          "Tool handled optional empty parameter gracefully (valid behavior)",
        bonusPoints: 15, // Graceful degradation bonus
      };
    }

    // Case 3: Defensive programming patterns (no penalty)
    // Check BEFORE execution detection because patterns like "query returned 0"
    // might match execution indicators but are actually safe
    if (this.isDefensiveProgrammingResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "defensive_programming",
        reason: "Tool handled empty input defensively",
        bonusPoints: 0,
      };
    }

    // Case 4: Safe reflection patterns (no penalty)
    if (this.safeResponseDetector.isReflectionResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_reflection",
        reason: "Tool safely reflected input without execution",
        bonusPoints: 0,
      };
    }

    // Case 5: Check for execution evidence - VULNERABLE (full penalty)
    if (
      this.executionDetector.hasExecutionEvidence(responseText) ||
      this.executionDetector.detectExecutionArtifacts(responseText)
    ) {
      return {
        shouldPenalize: true,
        penaltyAmount: 100,
        classification: "execution_detected",
        reason: "Tool executed input without validation",
        bonusPoints: 0,
      };
    }

    // Case 6: Unknown - partial penalty for manual review
    return {
      shouldPenalize: true,
      penaltyAmount: 25,
      classification: "unknown",
      reason: "Unable to determine safety - manual review recommended",
      bonusPoints: 0,
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

  /**
   * Issue #173: Detect helpful suggestion patterns in error responses
   * Patterns like: "Did you mean: Button, Checkbox?"
   * Returns extracted suggestions for bonus scoring
   */
  private detectSuggestionPatterns(responseText: string): {
    hasSuggestions: boolean;
    suggestions: string[];
  } {
    // Issue #173: ReDoS protection - limit input length before regex matching
    const truncatedText = responseText.slice(0, 2000);

    // Issue #173: Bonus points - see docs/ASSESSMENT_CATALOG.md for scoring table
    // Suggestions: +10 points for helpful error messages like "Did you mean: X?"
    const suggestionPatterns = [
      /did\s+you\s+mean[:\s]+([^?.]+)/i,
      /perhaps\s+you\s+meant[:\s]+([^?.]+)/i,
      /similar\s+to[:\s]+([^?.]+)/i,
      /suggestions?[:\s]+([^?.]+)/i,
      /valid\s+(options?|values?)[:\s]+([^?.]+)/i,
      /available[:\s]+([^?.]+)/i,
      /\btry[:\s]+([^?.]+)/i,
      /expected\s+one\s+of[:\s]+([^?.]+)/i,
    ];

    for (const pattern of suggestionPatterns) {
      const match = truncatedText.match(pattern);
      if (match) {
        // Get the captured group (last non-undefined group)
        const suggestionText = match[match.length - 1] || match[1] || "";
        const suggestions = suggestionText
          .split(/[,;]/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0 && s.length < 50);

        if (suggestions.length > 0) {
          return { hasSuggestions: true, suggestions };
        }
      }
    }

    return { hasSuggestions: false, suggestions: [] };
  }

  /**
   * Issue #173: Check for neutral/graceful responses on optional parameters
   * These indicate the tool handled empty/missing optional input appropriately
   */
  private isNeutralGracefulResponse(responseText: string): boolean {
    // Issue #173: ReDoS protection - limit input length before regex matching
    const truncatedText = responseText.slice(0, 2000);

    const gracefulPatterns = [
      /^\s*\[\s*\]\s*$/, // Empty JSON array (standalone)
      /^\s*\{\s*\}\s*$/, // Empty JSON object (standalone)
      /^\s*$/, // Empty/whitespace only response
      /no\s+results?\s*(found)?/i, // "No results" / "No results found"
      /^results?:\s*\[\s*\]/i, // "results: []"
      /returned\s+0\s+/i, // "returned 0 items"
      /found\s+0\s+/i, // "found 0 matches"
      /empty\s+list/i, // "empty list"
      /no\s+matching/i, // "no matching items"
      /default\s+value/i, // "using default value"
      /^null$/i, // Explicit null
      /no\s+data/i, // "no data"
      /"results"\s*:\s*\[\s*\]/, // JSON with empty results array
      /"items"\s*:\s*\[\s*\]/, // JSON with empty items array
      /"data"\s*:\s*\[\s*\]/, // JSON with empty data array
    ];

    return gracefulPatterns.some((pattern) => pattern.test(truncatedText));
  }

  private calculateMetrics(
    tests: ErrorTestDetail[],
    _passed: number, // parameter kept for API compatibility
  ): ErrorHandlingMetrics {
    // Calculate enhanced score with bonus points for quality
    let enhancedScore = 0;
    let maxPossibleScore = 0;

    // Issue #173: Track graceful degradation and suggestion metrics
    let gracefulDegradationCount = 0;
    let suggestionCount = 0;
    let suggestionBonusPoints = 0;

    tests.forEach((test) => {
      // Issue #99: Contextual scoring for invalid_values tests
      // Instead of blanket exclusion, analyze response patterns to determine if
      // the tool safely handled empty strings (defensive programming, reflection)
      // or if it executed without validation (security concern).
      if (test.testType === "invalid_values") {
        const analysis = this.analyzeInvalidValuesResponse(test);

        // Issue #173: Track graceful degradation
        if (analysis.classification === "graceful_degradation") {
          gracefulDegradationCount++;
        }

        // Issue #173: Track suggestions
        if (test.hasSuggestions) {
          suggestionCount++;
        }

        // Issue #173: Apply bonus points for graceful handling and suggestions
        if (analysis.bonusPoints > 0) {
          enhancedScore += analysis.bonusPoints;
          maxPossibleScore += analysis.bonusPoints;
          suggestionBonusPoints += analysis.bonusPoints;
        }

        if (!analysis.shouldPenalize) {
          // Safe response (rejection, reflection, defensive programming, graceful degradation)
          // Skip base scoring to preserve backward compatibility for well-behaved tools
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

        // Issue #173: Extra points for suggestions in other test types
        if (test.hasSuggestions) {
          suggestionCount++;
          enhancedScore += 10;
          maxPossibleScore += 10;
          suggestionBonusPoints += 10;
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
      // Issue #173: Graceful degradation and suggestion metrics
      gracefulDegradationCount,
      suggestionCount,
      suggestionBonusPoints,
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

  /**
   * Check if an error indicates an external service failure
   * Issue #168: External API tools may fail due to service unavailability,
   * which should not count as validation failure
   */
  private isExternalServiceError(errorInfo: {
    code?: string | number;
    message?: string;
  }): boolean {
    const message = errorInfo.message?.toLowerCase() ?? "";
    const code = String(errorInfo.code ?? "").toLowerCase();

    // Common external service error patterns
    const externalErrorPatterns =
      /rate\s*limit|429|503|502|504|service\s*unavailable|temporarily|timeout|connection\s*refused|network\s*error|api\s*error|external\s*service|upstream|gateway|unreachable|econnrefused|enotfound|etimedout|socket\s*hang\s*up/i;

    return (
      externalErrorPatterns.test(message) || externalErrorPatterns.test(code)
    );
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
