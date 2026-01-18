/**
 * Input Validation Tester
 *
 * Tests tool input validation with 4 test types:
 * - missing_required: Tests missing required parameters
 * - wrong_type: Tests type validation with wrong types
 * - excessive_input: Tests input size limits
 * - invalid_values: Tests edge case handling
 *
 * @module assessment/modules/ProtocolComplianceAssessor/errorHandling/InputValidationTester
 * @see GitHub Issue #188
 */

import type {
  ErrorTestDetail,
  CallToolFunction,
  Tool,
  JSONSchema7,
  InvalidValueParamsResult,
  ErrorInfo,
  Logger,
  AssessmentConfiguration,
  CompatibilityCallToolResult,
} from "../types";
// EXTERNAL_SERVICE_ERROR_PATTERNS imported but not directly used (patterns handled in ErrorClassifier)
import { ErrorClassifier } from "../../securityTests/ErrorClassifier";
import { InvalidValuesAnalyzer } from "./InvalidValuesAnalyzer";
import { ErrorHandlingReporter } from "./ErrorHandlingReporter";

/**
 * Tests tool input validation across multiple scenarios.
 */
export class InputValidationTester {
  private errorClassifier: ErrorClassifier;
  private invalidValuesAnalyzer: InvalidValuesAnalyzer;
  private reporter: ErrorHandlingReporter;

  constructor(config: AssessmentConfiguration, logger: Logger) {
    this.errorClassifier = new ErrorClassifier();
    this.invalidValuesAnalyzer = new InvalidValuesAnalyzer(config, logger);
    this.reporter = new ErrorHandlingReporter(config, logger);
  }

  /**
   * Execute with timeout helper.
   */
  private async executeWithTimeout<T>(
    promise: Promise<T>,
    timeout: number,
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), timeout),
      ),
    ]);
  }

  /**
   * Test all error handling scenarios for a single tool.
   */
  async testTool(
    tool: Tool,
    callTool: CallToolFunction,
    isExternalAPI: boolean,
  ): Promise<ErrorTestDetail[]> {
    const tests: ErrorTestDetail[] = [];

    // Scored tests first (affect compliance score)
    tests.push(await this.testMissingParameters(tool, callTool, isExternalAPI));
    tests.push(await this.testWrongTypes(tool, callTool, isExternalAPI));
    tests.push(await this.testExcessiveInput(tool, callTool, isExternalAPI));

    // Informational tests last (do not affect compliance score)
    tests.push(await this.testInvalidValues(tool, callTool, isExternalAPI));

    return tests;
  }

  /**
   * Test missing required parameters.
   */
  async testMissingParameters(
    tool: Tool,
    callTool: CallToolFunction,
    isExternalAPI: boolean = false,
  ): Promise<ErrorTestDetail> {
    const testInput = {}; // Empty params

    const schema = this.getToolSchema(tool);
    const hasRequiredParams =
      schema?.required &&
      Array.isArray(schema.required) &&
      schema.required.length > 0;

    // If no required parameters, this test should pass
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
          /\b(query|field|parameter|argument|value|input)\b/i.test(
            errorInfo.message ?? "",
          ));

      // Issue #168: External service errors
      if (
        isExternalAPI &&
        isError &&
        this.reporter.isExternalServiceError(errorInfo)
      ) {
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
      // Issue #153: Connection errors should NOT count as passed
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

      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("required") ||
        messageLower.includes("missing") ||
        messageLower.includes("parameter") ||
        messageLower.includes("must") ||
        messageLower.includes("invalid") ||
        messageLower.includes("validation");

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

  /**
   * Test wrong parameter types.
   */
  async testWrongTypes(
    tool: Tool,
    callTool: CallToolFunction,
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
          /\b(validation|validate|schema|format)\b/i.test(
            errorInfo.message ?? "",
          ));

      // Issue #168: External service errors
      if (
        isExternalAPI &&
        isError &&
        this.reporter.isExternalServiceError(errorInfo)
      ) {
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
      // Issue #153: Connection errors
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

  /**
   * Test invalid parameter values (edge cases).
   */
  async testInvalidValues(
    tool: Tool,
    callTool: CallToolFunction,
    isExternalAPI: boolean = false,
  ): Promise<ErrorTestDetail> {
    const schema = this.getToolSchema(tool);
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
      const responseText =
        this.invalidValuesAnalyzer.extractResponseTextSafe(response);

      const { hasSuggestions, suggestions } =
        this.invalidValuesAnalyzer.detectSuggestionPatterns(responseText);

      // Issue #168: External service errors
      if (
        isExternalAPI &&
        isError &&
        this.reporter.isExternalServiceError(errorInfo)
      ) {
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
          testedParameter,
          parameterIsRequired,
          hasSuggestions,
          suggestions: suggestions.length > 0 ? suggestions : undefined,
        };
      }

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
        testedParameter,
        parameterIsRequired,
        hasSuggestions,
        suggestions: suggestions.length > 0 ? suggestions : undefined,
      };
    } catch (error) {
      // Issue #153: Connection errors
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
          testedParameter,
          parameterIsRequired,
        };
      }

      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("invalid") ||
        messageLower.includes("not allowed") ||
        messageLower.includes("must") ||
        messageLower.includes("cannot") ||
        messageLower.includes("validation") ||
        messageLower.includes("error");

      const { hasSuggestions, suggestions } =
        this.invalidValuesAnalyzer.detectSuggestionPatterns(messageLower);

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
        testedParameter,
        parameterIsRequired,
        hasSuggestions,
        suggestions: suggestions.length > 0 ? suggestions : undefined,
      };
    }
  }

  /**
   * Test excessive input size.
   */
  async testExcessiveInput(
    tool: Tool,
    callTool: CallToolFunction,
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

      // Issue #168: External service errors
      if (
        isExternalAPI &&
        isError &&
        this.reporter.isExternalServiceError(errorInfo)
      ) {
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
        testInput: { ...testInput, value: "[100KB string]" },
        expectedError: "Input size limit exceeded",
        actualResponse: {
          isError,
          errorCode: errorInfo.code,
          errorMessage: errorInfo.message,
          rawResponse: response ? "[response omitted]" : undefined,
        },
        passed: isError || response !== null,
        reason:
          !isError && !response ? "Tool crashed on large input" : undefined,
      };
    } catch (error) {
      // Issue #153: Connection errors
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

      const errorInfo = this.extractErrorInfo(error);
      const messageLower = errorInfo.message?.toLowerCase() ?? "";
      const isMeaningfulError =
        messageLower.includes("size") ||
        messageLower.includes("large") ||
        messageLower.includes("limit") ||
        messageLower.includes("exceed") ||
        messageLower.includes("too") ||
        messageLower.includes("maximum");

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

  // Helper methods

  private getToolSchema(tool: Tool): JSONSchema7 | null {
    if (!tool.inputSchema) return null;
    return typeof tool.inputSchema === "string"
      ? (this.safeJsonParse(tool.inputSchema) as JSONSchema7 | null)
      : (tool.inputSchema as JSONSchema7);
  }

  private safeJsonParse(str: string): unknown | null {
    try {
      return JSON.parse(str);
    } catch {
      return null;
    }
  }

  private generateWrongTypeParams(
    schema: JSONSchema7 | null,
  ): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!schema?.properties) return { value: 123 };

    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, JSONSchema7>,
    )) {
      switch (prop.type) {
        case "string":
          params[key] = 123;
          break;
        case "number":
        case "integer":
          params[key] = "not a number";
          break;
        case "boolean":
          params[key] = "yes";
          break;
        case "array":
          params[key] = "not an array";
          break;
        case "object":
          params[key] = "not an object";
          break;
      }
    }

    return params;
  }

  private generateInvalidValueParams(
    schema: JSONSchema7 | null,
  ): InvalidValueParamsResult {
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
      if (!firstParamSet) {
        testedParameter = key;
        parameterIsRequired = requiredSet.has(key);
        firstParamSet = true;
      }

      if (prop.type === "string") {
        if (prop.enum) {
          params[key] = "not_in_enum";
        } else if (prop.format === "email") {
          params[key] = "invalid-email";
        } else if (prop.format === "uri") {
          params[key] = "not://a/valid/uri";
        } else {
          params[key] = "";
        }
      } else if (prop.type === "number" || prop.type === "integer") {
        if (prop.minimum !== undefined) {
          params[key] = prop.minimum - 1;
        } else if (prop.maximum !== undefined) {
          params[key] = prop.maximum + 1;
        } else {
          params[key] = -999999;
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
      params.value = value;
    }

    return params;
  }

  private isErrorResponse(response: CompatibilityCallToolResult): boolean {
    return response?.isError === true;
  }

  private extractErrorInfo(response: unknown): ErrorInfo {
    if (response instanceof Error) {
      return {
        message: response.message,
        code: (response as Error & { code?: string | number }).code,
      };
    }
    if (response && typeof response === "object") {
      const obj = response as Record<string, unknown>;
      if (obj.content && Array.isArray(obj.content)) {
        const textContent = (
          obj.content as Array<{ type: string; text?: string }>
        ).find((c) => c.type === "text");
        return {
          message: textContent?.text,
          code: obj.errorCode as string | number | undefined,
        };
      }
      return {
        message: (obj.errorMessage ?? obj.message ?? obj.error) as
          | string
          | undefined,
        code: obj.errorCode as string | number | undefined,
      };
    }
    return { message: String(response) };
  }
}
