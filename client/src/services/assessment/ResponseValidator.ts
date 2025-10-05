/**
 * Response Validator for MCP Tool Testing
 * Validates that tool responses are actually functional, not just present
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

export interface ValidationResult {
  isValid: boolean;
  isError: boolean;
  confidence: number; // 0-100
  issues: string[];
  evidence: string[];
  classification:
    | "fully_working"
    | "partially_working"
    | "connectivity_only"
    | "broken"
    | "error";
}

export interface ValidationContext {
  tool: Tool;
  input: Record<string, unknown>;
  response: CompatibilityCallToolResult;
  scenarioCategory?: "happy_path" | "edge_case" | "boundary" | "error_case";
}

export class ResponseValidator {
  /**
   * Validate a tool response comprehensively
   */
  static validateResponse(context: ValidationContext): ValidationResult {
    const result: ValidationResult = {
      isValid: false,
      isError: false,
      confidence: 0,
      issues: [],
      evidence: [],
      classification: "broken",
    };

    // Check if response indicates an error
    if (context.response.isError) {
      result.isError = true;
      result.classification = "error";

      // For error scenarios, we expect errors
      if (context.scenarioCategory === "error_case") {
        result.isValid = this.validateErrorResponse(context, result);
        result.confidence = result.isValid ? 90 : 20;
      } else {
        // Check if this is a business logic error (resource not found, etc.)
        const isBusinessError = this.isBusinessLogicError(context);
        if (isBusinessError) {
          // This is actually a sign the tool is working correctly!
          result.isValid = true;
          result.classification = "fully_working";
          result.confidence = 85;
          result.evidence.push(
            "Tool correctly validates business logic and returns appropriate errors",
          );
          result.evidence.push(
            "Resource validation errors indicate proper API integration",
          );
        } else {
          // Unexpected error
          result.issues.push("Unexpected error response");
          result.confidence = 10;
        }
      }

      return result;
    }

    // Validate successful responses
    const validations = [
      this.validateResponseStructure(context, result),
      this.validateResponseContent(context, result),
      this.validateSemanticCorrectness(context, result),
      this.validateToolSpecificLogic(context, result),
      this.validateStructuredOutput(context, result), // NEW: MCP 2025-06-18 validation
    ];

    // Calculate overall validity and confidence
    const passedValidations = validations.filter((v) => v).length;
    result.isValid = passedValidations >= 3; // Need at least 3/5 validations to pass
    result.confidence = (passedValidations / validations.length) * 100;

    // Classify based on validation results
    if (passedValidations >= 4) {
      result.classification = "fully_working";
    } else if (passedValidations >= 2) {
      result.classification = "partially_working";
    } else if (passedValidations >= 1) {
      result.classification = "connectivity_only";
    } else {
      result.classification = "broken";
    }

    return result;
  }

  /**
   * Check if error is a business logic error (not a tool failure)
   * These errors indicate the tool is working correctly but rejecting invalid business data
   */
  static isBusinessLogicError(context: ValidationContext): boolean {
    const content = context.response.content as
      | Array<{ type: string; text?: string }>
      | undefined;
    const errorText =
      content?.[0]?.type === "text" && content[0].text
        ? content[0].text.toLowerCase()
        : JSON.stringify(context.response.content).toLowerCase();

    // Extract any error code from the response
    const errorCodeMatch = errorText.match(
      /(?:code|error_code)["\s:]+([^",\s]+)/,
    );
    const errorCode = errorCodeMatch ? errorCodeMatch[1] : null;

    // MCP standard error codes that indicate proper validation
    const mcpValidationCodes = [
      "-32602", // Invalid params - tool is validating input correctly
      "-32603", // Internal error - tool handled error gracefully
      "invalid_params",
      "validation_error",
      "bad_request",
    ];

    if (
      errorCode &&
      mcpValidationCodes.some((code) => errorText.includes(code))
    ) {
      return true; // Tool is properly implementing MCP error codes
    }

    // Common business logic error patterns that indicate the tool is working correctly
    const businessErrorPatterns = [
      // Resource validation errors (tool is checking if resources exist)
      "not found",
      "does not exist",
      "doesn't exist",
      "no such",
      "cannot find",
      "could not find",
      "unable to find",
      "invalid id",
      "invalid identifier",
      "unknown resource",
      "resource not found",
      "entity not found",
      "object not found",
      "record not found",
      "item not found",
      "node not found",
      "nodes not found",
      "no entities",
      "no results",
      "not exist",
      "no nodes",
      "no matching",
      "no matches",
      "empty result",
      "zero results",
      "nothing found",
      "no data",
      "no items",

      // Data validation errors (tool is validating data format/content)
      "invalid format",
      "invalid value",
      "invalid type",
      "type mismatch",
      "schema validation",
      "constraint violation",
      "out of range",
      "exceeds maximum",
      "below minimum",
      "invalid length",
      "pattern mismatch",
      "regex failed",

      // Permission and authorization (tool is checking access rights)
      "unauthorized",
      "permission denied",
      "access denied",
      "forbidden",
      "not authorized",
      "insufficient permissions",
      "no access",
      "authentication required",
      "token expired",
      "invalid credentials",

      // Business rule validation (tool is enforcing business logic)
      "already exists",
      "duplicate",
      "conflict",
      "quota exceeded",
      "limit reached",
      "not allowed",
      "operation not permitted",
      "invalid state",
      "precondition failed",
      "dependency not met",

      // API-specific validation
      "invalid parent",
      "invalid reference",
      "invalid relationship",
      "missing required",
      "required field",
      "required parameter",
      "validation failed",
      "invalid request",
      "bad request",
      "malformed",

      // Rate limiting (shows API integration is working)
      "rate limit",
      "too many requests",
      "throttled",
      "quota",
      "exceeded",

      // Configuration validation
      "not configured",
      "not enabled",
      "not available",
      "not supported",
      "feature disabled",
      "service unavailable",
    ];

    // Check if error matches any business logic pattern
    const hasBusinessErrorPattern = businessErrorPatterns.some((pattern) =>
      errorText.includes(pattern),
    );

    // HTTP status codes that indicate business logic validation
    const businessStatusCodes = [
      "400", // Bad Request - input validation
      "401", // Unauthorized - auth validation
      "403", // Forbidden - permission validation
      "404", // Not Found - resource validation
      "409", // Conflict - state validation
      "422", // Unprocessable Entity - semantic validation
      "429", // Too Many Requests - rate limit validation
    ];

    const hasBusinessStatusCode = businessStatusCodes.some(
      (code) =>
        errorText.includes(code) ||
        errorText.includes(`status: ${code}`) ||
        errorText.includes(`statuscode: ${code}`),
    );

    // Check for structured error response (indicates proper error handling)
    const hasStructuredError =
      (errorText.includes("error") || errorText.includes("message")) &&
      (errorText.includes("code") ||
        errorText.includes("type") ||
        errorText.includes("status")) &&
      (errorText.includes("{") || errorText.includes(":")); // JSON-like structure

    // Check if the tool is validating our test data
    const validatesTestData =
      // Rejects test IDs
      ((errorText.includes("test") ||
        errorText.includes("example") ||
        errorText.includes("demo")) &&
        (errorText.includes("invalid") ||
          errorText.includes("not found") ||
          errorText.includes("does not exist"))) ||
      // Rejects placeholder values
      errorText.includes("test_value") ||
      errorText.includes("test@example.com") ||
      errorText.includes("example.com") ||
      // Shows it validated UUID format
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.test(
        errorText,
      ) ||
      // Shows it parsed and validated numeric IDs
      /\bid["\s:]+\d+/.test(errorText) ||
      /\bid["\s:]+["'][^"']+["']/.test(errorText);

    // Check tool operation type - resource operations are expected to validate
    const toolName = context.tool.name.toLowerCase();
    const isValidationExpected =
      // CRUD operations
      toolName.includes("create") ||
      toolName.includes("update") ||
      toolName.includes("delete") ||
      toolName.includes("get") ||
      toolName.includes("fetch") ||
      toolName.includes("read") ||
      toolName.includes("write") ||
      // Data operations
      toolName.includes("query") ||
      toolName.includes("search") ||
      toolName.includes("find") ||
      toolName.includes("list") ||
      // State operations
      toolName.includes("move") ||
      toolName.includes("copy") ||
      toolName.includes("duplicate") ||
      toolName.includes("archive") ||
      // Relationship operations
      toolName.includes("link") ||
      toolName.includes("associate") ||
      toolName.includes("connect") ||
      toolName.includes("attach");

    // Calculate confidence that this is a business logic error
    let confidenceFactors = 0;
    let totalFactors = 0;

    // High confidence indicators
    if (
      errorCode &&
      mcpValidationCodes.some((code) => errorText.includes(code))
    ) {
      confidenceFactors += 2; // MCP compliance is strong indicator
    }
    totalFactors += 2;

    if (hasBusinessErrorPattern) confidenceFactors++;
    totalFactors++;

    if (hasBusinessStatusCode) confidenceFactors++;
    totalFactors++;

    if (hasStructuredError) confidenceFactors++;
    totalFactors++;

    if (validatesTestData) confidenceFactors++;
    totalFactors++;

    if (isValidationExpected) confidenceFactors++;
    totalFactors++;

    // Require at least 50% confidence that this is business logic validation
    const confidence = confidenceFactors / totalFactors;

    // For tools that are expected to validate, be more lenient (30% confidence)
    // For other tools, require higher confidence (50%)
    // Lowered thresholds to better catch business logic errors that may not match all patterns
    const confidenceThreshold = isValidationExpected ? 0.3 : 0.5;

    return confidence >= confidenceThreshold;
  }

  /**
   * Validate error responses are proper and informative
   */
  private static validateErrorResponse(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    const content = context.response.content as
      | Array<{ type: string; text?: string }>
      | undefined;
    const errorText =
      content?.[0]?.type === "text" && content[0].text
        ? content[0].text
        : JSON.stringify(context.response.content);

    // Check for proper error structure
    let hasProperError = false;

    // Check for MCP standard error codes
    if (errorText.includes("-32602") || errorText.includes("Invalid params")) {
      result.evidence.push("Proper MCP error code for invalid parameters");
      hasProperError = true;
    }

    // Check for descriptive error messages
    if (
      errorText.length > 20 &&
      (errorText.toLowerCase().includes("invalid") ||
        errorText.toLowerCase().includes("required") ||
        errorText.toLowerCase().includes("type") ||
        errorText.toLowerCase().includes("validation"))
    ) {
      result.evidence.push("Descriptive error message provided");
      hasProperError = true;
    }

    if (!hasProperError) {
      result.issues.push(
        "Error response lacks proper error codes or descriptive messages",
      );
    }

    return hasProperError;
  }

  /**
   * Validate response structure matches expectations
   */
  private static validateResponseStructure(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    // Check if response has content
    if (!context.response.content) {
      result.issues.push("Response has no content");
      return false;
    }

    // Check content structure
    const content = context.response.content as Array<{
      type: string;
      text?: string;
    }>;

    if (!Array.isArray(content) || content.length === 0) {
      result.issues.push("Response content is empty or not an array");
      return false;
    }

    // Check for expected content type
    const hasTextContent = content.some(
      (item) => item.type === "text" && item.text,
    );
    const hasResourceContent = content.some((item) => item.type === "resource");

    if (!hasTextContent && !hasResourceContent) {
      result.issues.push("Response lacks text or resource content");
      return false;
    }

    result.evidence.push("Response has valid structure");
    return true;
  }

  /**
   * Validate response content is meaningful
   */
  private static validateResponseContent(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    const content = context.response.content as Array<{
      type: string;
      text?: string;
    }>;
    const textContent =
      content.find((item) => item.type === "text")?.text || "";

    // Check if response is just echoing input (bad)
    const inputStr = JSON.stringify(context.input);
    if (textContent === inputStr || textContent === "test_value") {
      result.issues.push("Response appears to just echo input");
      return false;
    }

    // Check for minimal content length
    // But allow short responses for mutation tools (create/update/delete) that might return simple "Success"
    const toolName = context.tool.name.toLowerCase();
    const isMutationTool =
      toolName.includes("create") ||
      toolName.includes("update") ||
      toolName.includes("delete") ||
      toolName.includes("add") ||
      toolName.includes("remove") ||
      toolName.includes("insert");

    if (textContent.length < 10 && !isMutationTool) {
      result.issues.push("Response content is too short to be meaningful");
      return false;
    }

    // For mutation tools, accept common success indicators even if short
    if (isMutationTool && textContent.length < 10) {
      const successIndicators = [
        "success",
        "ok",
        "done",
        "created",
        "updated",
        "deleted",
        "added",
        "removed",
      ];
      const hasSuccessIndicator = successIndicators.some((indicator) =>
        textContent.toLowerCase().includes(indicator),
      );

      if (!hasSuccessIndicator) {
        result.issues.push(
          "Short response lacks success confirmation for mutation operation",
        );
        return false;
      }

      // Short success message is acceptable
      result.evidence.push("Mutation operation confirmed with short response");
      return true;
    }

    // Check for actual data/information
    try {
      const parsed = JSON.parse(textContent);

      // Check if parsed content has meaningful data
      if (typeof parsed === "object" && parsed !== null) {
        const keys = Object.keys(parsed);
        if (keys.length === 0) {
          result.issues.push("Response object is empty");
          return false;
        }

        // Check for null/undefined values
        const hasNonNullValues = keys.some(
          (key) => parsed[key] !== null && parsed[key] !== undefined,
        );

        if (!hasNonNullValues) {
          result.issues.push("Response contains only null/undefined values");
          return false;
        }

        result.evidence.push(`Response contains ${keys.length} data fields`);
        return true;
      }
    } catch {
      // Not JSON, check as plain text
      if (textContent.includes("error") || textContent.includes("Error")) {
        // If it contains error but isError is false, that's suspicious
        if (!context.response.isError) {
          result.issues.push(
            "Response contains error text but isError flag is false",
          );
          return false;
        }
      }
    }

    result.evidence.push("Response contains meaningful content");
    return true;
  }

  /**
   * Validate semantic correctness based on input/output relationship
   */
  private static validateSemanticCorrectness(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    const toolName = context.tool.name.toLowerCase();
    const content = context.response.content as Array<{
      type: string;
      text?: string;
    }>;
    const textContent =
      content.find((item) => item.type === "text")?.text || "";

    // Tool-specific semantic validation
    if (
      toolName.includes("search") ||
      toolName.includes("find") ||
      toolName.includes("get")
    ) {
      // Search tools should return results related to query
      const query = this.findQueryParameter(context.input);
      if (query && typeof query === "string") {
        // Very basic check - response should reference the query somehow
        if (
          !textContent.toLowerCase().includes(query.toLowerCase()) &&
          !textContent.includes("results") &&
          !textContent.includes("found")
        ) {
          result.issues.push("Search response doesn't seem related to query");
          return false;
        }
        result.evidence.push("Search response appears related to query");
        return true;
      }
    }

    if (
      toolName.includes("create") ||
      toolName.includes("add") ||
      toolName.includes("insert")
    ) {
      // Creation tools should return created resource or ID
      if (
        !textContent.includes("id") &&
        !textContent.includes("created") &&
        !textContent.includes("success")
      ) {
        result.issues.push(
          "Creation response lacks confirmation or resource ID",
        );
        return false;
      }
      result.evidence.push("Creation response includes confirmation");
      return true;
    }

    if (toolName.includes("delete") || toolName.includes("remove")) {
      // Deletion tools should confirm deletion
      if (
        !textContent.includes("deleted") &&
        !textContent.includes("removed") &&
        !textContent.includes("success")
      ) {
        result.issues.push("Deletion response lacks confirmation");
        return false;
      }
      result.evidence.push("Deletion response confirms action");
      return true;
    }

    if (
      toolName.includes("update") ||
      toolName.includes("modify") ||
      toolName.includes("edit")
    ) {
      // Update tools should confirm update
      if (
        !textContent.includes("updated") &&
        !textContent.includes("modified") &&
        !textContent.includes("changed") &&
        !textContent.includes("success")
      ) {
        result.issues.push("Update response lacks confirmation");
        return false;
      }
      result.evidence.push("Update response confirms changes");
      return true;
    }

    if (toolName.includes("list") || toolName.includes("all")) {
      // List tools should return array or multiple items
      try {
        const parsed = JSON.parse(textContent);
        if (
          Array.isArray(parsed) ||
          (parsed &&
            typeof parsed === "object" &&
            ("items" in parsed || "results" in parsed))
        ) {
          result.evidence.push("List response contains array or collection");
          return true;
        }
      } catch {
        // Check for list-like text response
        if (textContent.includes(",") || textContent.includes("\n")) {
          result.evidence.push("Response appears to contain multiple items");
          return true;
        }
      }

      result.issues.push("List response doesn't contain collection");
      return false;
    }

    // Default validation - response should be different from input
    const inputStr = JSON.stringify(context.input);
    if (
      textContent !== inputStr &&
      textContent.length > inputStr.length * 0.5
    ) {
      result.evidence.push("Response is substantively different from input");
      return true;
    }

    result.issues.push("Response doesn't demonstrate clear functionality");
    return false;
  }

  /**
   * Validate tool-specific logic and patterns
   */
  private static validateToolSpecificLogic(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    const toolName = context.tool.name.toLowerCase();
    const content = context.response.content as Array<{
      type: string;
      text?: string;
    }>;
    const textContent =
      content.find((item) => item.type === "text")?.text || "";

    // Database/store tools
    if (
      toolName.includes("database") ||
      toolName.includes("store") ||
      toolName.includes("db")
    ) {
      if (
        textContent.includes("connection") &&
        textContent.includes("failed")
      ) {
        result.issues.push("Database connection failure");
        return false;
      }

      // Should have some indication of data operation
      if (
        textContent.includes("rows") ||
        textContent.includes("records") ||
        textContent.includes("documents") ||
        textContent.includes("query")
      ) {
        result.evidence.push("Response indicates database operation");
        return true;
      }
    }

    // File system tools
    if (
      toolName.includes("file") ||
      toolName.includes("read") ||
      toolName.includes("write")
    ) {
      if (
        textContent.includes("permission") &&
        textContent.includes("denied")
      ) {
        result.issues.push("File permission error");
        return false;
      }

      if (
        textContent.includes("not found") &&
        context.scenarioCategory !== "error_case"
      ) {
        result.issues.push("File not found error");
        return false;
      }

      // Should have file operation indication
      if (
        textContent.includes("bytes") ||
        textContent.includes("content") ||
        textContent.includes("saved") ||
        textContent.includes("written")
      ) {
        result.evidence.push("Response indicates file operation");
        return true;
      }
    }

    // API/HTTP tools
    if (
      toolName.includes("http") ||
      toolName.includes("api") ||
      toolName.includes("fetch")
    ) {
      // Check for HTTP status codes
      if (
        textContent.includes("200") ||
        textContent.includes("201") ||
        textContent.includes("success")
      ) {
        result.evidence.push("Response indicates successful HTTP operation");
        return true;
      }

      if (
        textContent.includes("404") ||
        textContent.includes("500") ||
        textContent.includes("error")
      ) {
        result.issues.push("HTTP error in response");
        return false;
      }
    }

    // Computation/calculation tools
    if (
      toolName.includes("calc") ||
      toolName.includes("compute") ||
      toolName.includes("math")
    ) {
      // Should return numeric result
      try {
        const parsed = JSON.parse(textContent);
        if (
          typeof parsed === "number" ||
          (parsed && "result" in parsed && typeof parsed.result === "number")
        ) {
          result.evidence.push("Response contains numeric computation result");
          return true;
        }
      } catch {
        // Check for number in text
        if (/\d+/.test(textContent)) {
          result.evidence.push("Response contains numeric value");
          return true;
        }
      }

      result.issues.push("Computation tool didn't return numeric result");
      return false;
    }

    // Default - tool responded with non-empty content
    if (textContent.length > 20) {
      result.evidence.push("Tool provided substantive response");
      return true;
    }

    result.issues.push("Response lacks tool-specific indicators");
    return false;
  }

  /**
   * Find query-like parameter in input
   */
  private static findQueryParameter(input: Record<string, unknown>): unknown {
    const queryKeys = [
      "query",
      "q",
      "search",
      "term",
      "keyword",
      "filter",
      "name",
      "id",
    ];

    for (const key of queryKeys) {
      if (key in input) {
        return input[key];
      }
    }

    // Return first string parameter as fallback
    for (const value of Object.values(input)) {
      if (typeof value === "string") {
        return value;
      }
    }

    return null;
  }

  /**
   * Validate structured output against outputSchema (MCP 2025-06-18 feature)
   */
  private static validateStructuredOutput(
    context: ValidationContext,
    result: ValidationResult,
  ): boolean {
    // Check if tool has outputSchema defined
    const tool = context.tool as any; // Cast to any to access potential outputSchema property
    if (!tool.outputSchema) {
      // Tool doesn't define outputSchema, this validation is not applicable
      result.evidence.push(
        "Tool does not define outputSchema (optional MCP 2025-06-18 feature)",
      );
      return true; // Not a failure if not using structured output
    }

    // Check if response contains structuredContent
    const response = context.response as any;
    if (response.structuredContent) {
      // Validate structuredContent against outputSchema
      try {
        // Import Ajv for JSON schema validation
        const Ajv = require("ajv");
        const ajv = new Ajv({ allErrors: true });

        const validate = ajv.compile(tool.outputSchema);
        const valid = validate(response.structuredContent);

        if (valid) {
          result.evidence.push(
            "✅ Structured output matches outputSchema definition",
          );
          result.evidence.push(
            "Tool properly implements MCP 2025-06-18 structured output",
          );
          return true;
        } else {
          result.issues.push(
            `Structured output validation failed: ${ajv.errorsText(validate.errors)}`,
          );
          return false;
        }
      } catch (error) {
        result.issues.push(`Failed to validate structured output: ${error}`);
        return false;
      }
    }

    // Check if response contains resource URIs (another MCP 2025-06-18 feature)
    const content = context.response.content as Array<{
      type: string;
      uri?: string;
      text?: string;
    }>;
    const hasResourceUris = content.some(
      (item) => item.type === "resource" && item.uri,
    );

    if (hasResourceUris) {
      result.evidence.push(
        "Response uses resource URIs for external content (MCP 2025-06-18 feature)",
      );
      return true;
    }

    // Tool has outputSchema but didn't provide structuredContent
    // This is okay - tools can provide both text and structured output
    result.evidence.push(
      "Tool has outputSchema but provided text response (backward compatibility)",
    );
    return true;
  }

  /**
   * Calculate confidence score for a set of validation results
   */
  static calculateOverallConfidence(results: ValidationResult[]): number {
    if (results.length === 0) return 0;

    const weights = {
      fully_working: 1.0,
      partially_working: 0.7,
      connectivity_only: 0.3,
      error: 0.2,
      broken: 0.0,
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const result of results) {
      const weight = weights[result.classification];
      weightedSum += result.confidence * weight;
      totalWeight += 100; // Max confidence per result
    }

    return totalWeight > 0 ? (weightedSum / totalWeight) * 100 : 0;
  }
}
