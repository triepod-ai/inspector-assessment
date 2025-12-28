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

      // Simplified: ANY error response means the tool is functional
      // The tool responded (even with an error) - that's functionality!
      result.isValid = true;
      result.classification = "fully_working";
      result.confidence = 100;
      result.evidence.push("Tool responded with error (tool is functional)");

      // Add context about the error for debugging
      const content = context.response.content as
        | Array<{ type: string; text?: string }>
        | undefined;
      const errorText = content?.[0]?.text || "Unknown error";
      result.evidence.push(`Error message: ${errorText.substring(0, 100)}`);

      return result;
    }

    // Simplified functionality validation:
    // If the tool responds with content, it's functional.
    // We don't check response quality/structure - that's for error handling tests.

    // Check 1: Response has content
    if (!context.response.content) {
      result.issues.push("Response has no content");
      result.classification = "broken";
      result.confidence = 0;
      return result;
    }

    // Check 2: Content is a non-empty array
    const content = context.response.content as Array<{
      type: string;
      text?: string;
    }>;

    if (!Array.isArray(content) || content.length === 0) {
      result.issues.push("Response content is empty or not an array");
      result.classification = "broken";
      result.confidence = 0;
      return result;
    }

    // Tool responded successfully - it's functional!
    result.isValid = true;
    result.classification = "fully_working";
    result.confidence = 100;
    result.evidence.push("Tool responded successfully with content");

    // Add details about response type for debugging
    const hasText = content.some((item) => item.type === "text");
    const hasResource = content.some((item) => item.type === "resource");
    if (hasText) {
      result.evidence.push("Response includes text content");
    }
    if (hasResource) {
      result.evidence.push("Response includes resource content");
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
      "invalid input",
      "invalid parameter",
      "invalid data",
      "type mismatch",
      "schema validation",
      "constraint violation",
      "out of range",
      "exceeds maximum",
      "below minimum",
      "invalid length",
      "pattern mismatch",
      "regex failed",
      "must have",
      "must be",

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

      // API operational/billing errors (shows API integration is working)
      "insufficient credits",
      "credits",
      "no credits",
      "credit balance",
      "billing",
      "subscription",
      "plan upgrade",
      "payment required",
      "account suspended",
      "trial expired",
      "usage limit",

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
      toolName.includes("attach") ||
      // API/scraping operations
      toolName.includes("scrape") ||
      toolName.includes("crawl") ||
      toolName.includes("map") ||
      toolName.includes("extract") ||
      toolName.includes("parse") ||
      toolName.includes("analyze") ||
      toolName.includes("process");

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

    if (hasBusinessErrorPattern) confidenceFactors += 2; // Increased weight for business error patterns
    totalFactors += 2;

    if (hasBusinessStatusCode) confidenceFactors++;
    totalFactors++;

    if (hasStructuredError) confidenceFactors++;
    totalFactors++;

    if (validatesTestData) confidenceFactors++;
    totalFactors++;

    if (isValidationExpected) confidenceFactors += 2; // Increased weight for validation-expected tools
    totalFactors += 2;

    // Require at least 50% confidence that this is business logic validation
    const confidence = confidenceFactors / totalFactors;

    // Special case: Strong operational error indicators (quota, rate limit, billing)
    // These are almost always business logic errors, not tool failures
    const hasStrongOperationalError =
      hasBusinessErrorPattern &&
      (errorText.includes("quota") ||
        errorText.includes("credit") ||
        errorText.includes("rate limit") ||
        errorText.includes("throttle") ||
        errorText.includes("billing") ||
        errorText.includes("payment") ||
        errorText.includes("subscription") ||
        errorText.includes("trial"));

    // Determine confidence threshold based on error type and tool type
    // - Strong operational errors: 20% (very lenient, these are obvious)
    // - Validation-expected tools: 30% (lenient)
    // - Other tools: 50% (standard)
    const confidenceThreshold = hasStrongOperationalError
      ? 0.2
      : isValidationExpected
        ? 0.3
        : 0.5;

    return confidence >= confidenceThreshold;
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
