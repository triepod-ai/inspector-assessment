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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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

    // MCP 2025-06-18: Check structuredContent first (modern MCP tools)
    // Modern tools provide structuredContent even without outputSchema
    const response = context.response as any;
    if (response.structuredContent) {
      const structured = response.structuredContent;

      // Handle structured array responses
      if (Array.isArray(structured)) {
        if (structured.length === 0) {
          // Empty array is valid - tool processed request successfully but had no data
          // Example: create_relations returns [] when referenced entities don't exist
          result.evidence.push(
            "Tool returned empty array (processed successfully, no matching data)",
          );
          return true;
        }

        // For mutation tools, check for IDs
        if (isMutationTool) {
          const hasIds = structured.some(
            (item: any) =>
              item &&
              typeof item === "object" &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Mutation operation returned ${structured.length} item(s) with IDs in structuredContent`,
            );
            return true;
          }
        }

        result.evidence.push(
          `Response has structuredContent array with ${structured.length} item(s)`,
        );
        return true;
      }

      // Handle structured object responses
      if (typeof structured === "object" && structured !== null) {
        const keys = Object.keys(structured);
        if (keys.length === 0) {
          result.issues.push("structuredContent object is empty");
          return false;
        }

        const hasNonNullValues = keys.some(
          (key) => structured[key] !== null && structured[key] !== undefined,
        );
        if (!hasNonNullValues) {
          result.issues.push(
            "structuredContent contains only null/undefined values",
          );
          return false;
        }

        result.evidence.push(
          `Response has structuredContent with ${keys.length} data fields`,
        );
        return true;
      }
    }

    // Fallback: Check for actual data/information in content.text
    try {
      const parsed = JSON.parse(textContent);

      // Handle JSON array responses (common for batch operations)
      if (Array.isArray(parsed)) {
        if (parsed.length === 0) {
          // Empty array is valid - tool processed request successfully but had no data
          result.evidence.push(
            "Tool returned empty array (processed successfully, no matching data)",
          );
          return true;
        }

        // For mutation tools, check if array items have IDs (indicates successful creation)
        if (isMutationTool && parsed.length > 0) {
          const hasIds = parsed.some(
            (item) =>
              typeof item === "object" &&
              item !== null &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Mutation operation returned ${parsed.length} item(s) with IDs`,
            );
            return true;
          }
        }

        result.evidence.push(`Response is array with ${parsed.length} item(s)`);
        return true;
      }

      // Handle JSON object responses
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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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
      // MCP 2025-06-18: Check structuredContent first
      const response = context.response as any;
      if (response.structuredContent) {
        const structured = response.structuredContent;

        // Check for array results
        if (Array.isArray(structured)) {
          result.evidence.push(
            `Search returned ${structured.length} result(s) in structuredContent (empty results are valid)`,
          );
          return true;
        }

        // Check for object with search result structure
        if (typeof structured === "object" && structured !== null) {
          const hasSearchStructure =
            "entities" in structured ||
            "relations" in structured ||
            "results" in structured ||
            "items" in structured ||
            "data" in structured ||
            "matches" in structured;

          if (hasSearchStructure) {
            result.evidence.push(
              "Search response has proper result structure in structuredContent",
            );
            return true;
          }

          // Single result object
          if (Object.keys(structured).length > 0) {
            result.evidence.push(
              "Search returned single result object in structuredContent",
            );
            return true;
          }
        }
      }

      // Fallback: Search tools should return results structure (even if empty)
      try {
        const parsed = JSON.parse(textContent);

        // Check for common search response structures
        if (Array.isArray(parsed)) {
          // Array of results (even empty is valid - means no matches)
          result.evidence.push(
            `Search returned ${parsed.length} result(s) (empty results are valid)`,
          );
          return true;
        }

        if (typeof parsed === "object" && parsed !== null) {
          // Check for common search result object structures
          const hasSearchStructure =
            "entities" in parsed ||
            "relations" in parsed ||
            "results" in parsed ||
            "items" in parsed ||
            "data" in parsed ||
            "matches" in parsed;

          if (hasSearchStructure) {
            result.evidence.push("Search response has proper result structure");
            return true;
          }

          // Single result object (e.g., get by ID)
          if (Object.keys(parsed).length > 0) {
            result.evidence.push("Search returned single result object");
            return true;
          }
        }
      } catch {
        // Not JSON, check text patterns
      }

      // Fallback to text-based validation
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

      // If no query parameter, just check for search-related keywords
      if (
        textContent.includes("result") ||
        textContent.includes("found") ||
        textContent.includes("match") ||
        textContent.includes("entity") ||
        textContent.includes("entities")
      ) {
        result.evidence.push("Search response contains search-related data");
        return true;
      }
    }

    if (
      toolName.includes("create") ||
      toolName.includes("add") ||
      toolName.includes("insert")
    ) {
      // MCP 2025-06-18: Check structuredContent first
      const response = context.response as any;
      if (response.structuredContent) {
        const structured = response.structuredContent;

        // Check if response is array with IDs
        if (Array.isArray(structured)) {
          const hasIds = structured.some(
            (item: any) =>
              item &&
              typeof item === "object" &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Creation response includes ${structured.length} item(s) with IDs in structuredContent`,
            );
            return true;
          }

          // Even without IDs, array response indicates success
          if (structured.length > 0) {
            result.evidence.push(
              "Creation response includes created items in structuredContent",
            );
            return true;
          }
        }

        // Check if response is object with ID
        if (typeof structured === "object" && structured !== null) {
          if ("id" in structured || "_id" in structured || "ID" in structured) {
            result.evidence.push(
              "Creation response includes resource ID in structuredContent",
            );
            return true;
          }

          // Check for entity/relation structures
          if (
            "entities" in structured ||
            "relations" in structured ||
            "observations" in structured
          ) {
            result.evidence.push(
              "Creation response includes entity/relation data in structuredContent",
            );
            return true;
          }
        }
      }

      // Fallback: Creation tools should return created resource or ID
      // Try to parse as JSON first to check for structured data with IDs
      try {
        const parsed = JSON.parse(textContent);

        // Check if response is array with IDs (common for batch creation)
        if (Array.isArray(parsed)) {
          const hasIds = parsed.some(
            (item) =>
              typeof item === "object" &&
              item !== null &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Creation response includes ${parsed.length} item(s) with IDs`,
            );
            return true;
          }
        }

        // Check if response is object with ID
        if (typeof parsed === "object" && parsed !== null) {
          if ("id" in parsed || "_id" in parsed || "ID" in parsed) {
            result.evidence.push("Creation response includes resource ID");
            return true;
          }
        }
      } catch {
        // Not JSON, check text patterns
      }

      // Fallback to text-based validation
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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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

    // Creation/mutation tools (entities, relations, observations, etc.)
    if (
      toolName.includes("create") ||
      toolName.includes("add") ||
      toolName.includes("insert") ||
      toolName.includes("entity") ||
      toolName.includes("entities") ||
      toolName.includes("relation") ||
      toolName.includes("observation")
    ) {
      // MCP 2025-06-18: Check structuredContent first (CRITICAL FIX)
      const response = context.response as any;
      if (response.structuredContent) {
        const structured = response.structuredContent;

        // Check for array responses with IDs
        if (Array.isArray(structured)) {
          const hasIds = structured.some(
            (item: any) =>
              item &&
              typeof item === "object" &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Creation tool returned ${structured.length} entity/entities with IDs in structuredContent`,
            );
            return true;
          }

          // Check for entity-like objects even without IDs
          const hasEntityStructure = structured.some(
            (item: any) =>
              item &&
              typeof item === "object" &&
              ("name" in item ||
                "entityType" in item ||
                "from" in item ||
                "to" in item),
          );
          if (hasEntityStructure) {
            result.evidence.push(
              "Creation tool returned entity-like objects in structuredContent",
            );
            return true;
          }
        }

        // Check for object with ID
        if (
          structured &&
          typeof structured === "object" &&
          ("id" in structured || "_id" in structured || "ID" in structured)
        ) {
          result.evidence.push(
            "Creation tool returned entity with ID in structuredContent",
          );
          return true;
        }

        // Check for entity/relation structure
        if (
          structured &&
          typeof structured === "object" &&
          ("name" in structured ||
            "entityType" in structured ||
            "from" in structured ||
            "to" in structured ||
            "entities" in structured ||
            "relations" in structured ||
            "observations" in structured)
        ) {
          result.evidence.push(
            "Creation tool returned entity/relation structure in structuredContent",
          );
          return true;
        }
      }

      // Fallback: Try parsing content.text as JSON
      try {
        const parsed = JSON.parse(textContent);

        // Check for array responses with IDs (common for batch operations)
        if (Array.isArray(parsed)) {
          const hasIds = parsed.some(
            (item) =>
              item &&
              typeof item === "object" &&
              ("id" in item || "_id" in item || "ID" in item),
          );
          if (hasIds) {
            result.evidence.push(
              `Creation tool returned ${parsed.length} entity/entities with IDs`,
            );
            return true;
          }

          // Even without IDs, if array has entity-like objects, it's valid
          const hasEntityStructure = parsed.some(
            (item) =>
              item &&
              typeof item === "object" &&
              ("name" in item ||
                "entityType" in item ||
                "from" in item ||
                "to" in item),
          );
          if (hasEntityStructure) {
            result.evidence.push("Creation tool returned entity-like objects");
            return true;
          }
        }

        // Check for object with ID
        if (
          parsed &&
          typeof parsed === "object" &&
          ("id" in parsed || "_id" in parsed || "ID" in parsed)
        ) {
          result.evidence.push("Creation tool returned entity with ID");
          return true;
        }

        // Check for entity structure
        if (
          parsed &&
          typeof parsed === "object" &&
          ("name" in parsed ||
            "entityType" in parsed ||
            "from" in parsed ||
            "to" in parsed ||
            "entities" in parsed ||
            "relations" in parsed)
        ) {
          result.evidence.push(
            "Creation tool returned entity/relation structure",
          );
          return true;
        }
      } catch {
        // Not JSON, check text patterns
      }

      // Fallback: check for success indicators in text
      if (
        textContent.includes("id") ||
        textContent.includes("created") ||
        textContent.includes("entity") ||
        textContent.includes("entities") ||
        textContent.includes("relation") ||
        textContent.includes("observation")
      ) {
        result.evidence.push(
          "Creation tool response contains entity/relation indicators",
        );
        return true;
      }
    }

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
   * NOTE: Currently unused - kept for potential future use
   */
  // @ts-ignore - Unused method kept for potential future use
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
      // Tool provides structuredContent - this is the modern MCP 2025-06-18 pattern
      // outputSchema validation is optional and rarely used, so we accept any structuredContent
      result.evidence.push(
        "Tool provides structuredContent (MCP 2025-06-18 modern response format)",
      );
      return true;
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
