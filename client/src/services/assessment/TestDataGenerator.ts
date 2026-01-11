/**
 * Smart Test Data Generator for MCP Tool Testing
 * Generates realistic, context-aware test data based on parameter schemas
 *
 * Supports optional Claude Code integration for intelligent test generation
 * when ClaudeCodeBridge is provided.
 *
 * @internal
 * @module assessment/TestDataGenerator
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ClaudeCodeBridge } from "./lib/claudeCodeBridge";
import type { Logger } from "./lib/logger";
import { JSONSchema7 } from "@/lib/assessmentTypes";
import {
  REALISTIC_DATA,
  TOOL_CATEGORY_DATA,
  SPECIFIC_FIELD_PATTERNS,
} from "./testdata";

export interface TestScenario {
  name: string;
  description: string;
  params: Record<string, unknown>;
  expectedBehavior: string;
  category: "happy_path" | "edge_case" | "boundary" | "error_case";
  source?: "schema-based" | "claude-generated"; // Track generation method
}

export class TestDataGenerator {
  // Optional Claude Code bridge for intelligent test generation
  private static claudeBridge: ClaudeCodeBridge | null = null;
  // Optional logger for diagnostic output
  private static logger: Logger | null = null;

  /**
   * Re-exported REALISTIC_DATA for backward compatibility.
   * Data is now defined in ./testdata/realistic-values.ts
   * Accessed via (TestDataGenerator as any).REALISTIC_DATA in tests.
   * @internal
   */
  protected static readonly REALISTIC_DATA = REALISTIC_DATA;

  /**
   * Set the Claude Code bridge for intelligent test generation
   * Call this once during initialization if Claude integration is enabled
   */
  static setClaudeBridge(bridge: ClaudeCodeBridge | null): void {
    this.claudeBridge = bridge;
  }

  /**
   * Set the logger for diagnostic output
   * Call this once during initialization
   */
  static setLogger(logger: Logger | null): void {
    this.logger = logger;
  }

  /**
   * Check if Claude Code integration is available and enabled
   */
  static isClaudeEnabled(): boolean {
    return (
      this.claudeBridge !== null &&
      this.claudeBridge.isFeatureEnabled("intelligentTestGeneration")
    );
  }

  /**
   * Generate multiple test scenarios for a tool
   * Uses Claude Code if available for intelligent generation,
   * otherwise falls back to schema-based generation.
   */
  static generateTestScenarios(tool: Tool): TestScenario[] {
    const scenarios: TestScenario[] = [];

    // Always include at least one happy path scenario
    scenarios.push(this.generateHappyPathScenario(tool));

    // Add edge cases based on tool complexity
    const edgeCases = this.generateEdgeCaseScenarios(tool);
    scenarios.push(...edgeCases);

    // Add boundary value scenarios for numeric inputs
    const boundaryScenarios = this.generateBoundaryScenarios(tool);
    scenarios.push(...boundaryScenarios);

    // Add one error scenario to test error handling
    scenarios.push(this.generateErrorScenario(tool));

    return scenarios;
  }

  /**
   * Generate test scenarios with optional Claude enhancement
   * This async version tries Claude first if enabled, then falls back to schema-based.
   */
  static async generateTestScenariosAsync(tool: Tool): Promise<TestScenario[]> {
    // Try Claude-enhanced generation first
    if (this.isClaudeEnabled() && this.claudeBridge) {
      try {
        const claudeParams =
          await this.claudeBridge.generateTestParameters(tool);

        if (claudeParams && claudeParams.length > 0) {
          this.logger?.info("Using Claude-generated params", {
            toolName: tool.name,
          });

          // Convert Claude params to TestScenario format
          const claudeScenarios: TestScenario[] = claudeParams.map(
            (params, index) => ({
              name: this.getClaudeScenarioName(index),
              description: `Claude-generated test case ${index + 1} for ${tool.name}`,
              params,
              expectedBehavior:
                "Should execute successfully with valid response",
              category: this.getClaudeScenarioCategory(index),
              source: "claude-generated" as const,
            }),
          );

          // Add one error scenario (Claude focuses on valid inputs)
          claudeScenarios.push({
            ...this.generateErrorScenario(tool),
            source: "schema-based",
          });

          return claudeScenarios;
        }
      } catch (error) {
        this.logger?.warn(
          "Claude generation failed, falling back to schema-based",
          {
            toolName: tool.name,
            error: String(error),
          },
        );
      }
    }

    // Fall back to schema-based generation
    return this.generateTestScenarios(tool).map((scenario) => ({
      ...scenario,
      source: "schema-based" as const,
    }));
  }

  /**
   * Get scenario name based on index for Claude-generated scenarios
   */
  private static getClaudeScenarioName(index: number): string {
    const names = [
      "Happy Path - Typical Usage",
      "Edge Case - Boundary Values",
      "Minimal Input - Required Fields Only",
      "Comprehensive - All Fields Populated",
      "Variant - Alternative Valid Input",
    ];
    return names[index] || `Test Case ${index + 1}`;
  }

  /**
   * Get scenario category based on index for Claude-generated scenarios
   */
  private static getClaudeScenarioCategory(
    index: number,
  ): TestScenario["category"] {
    const categories: TestScenario["category"][] = [
      "happy_path",
      "edge_case",
      "boundary",
      "happy_path",
      "edge_case",
    ];
    return categories[index] || "happy_path";
  }

  /**
   * Generate a happy path scenario with realistic data
   */
  private static generateHappyPathScenario(tool: Tool): TestScenario {
    const params = this.generateRealisticParams(tool, "typical");

    return {
      name: "Happy Path - Typical Usage",
      description: `Test ${tool.name} with typical, valid inputs`,
      params,
      expectedBehavior: "Should execute successfully and return valid response",
      category: "happy_path",
    };
  }

  /**
   * Generate edge case scenarios
   */
  private static generateEdgeCaseScenarios(tool: Tool): TestScenario[] {
    const scenarios: TestScenario[] = [];

    // Empty values scenario (where applicable)
    const emptyParams = this.generateRealisticParams(tool, "empty");
    if (Object.keys(emptyParams).length > 0) {
      scenarios.push({
        name: "Edge Case - Empty Values",
        description: "Test with empty but valid values",
        params: emptyParams,
        expectedBehavior: "Should handle empty values gracefully",
        category: "edge_case",
      });
    }

    // Maximum values scenario
    const maxParams = this.generateRealisticParams(tool, "maximum");
    scenarios.push({
      name: "Edge Case - Maximum Values",
      description: "Test with maximum/large values",
      params: maxParams,
      expectedBehavior: "Should handle large inputs without issues",
      category: "edge_case",
    });

    // Special characters scenario (for string inputs)
    if (this.hasStringInputs(tool)) {
      const specialParams = this.generateRealisticParams(tool, "special");
      scenarios.push({
        name: "Edge Case - Special Characters",
        description: "Test with special characters and unicode",
        params: specialParams,
        expectedBehavior: "Should properly handle special characters",
        category: "edge_case",
      });
    }

    return scenarios;
  }

  /**
   * Generate boundary value scenarios
   */
  private static generateBoundaryScenarios(tool: Tool): TestScenario[] {
    const scenarios: TestScenario[] = [];

    if (!tool.inputSchema || tool.inputSchema.type !== "object") {
      return scenarios;
    }

    const properties = tool.inputSchema.properties || {};

    // OPTIMIZATION: Check if any fields have boundary constraints before generating tests
    // This prevents running boundary tests on tools that don't define min/max constraints
    let hasBoundaries = false;
    for (const [_key, schema] of Object.entries(properties)) {
      const schemaObj = schema as JSONSchema7;
      if (
        schemaObj.minimum !== undefined ||
        schemaObj.maximum !== undefined ||
        schemaObj.minLength !== undefined ||
        schemaObj.maxLength !== undefined
      ) {
        hasBoundaries = true;
        break;
      }
    }

    // Early return if no boundaries defined - saves 0-4 test scenarios per tool
    if (!hasBoundaries) {
      return scenarios;
    }

    for (const [key, schema] of Object.entries(properties)) {
      const schemaObj = schema as JSONSchema7;

      // Test numeric boundaries
      if (schemaObj.type === "number" || schemaObj.type === "integer") {
        if (schemaObj.minimum !== undefined) {
          const params = this.generateRealisticParams(tool, "typical");
          params[key] = schemaObj.minimum;
          scenarios.push({
            name: `Boundary - ${key} at minimum`,
            description: `Test ${key} at its minimum value`,
            params,
            expectedBehavior: "Should accept minimum value",
            category: "boundary",
          });
        }

        if (schemaObj.maximum !== undefined) {
          const params = this.generateRealisticParams(tool, "typical");
          params[key] = schemaObj.maximum;
          scenarios.push({
            name: `Boundary - ${key} at maximum`,
            description: `Test ${key} at its maximum value`,
            params,
            expectedBehavior: "Should accept maximum value",
            category: "boundary",
          });
        }
      }

      // Test string length boundaries
      if (schemaObj.type === "string") {
        if (schemaObj.minLength !== undefined) {
          const params = this.generateRealisticParams(tool, "typical");
          params[key] = "a".repeat(schemaObj.minLength);
          scenarios.push({
            name: `Boundary - ${key} at min length`,
            description: `Test ${key} at minimum length`,
            params,
            expectedBehavior: "Should accept minimum length string",
            category: "boundary",
          });
        }

        if (schemaObj.maxLength !== undefined) {
          const params = this.generateRealisticParams(tool, "typical");
          params[key] = "a".repeat(schemaObj.maxLength);
          scenarios.push({
            name: `Boundary - ${key} at max length`,
            description: `Test ${key} at maximum length`,
            params,
            expectedBehavior: "Should accept maximum length string",
            category: "boundary",
          });
        }
      }
    }

    return scenarios;
  }

  /**
   * Generate an error scenario
   */
  private static generateErrorScenario(tool: Tool): TestScenario {
    const params: Record<string, unknown> = {};

    if (
      tool.inputSchema &&
      tool.inputSchema.type === "object" &&
      tool.inputSchema.properties
    ) {
      // Intentionally provide wrong types
      for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
        const schemaObj = schema as JSONSchema7;

        switch (schemaObj.type) {
          case "string":
            params[key] = 123; // Wrong type
            break;
          case "number":
          case "integer":
            params[key] = "not_a_number"; // Wrong type
            break;
          case "boolean":
            params[key] = "not_a_boolean"; // Wrong type
            break;
          case "array":
            params[key] = "not_an_array"; // Wrong type
            break;
          case "object":
            params[key] = "not_an_object"; // Wrong type
            break;
          default:
            params[key] = null;
        }

        // Only set one wrong parameter to make the error clear
        break;
      }
    }

    return {
      name: "Error Case - Invalid Type",
      description: "Test error handling with invalid parameter types",
      params,
      expectedBehavior:
        "Should return clear error about invalid parameter type",
      category: "error_case",
    };
  }

  /**
   * Generate realistic parameters based on schema and variant
   */
  public static generateRealisticParams(
    tool: Tool,
    variant: "typical" | "empty" | "maximum" | "special",
  ): Record<string, unknown> {
    const params: Record<string, unknown> = {};

    if (!tool.inputSchema || tool.inputSchema.type !== "object") {
      return params;
    }

    const properties = tool.inputSchema.properties || {};

    for (const [key, schema] of Object.entries(properties)) {
      params[key] = this.generateRealisticValue(
        key,
        schema as JSONSchema7,
        variant,
      );
    }

    return params;
  }

  /**
   * Generate a realistic value based on field name and schema
   */
  private static generateRealisticValue(
    fieldName: string,
    schema: JSONSchema7,
    variant: "typical" | "empty" | "maximum" | "special",
  ): unknown {
    const lowerFieldName = fieldName.toLowerCase();

    switch (schema.type) {
      case "string":
        // Check for enums first
        if (schema.enum && schema.enum.length > 0) {
          return variant === "typical"
            ? schema.enum[0]
            : schema.enum[schema.enum.length - 1];
        }

        // Context-aware string generation
        if (
          lowerFieldName.includes("url") ||
          lowerFieldName.includes("link") ||
          lowerFieldName.includes("endpoint")
        ) {
          return variant === "empty"
            ? ""
            : variant === "maximum"
              ? "https://very-long-domain-name-for-testing-maximum-length.example.com/path/to/resource?param1=value1&param2=value2"
              : variant === "special"
                ? "https://example.com/path?special=!@#$%^&*()"
                : REALISTIC_DATA.urls[
                    Math.floor(Math.random() * REALISTIC_DATA.urls.length)
                  ];
        }

        if (
          lowerFieldName.includes("email") ||
          lowerFieldName.includes("mail")
        ) {
          return variant === "empty"
            ? ""
            : variant === "maximum"
              ? "very.long.email.address.for.testing@subdomain.example-company.co.uk"
              : variant === "special"
                ? "user+tag@example.com"
                : REALISTIC_DATA.emails[
                    Math.floor(Math.random() * REALISTIC_DATA.emails.length)
                  ];
        }

        if (
          lowerFieldName.includes("path") ||
          lowerFieldName.includes("file") ||
          lowerFieldName.includes("directory") ||
          lowerFieldName.includes("folder")
        ) {
          return variant === "empty"
            ? ""
            : variant === "maximum"
              ? "/very/long/path/to/deeply/nested/directory/structure/for/testing/file.txt"
              : variant === "special"
                ? "./path/with spaces/and-special#chars.txt"
                : REALISTIC_DATA.paths[
                    Math.floor(Math.random() * REALISTIC_DATA.paths.length)
                  ];
        }

        if (
          lowerFieldName.includes("query") ||
          lowerFieldName.includes("search") ||
          lowerFieldName.includes("filter")
        ) {
          return variant === "empty"
            ? "test" // Use "test" instead of "" to ensure search tools have valid input
            : variant === "maximum"
              ? "very long search query with many terms for testing maximum input length handling"
              : variant === "special"
                ? 'search with "quotes" and special: characters!'
                : REALISTIC_DATA.queries[
                    Math.floor(Math.random() * REALISTIC_DATA.queries.length)
                  ];
        }

        if (
          lowerFieldName.includes("id") ||
          lowerFieldName.includes("key") ||
          lowerFieldName.includes("identifier")
        ) {
          // Check if this field requires UUID format based on common patterns
          const requiresUuid =
            lowerFieldName.includes("uuid") ||
            lowerFieldName.includes("page_id") ||
            lowerFieldName.includes("database_id") ||
            lowerFieldName.includes("user_id") ||
            lowerFieldName.includes("block_id") ||
            lowerFieldName.includes("comment_id") ||
            lowerFieldName.includes("workspace_id") ||
            lowerFieldName.includes("notion") ||
            // Check schema description for UUID hints
            (schema.description &&
              (schema.description.toLowerCase().includes("uuid") ||
                schema.description
                  .toLowerCase()
                  .includes("universally unique")));

          if (requiresUuid) {
            // Always return a valid UUID for UUID-required fields
            return variant === "empty"
              ? "00000000-0000-0000-0000-000000000000" // Nil UUID
              : "550e8400-e29b-41d4-a716-446655440000"; // Valid UUID v4
          }

          return variant === "empty"
            ? "1" // Minimal non-empty ID to avoid creating invalid entities
            : variant === "maximum"
              ? "very_long_identifier_string_for_testing_maximum_length_handling_in_system"
              : REALISTIC_DATA.ids[
                  Math.floor(Math.random() * REALISTIC_DATA.ids.length)
                ];
        }

        if (
          lowerFieldName.includes("name") ||
          lowerFieldName.includes("title") ||
          lowerFieldName.includes("label")
        ) {
          return variant === "empty"
            ? "a" // Minimal non-empty value to avoid breaking search functionality
            : variant === "maximum"
              ? "Very Long Name For Testing Maximum String Length Handling In The System"
              : variant === "special"
                ? "Name with Special™ Characters® and Émojis 🎉"
                : REALISTIC_DATA.names[
                    Math.floor(Math.random() * REALISTIC_DATA.names.length)
                  ];
        }

        if (
          lowerFieldName.includes("date") ||
          lowerFieldName.includes("time")
        ) {
          return variant === "empty" ? "" : REALISTIC_DATA.timestamps[0];
        }

        // Default string value - try to be contextual
        return variant === "empty"
          ? ""
          : variant === "maximum"
            ? "x".repeat(100)
            : variant === "special"
              ? 'Special chars: !@#$%^&*()_+-=[]{}|;:",.<>?/~`'
              : "test"; // Simple, generic test value that often works

      case "number":
      case "integer":
        if (variant === "maximum") {
          return schema.maximum || 999999;
        }
        if (variant === "empty") {
          return schema.minimum || 0;
        }

        // Context-aware number generation
        if (lowerFieldName.includes("port")) {
          return 8080;
        }
        if (
          lowerFieldName.includes("timeout") ||
          lowerFieldName.includes("delay")
        ) {
          return 5000; // milliseconds
        }
        if (
          lowerFieldName.includes("count") ||
          lowerFieldName.includes("limit")
        ) {
          return 10;
        }
        if (
          lowerFieldName.includes("page") ||
          lowerFieldName.includes("offset")
        ) {
          return 0;
        }
        if (
          lowerFieldName.includes("size") ||
          lowerFieldName.includes("length")
        ) {
          return 100;
        }

        return schema.minimum || 1;

      case "boolean":
        return variant === "empty" ? false : true;

      case "array":
        if (variant === "empty") {
          // For mutation tools with array inputs, empty arrays are valid but useless for testing
          // Generate one minimal item instead to make the test meaningful
          const isMutationField =
            lowerFieldName.includes("entities") ||
            lowerFieldName.includes("relations") ||
            lowerFieldName.includes("observations") ||
            lowerFieldName.includes("documents");

          if (isMutationField && schema.items) {
            // Generate one minimal item even for "empty" variant
            const itemSchema = Array.isArray(schema.items)
              ? schema.items[0]
              : schema.items;
            const item = this.generateValueFromSchema(itemSchema, "empty");
            return [item];
          }
          return [];
        }

        if (variant === "maximum") {
          // Generate multiple items
          const count = 10;
          if (schema.items) {
            const itemSchema = Array.isArray(schema.items)
              ? schema.items[0]
              : schema.items;
            return Array(count)
              .fill(0)
              .map(() => this.generateValueFromSchema(itemSchema, variant));
          }
          return Array(count)
            .fill(0)
            .map((_, i) => `item_${i}`);
        }

        // Typical variant - generate realistic array
        if (schema.items) {
          // Generate 1-2 items based on schema.items
          const itemSchema = Array.isArray(schema.items)
            ? schema.items[0]
            : schema.items;
          const item = this.generateValueFromSchema(itemSchema, variant);
          return [item];
        }

        // Context-aware array generation (fallback for simple arrays without schema.items)
        if (
          lowerFieldName.includes("tag") ||
          lowerFieldName.includes("label")
        ) {
          return ["tag1", "tag2", "tag3"];
        }
        if (lowerFieldName.includes("id")) {
          return ["id_1", "id_2", "id_3"];
        }

        return REALISTIC_DATA.arrays[1];

      case "object":
        // Don't return empty object for "empty" variant
        // Let it fall through to generate minimal object properties
        // This avoids creating objects with no required fields
        if (variant === "maximum") {
          return REALISTIC_DATA.jsonObjects[4]; // deeply nested
        }

        // Context-aware object generation
        if (
          lowerFieldName.includes("config") ||
          lowerFieldName.includes("settings")
        ) {
          return variant === "empty"
            ? { enabled: false }
            : { enabled: true, timeout: 5000, retries: 3 };
        }
        if (
          lowerFieldName.includes("metadata") ||
          lowerFieldName.includes("meta")
        ) {
          return variant === "empty"
            ? { version: "1.0.0" }
            : {
                created: new Date().toISOString(),
                version: "1.0.0",
                author: "test",
              };
        }
        if (
          lowerFieldName.includes("filter") ||
          lowerFieldName.includes("query")
        ) {
          return variant === "empty"
            ? { limit: 1 }
            : { status: "active", type: "user", limit: 10 };
        }

        return variant === "empty" ? { id: 1 } : REALISTIC_DATA.jsonObjects[0];

      default:
        // Return safe default instead of null to prevent tool crashes
        return "test";
    }
  }

  /**
   * Check if tool has string inputs
   */
  private static hasStringInputs(tool: Tool): boolean {
    if (!tool.inputSchema || tool.inputSchema.type !== "object") {
      return false;
    }

    const properties = tool.inputSchema.properties || {};

    for (const schema of Object.values(properties)) {
      if ((schema as JSONSchema7).type === "string") {
        return true;
      }
    }

    return false;
  }

  /**
   * Generate a single realistic value for backward compatibility
   */
  static generateSingleValue(fieldName: string, schema: JSONSchema7): unknown {
    return this.generateRealisticValue(fieldName, schema, "typical");
  }

  /**
   * Generate value from JSON schema definition
   */
  private static generateValueFromSchema(
    schema: JSONSchema7,
    variant: "typical" | "empty" | "maximum" | "special",
  ): unknown {
    if (!schema || !schema.type) {
      // Return safe default instead of null to prevent tool crashes
      return "test";
    }

    switch (schema.type) {
      case "object": {
        const obj: Record<string, unknown> = {};
        if (schema.properties) {
          for (const [key, propSchema] of Object.entries(schema.properties)) {
            obj[key] = this.generateRealisticValue(
              key,
              propSchema as JSONSchema7,
              variant,
            );
          }
        }
        return obj;
      }

      case "array":
        if (schema.items) {
          const itemSchema = Array.isArray(schema.items)
            ? schema.items[0]
            : schema.items;
          const item = this.generateValueFromSchema(itemSchema, variant);
          return [item];
        }
        return [];

      case "string":
        return variant === "empty" ? "" : "test";

      case "number":
      case "integer":
        return variant === "empty" ? 0 : 1;

      case "boolean":
        return variant === "empty" ? false : true;

      default:
        // Return safe default instead of null to prevent tool crashes
        return "test";
    }
  }

  // ============================================================================
  // Tool Category-Aware Generation
  // ============================================================================

  /**
   * Re-exported TOOL_CATEGORY_DATA for backward compatibility.
   * Data is now defined in ./testdata/tool-category-data.ts
   */
  static readonly TOOL_CATEGORY_DATA = TOOL_CATEGORY_DATA;

  /**
   * Generate a value using tool category as hint.
   * For specific field names (url, email, path, etc.), uses field-name detection.
   * For generic field names with specific tool categories, uses category-specific inputs.
   * Otherwise falls back to field-name-based generation.
   *
   * @param fieldName The parameter field name
   * @param schema The parameter schema
   * @param category The tool category from ToolClassifier (e.g., "CALCULATOR", "SEARCH_RETRIEVAL")
   * @returns Generated test value appropriate for the tool type
   */
  static generateValueForCategory(
    fieldName: string,
    schema: Record<string, unknown>,
    category: string,
  ): unknown {
    // Specific field names (url, email, path, etc.) take precedence over category
    // These indicate explicit data type requirements regardless of tool category
    const isSpecificFieldName = SPECIFIC_FIELD_PATTERNS.some((pattern) =>
      pattern.test(fieldName),
    );
    if (isSpecificFieldName) {
      return this.generateSingleValue(fieldName, schema);
    }

    // For specific tool categories (not GENERIC), use category-specific test values
    // This ensures calculator tools get math expressions, search tools get search queries, etc.
    const categoryData = TOOL_CATEGORY_DATA[category];
    if (categoryData?.default) {
      return categoryData.default[0];
    }

    // For GENERIC category or unknown categories, use field-name-based generation
    return this.generateSingleValue(fieldName, schema);
  }
}
