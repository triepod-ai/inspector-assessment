/**
 * Functionality Assessor Module
 * Tests tool functionality and basic operations
 */

import { FunctionalityAssessment, ToolTestResult } from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { ResponseValidator } from "../ResponseValidator";
import { createConcurrencyLimit } from "../lib/concurrencyLimit";

export class FunctionalityAssessor extends BaseAssessor {
  /**
   * Select tools for testing based on configuration
   */
  private selectToolsForTesting(tools: any[]): any[] {
    // Prefer new selectedToolsForTesting configuration
    // Note: undefined/null means "test all" (default), empty array [] means "test none" (explicit)
    if (this.config.selectedToolsForTesting !== undefined) {
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      const selectedTools = tools.filter((tool) =>
        selectedNames.has(tool.name),
      );

      // Empty array means user explicitly selected 0 tools
      if (this.config.selectedToolsForTesting.length === 0) {
        this.log(
          `User selected 0 tools for functionality testing - skipping tests`,
        );
        return [];
      }

      // If no tools matched the names (config out of sync), log warning but respect selection
      if (selectedTools.length === 0) {
        this.log(
          `Warning: No tools matched selection (${this.config.selectedToolsForTesting.join(", ")})`,
        );
        return [];
      }

      this.log(
        `Testing ${selectedTools.length} selected tools out of ${tools.length} for functionality`,
      );
      return selectedTools;
    }

    // Default: test all tools
    this.log(`Testing all ${tools.length} tools for functionality`);
    return tools;
  }

  async assess(context: AssessmentContext): Promise<FunctionalityAssessment> {
    this.log(
      `Starting functionality assessment${this.config.reviewerMode ? " (reviewer mode - quick verification)" : ""}`,
    );

    const toolResults: ToolTestResult[] = [];
    const brokenTools: string[] = [];
    let workingTools = 0;

    // Select tools for testing
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Parallel tool testing with concurrency limit
    const concurrency = this.config.maxParallelTests ?? 5;
    const limit = createConcurrencyLimit(concurrency);

    // Progress tracking for batched events
    const totalEstimate = toolsToTest.length;
    let completedTests = 0;
    let lastBatchTime = Date.now();
    const startTime = Date.now();
    const BATCH_INTERVAL = 500;
    const BATCH_SIZE = 5; // Smaller batch for functionality (fewer tests)
    let batchCount = 0;

    const emitProgressBatch = () => {
      if (context.onProgress) {
        context.onProgress({
          type: "test_batch",
          module: "functionality",
          completed: completedTests,
          total: totalEstimate,
          batchSize: batchCount,
          elapsed: Date.now() - startTime,
        });
      }
      batchCount = 0;
      lastBatchTime = Date.now();
    };

    this.log(
      `Testing ${toolsToTest.length} tools with concurrency limit of ${concurrency}`,
    );

    const results = await Promise.all(
      toolsToTest.map((tool) =>
        limit(async () => {
          this.testCount++;
          completedTests++;
          batchCount++;

          const result = await this.testTool(tool, context.callTool);

          // Emit progress batch if threshold reached
          const timeSinceLastBatch = Date.now() - lastBatchTime;
          if (
            batchCount >= BATCH_SIZE ||
            timeSinceLastBatch >= BATCH_INTERVAL
          ) {
            emitProgressBatch();
          }

          // Add delay between tests to avoid rate limiting
          if (
            this.config.delayBetweenTests &&
            this.config.delayBetweenTests > 0
          ) {
            await this.sleep(this.config.delayBetweenTests);
          }

          return result;
        }),
      ),
    );

    // Final flush of any remaining progress
    if (batchCount > 0) {
      emitProgressBatch();
    }

    // Post-process results after parallel execution
    for (const result of results) {
      toolResults.push(result);

      if (result.status === "working") {
        workingTools++;
      } else if (result.status === "broken") {
        brokenTools.push(result.toolName);

        if (this.config.skipBrokenTools) {
          this.log(
            `Skipping further tests for broken tool: ${result.toolName}`,
          );
        }
      }
    }

    const totalTools = toolsToTest.length;
    const testedTools = toolResults.filter((r) => r.tested).length;
    const coveragePercentage =
      testedTools > 0 ? (workingTools / testedTools) * 100 : 0;

    const status = this.determineStatus(workingTools, testedTools);
    const explanation = this.generateExplanation(
      totalTools,
      testedTools,
      workingTools,
      brokenTools,
    );

    return {
      totalTools,
      testedTools,
      workingTools,
      brokenTools,
      coveragePercentage,
      status,
      explanation,
      toolResults,
    };
  }

  private async testTool(
    tool: any,
    callTool: (name: string, params: Record<string, unknown>) => Promise<any>,
  ): Promise<ToolTestResult> {
    const startTime = Date.now();

    try {
      // Generate minimal valid parameters
      const testParams = this.generateMinimalParams(tool);

      this.log(
        `Testing tool: ${tool.name} with params: ${JSON.stringify(testParams)}`,
      );

      // Execute tool with timeout
      const response = await this.executeWithTimeout(
        callTool(tool.name, testParams),
        this.config.testTimeout,
      );

      const executionTime = Date.now() - startTime;

      // Check if response indicates an error using base class method
      // Use strict mode for functionality testing - only check explicit error indicators
      // This prevents false positives where valid responses mention "error" in their content
      if (this.isErrorResponse(response, true)) {
        // Check if this is a business logic error (validation error)
        // Tools that correctly validate inputs should be marked as "working"
        const validationContext = {
          tool,
          input: testParams,
          response,
        };

        if (ResponseValidator.isBusinessLogicError(validationContext)) {
          // Tool is correctly validating inputs - this is expected behavior
          return {
            toolName: tool.name,
            tested: true,
            status: "working",
            executionTime,
            testParameters: testParams,
            response,
          };
        }

        // Real tool failure (not just validation)
        return {
          toolName: tool.name,
          tested: true,
          status: "broken",
          error: this.extractErrorMessage(response),
          executionTime,
          testParameters: testParams,
          response,
        };
      }

      return {
        toolName: tool.name,
        tested: true,
        status: "working",
        executionTime,
        testParameters: testParams,
        response,
      };
    } catch (error) {
      return {
        toolName: tool.name,
        tested: true,
        status: "broken",
        error: this.extractErrorMessage(error),
        executionTime: Date.now() - startTime,
      };
    }
  }

  private generateMinimalParams(tool: any): Record<string, unknown> {
    if (!tool.inputSchema) return {};

    const schema =
      typeof tool.inputSchema === "string"
        ? this.safeJsonParse(tool.inputSchema)
        : tool.inputSchema;

    if (!schema?.properties) return {};

    const params: Record<string, unknown> = {};
    const required = schema.required || [];

    // For functionality testing, only generate REQUIRED parameters
    // This avoids triggering validation errors on optional parameters with complex rules
    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, any>,
    )) {
      // Only include required parameters for basic functionality testing
      if (required.includes(key)) {
        params[key] = this.generateParamValue(prop, key);
      }
    }

    return params;
  }

  private generateParamValue(
    prop: any,
    fieldName?: string,
    includeOptional = false,
  ): unknown {
    const type = prop.type;

    // Check for UUID format requirements
    const lowerFieldName = fieldName?.toLowerCase() || "";
    const requiresUuid =
      lowerFieldName.includes("uuid") ||
      lowerFieldName.includes("page_id") ||
      lowerFieldName.includes("database_id") ||
      lowerFieldName.includes("user_id") ||
      lowerFieldName.includes("block_id") ||
      lowerFieldName.includes("comment_id") ||
      lowerFieldName.includes("workspace_id") ||
      (prop.description &&
        (prop.description.toLowerCase().includes("uuid") ||
          prop.description.toLowerCase().includes("universally unique")));

    switch (type) {
      case "string":
        if (prop.enum) return prop.enum[0];
        if (prop.format === "uri") return "https://example.com";
        if (prop.format === "email") return "test@example.com";
        // Return valid UUID for UUID-required fields
        if (requiresUuid) return "550e8400-e29b-41d4-a716-446655440000";
        return "test";

      case "number":
      case "integer":
        if (prop.minimum !== undefined) return prop.minimum;
        if (prop.maximum !== undefined) return Math.min(prop.maximum, 10);
        // Use 10 instead of 0 for better validity (page_size, limit, etc.)
        return 10;

      case "boolean":
        return false;

      case "array":
        // Generate array with sample items based on items schema
        if (prop.items) {
          return [
            this.generateParamValue(prop.items, undefined, includeOptional),
          ];
        }
        return [];

      case "object":
        // Generate object with properties based on schema
        if (prop.properties) {
          const obj: Record<string, unknown> = {};
          const requiredProps = prop.required || [];

          // Generate properties based on includeOptional flag
          // includeOptional=false: Only required properties (for functionality testing)
          // includeOptional=true: All properties (for test input generation)
          for (const [key, subProp] of Object.entries(prop.properties)) {
            if (includeOptional || requiredProps.includes(key)) {
              obj[key] = this.generateParamValue(subProp, key, includeOptional);
            }
          }
          return obj;
        }
        return {};

      default:
        // Handle union types (anyOf, oneOf) by trying the first option
        if (prop.anyOf && Array.isArray(prop.anyOf) && prop.anyOf.length > 0) {
          return this.generateParamValue(
            prop.anyOf[0],
            fieldName,
            includeOptional,
          );
        }
        if (prop.oneOf && Array.isArray(prop.oneOf) && prop.oneOf.length > 0) {
          return this.generateParamValue(
            prop.oneOf[0],
            fieldName,
            includeOptional,
          );
        }
        // Return empty object instead of null to avoid validation errors
        return {};
    }
  }

  // Public method for testing purposes - allows tests to verify parameter generation logic
  // Always includes optional properties to test full schema
  public generateTestInput(schema: any): unknown {
    return this.generateParamValue(schema, undefined, true);
  }

  private generateExplanation(
    total: number,
    tested: number,
    working: number,
    broken: string[],
  ): string {
    const parts: string[] = [];

    if (total === 0) {
      return "No tools selected for functionality testing. Select tools to run functionality assessments.";
    }

    parts.push(`Tested ${tested} out of ${total} tools.`);

    if (tested > 0) {
      const successRate = (working / tested) * 100;
      parts.push(
        `${working} tools working correctly (${successRate.toFixed(1)}% success rate).`,
      );
    }

    if (broken.length > 0) {
      if (broken.length <= 3) {
        parts.push(`Broken tools: ${broken.join(", ")}.`);
      } else {
        parts.push(`${broken.length} tools failed testing.`);
      }
    }

    return parts.join(" ");
  }
}
