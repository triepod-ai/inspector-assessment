/**
 * Functionality Assessor Module
 * Tests tool functionality and basic operations
 */

import { FunctionalityAssessment, ToolTestResult } from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

export class FunctionalityAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<FunctionalityAssessment> {
    this.log("Starting functionality assessment");

    const toolResults: ToolTestResult[] = [];
    const brokenTools: string[] = [];
    let workingTools = 0;

    for (const tool of context.tools) {
      this.testCount++;

      if (!this.config.autoTest) {
        // Skip actual testing if autoTest is disabled
        toolResults.push({
          toolName: tool.name,
          tested: false,
          status: "untested",
        });
        continue;
      }

      const result = await this.testTool(tool, context.callTool);
      toolResults.push(result);

      if (result.status === "working") {
        workingTools++;
      } else if (result.status === "broken") {
        brokenTools.push(tool.name);

        if (this.config.skipBrokenTools) {
          this.log(`Skipping further tests for broken tool: ${tool.name}`);
        }
      }
    }

    const totalTools = context.tools.length;
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

      // Check if response indicates an error
      if (response?.isError) {
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

    // Generate minimal valid values for all fields
    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, any>,
    )) {
      params[key] = this.generateParamValue(prop);
    }

    return params;
  }

  private generateParamValue(prop: any): unknown {
    const type = prop.type;

    switch (type) {
      case "string":
        if (prop.enum) return prop.enum[0];
        if (prop.format === "uri") return "https://example.com";
        if (prop.format === "email") return "test@example.com";
        return "test";

      case "number":
      case "integer":
        if (prop.minimum !== undefined) return prop.minimum;
        if (prop.maximum !== undefined) return prop.maximum;
        return 0;

      case "boolean":
        return false;

      case "array":
        // Generate array with sample items based on items schema
        if (prop.items) {
          return [this.generateParamValue(prop.items)];
        }
        return [];

      case "object":
        // Generate object with properties based on schema
        if (prop.properties) {
          const obj: Record<string, unknown> = {};
          for (const [key, subProp] of Object.entries(prop.properties)) {
            obj[key] = this.generateParamValue(subProp);
          }
          return obj;
        }
        return {};

      default:
        return null;
    }
  }

  // Add public method for testing purposes
  private generateTestInput(schema: any): unknown {
    return this.generateParamValue(schema);
  }

  private generateExplanation(
    total: number,
    tested: number,
    working: number,
    broken: string[],
  ): string {
    const parts: string[] = [];

    if (total === 0) {
      return "No tools available to test.";
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
