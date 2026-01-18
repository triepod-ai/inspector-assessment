/**
 * Error Response Compliance Checker
 *
 * Validates error response format and structure.
 * Tests both basic error handling and multi-tool conformance.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/ErrorResponseChecker
 * @see GitHub Issue #188
 */

import type { AssessmentContext } from "../../../AssessmentOrchestrator";
import type {
  ProtocolCheckResult,
  CallToolFunction,
  Tool,
  Logger,
  AssessmentConfiguration,
  ContentItem,
} from "../types";

/**
 * Validates error response format compliance.
 */
export class ErrorResponseChecker {
  private config: AssessmentConfiguration;

  constructor(config: AssessmentConfiguration, _logger: Logger) {
    this.config = config;
  }

  // Note: getSpecVersion/getSpecBaseUrl reserved for future use with dynamic spec URLs

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
   * Basic error response check (single tool).
   */
  async checkBasic(
    tools: Tool[],
    callTool: CallToolFunction,
  ): Promise<ProtocolCheckResult> {
    try {
      if (tools.length === 0) {
        return {
          passed: true,
          confidence: "medium",
          evidence: "No tools to test",
          rawResponse: "No tools to test",
        };
      }

      const testTool = tools[0];
      try {
        const result = await callTool(testTool.name, { invalid_param: "test" });
        const isErrorResponse = result.isError === true;
        const hasContent = Array.isArray(result.content);
        const passed =
          (isErrorResponse && hasContent) || (!isErrorResponse && hasContent);

        return {
          passed,
          confidence: "high",
          evidence: "Tested error handling with invalid parameters",
          rawResponse: result,
        };
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const isStructuredError =
          errorMessage.includes("MCP error") ||
          errorMessage.includes("-32") ||
          errorMessage.includes("jsonrpc");

        return {
          passed: isStructuredError,
          confidence: "high",
          evidence: isStructuredError
            ? "Error follows MCP/JSON-RPC format"
            : "Non-standard error",
          rawResponse: error,
        };
      }
    } catch (error) {
      return {
        passed: false,
        confidence: "low",
        evidence: String(error),
        rawResponse: error,
      };
    }
  }

  /**
   * Multi-tool error response format check (conformance-style).
   */
  async checkFormat(context: AssessmentContext): Promise<ProtocolCheckResult> {
    const testTools = this.selectToolsForTesting(context.tools, 3);

    if (testTools.length === 0) {
      return {
        passed: false,
        confidence: "low",
        evidence: "No tools available to test error response format",
        warnings: ["Cannot validate error format without tools"],
      };
    }

    const results: Array<{
      toolName: string;
      passed: boolean;
      isErrorResponse: boolean;
      validations?: Record<string, boolean>;
      error?: string;
    }> = [];

    for (const testTool of testTools) {
      try {
        const result = await this.executeWithTimeout(
          context.callTool(testTool.name, {
            __test_invalid_param__: "should_cause_error",
          }),
          this.config.testTimeout ?? 5000,
        );

        const contentArray = Array.isArray(result.content)
          ? result.content
          : [];
        const validations = {
          hasIsErrorFlag: result.isError === true,
          hasContentArray: Array.isArray(result.content),
          contentNotEmpty: contentArray.length > 0,
          firstContentHasType:
            (contentArray as ContentItem[])[0]?.type !== undefined,
          firstContentIsTextOrResource:
            (contentArray as ContentItem[])[0]?.type === "text" ||
            (contentArray as ContentItem[])[0]?.type === "resource",
          hasErrorMessage:
            typeof (contentArray as ContentItem[])[0]?.text === "string" &&
            ((contentArray as ContentItem[])[0]?.text?.length ?? 0) > 0,
        };

        if (!result.isError && contentArray.length > 0) {
          results.push({
            toolName: testTool.name,
            passed: true,
            isErrorResponse: false,
            validations,
          });
        } else {
          const passedValidations = Object.values(validations).filter((v) => v);
          const allPassed =
            passedValidations.length === Object.keys(validations).length;
          results.push({
            toolName: testTool.name,
            passed: allPassed,
            isErrorResponse: true,
            validations,
          });
        }
      } catch (error) {
        results.push({
          toolName: testTool.name,
          passed: false,
          isErrorResponse: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const errorResponseResults = results.filter((r) => r.isErrorResponse);
    const passedCount = results.filter((r) => r.passed).length;
    const allPassed = passedCount === results.length;

    let confidence: "high" | "medium" | "low";
    if (errorResponseResults.length === 0) {
      confidence = "medium";
    } else if (allPassed) {
      confidence = "high";
    } else {
      confidence = "medium";
    }

    return {
      passed: allPassed,
      confidence,
      evidence: `Tested ${results.length} tool(s): ${passedCount}/${results.length} passed error format validation`,
      details: {
        toolResults: results,
        testedToolCount: results.length,
        errorResponseCount: errorResponseResults.length,
      },
      warnings: allPassed
        ? undefined
        : [
            "Error response format issues detected in some tools",
            "Ensure all errors have isError: true and content array with text type",
          ],
    };
  }

  /**
   * Select representative tools for testing (first, middle, last for diversity).
   */
  private selectToolsForTesting(
    tools: Array<{ name: string; inputSchema?: unknown }>,
    maxTools: number = 3,
  ): Array<{ name: string; inputSchema?: unknown }> {
    if (tools.length <= maxTools) return tools;
    const indices = [0, Math.floor(tools.length / 2), tools.length - 1];
    return [...new Set(indices)].slice(0, maxTools).map((i) => tools[i]);
  }
}
