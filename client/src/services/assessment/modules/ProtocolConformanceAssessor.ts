/**
 * Protocol Conformance Assessor Module
 *
 * Validates MCP protocol-level compliance using conformance-inspired tests.
 * Complements ErrorHandlingAssessor (application-level) with protocol-level validation.
 *
 * Protocol Checks:
 * 1. Error Response Format - Validates isError flag, content array structure
 * 2. Content Type Support - Validates valid content types (text, image, audio, resource)
 * 3. Initialization Handshake - Validates serverInfo completeness
 *
 * @module assessment/modules/ProtocolConformanceAssessor
 */

import { AssessmentStatus } from "@/lib/assessmentTypes";
import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type {
  ProtocolConformanceAssessment,
  ProtocolCheck,
} from "@/lib/assessment/extendedTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

// MCP content item structure for type safety
interface ContentItem {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
}

// Valid MCP content types
const VALID_CONTENT_TYPES = [
  "text",
  "image",
  "audio",
  "resource",
  "resource_link",
] as const;

/**
 * @deprecated Use ProtocolComplianceAssessor instead. Will be removed in v2.0.0.
 */
export class ProtocolConformanceAssessor extends BaseAssessor<ProtocolConformanceAssessment> {
  constructor(config: AssessmentConfiguration) {
    super(config);
    this.logger.warn(
      "ProtocolConformanceAssessor is deprecated. Use ProtocolComplianceAssessor instead. " +
        "This module will be removed in v2.0.0.",
      {
        module: "ProtocolConformanceAssessor",
        replacement: "ProtocolComplianceAssessor",
      },
    );
  }

  /**
   * Select representative tools for testing (first, middle, last for diversity)
   */
  private selectToolsForTesting(
    tools: Array<{ name: string; inputSchema?: unknown }>,
    maxTools: number = 3,
  ): Array<{ name: string; inputSchema?: unknown }> {
    if (tools.length <= maxTools) return tools;
    const indices = [0, Math.floor(tools.length / 2), tools.length - 1];
    return [...new Set(indices)].slice(0, maxTools).map((i) => tools[i]);
  }

  /**
   * Get MCP spec version from config or use default
   */
  private getSpecVersion(): string {
    return this.config.mcpProtocolVersion || "2025-06";
  }

  /**
   * Get base URL for MCP specification
   */
  private getSpecBaseUrl(): string {
    return `https://modelcontextprotocol.io/specification/${this.getSpecVersion()}`;
  }

  /**
   * Get lifecycle spec URL
   */
  private getSpecLifecycleUrl(): string {
    return `${this.getSpecBaseUrl()}/basic/lifecycle`;
  }

  /**
   * Get tools spec URL
   */
  private getSpecToolsUrl(): string {
    return `${this.getSpecBaseUrl()}/server/tools`;
  }

  async assess(
    context: AssessmentContext,
  ): Promise<ProtocolConformanceAssessment> {
    this.logger.info("Starting protocol conformance assessment");

    // Run all protocol checks
    const checks = {
      errorResponseFormat: await this.checkErrorResponseFormat(context),
      contentTypeSupport: await this.checkContentTypeSupport(context),
      initializationHandshake: await this.checkInitializationHandshake(context),
    };

    // Calculate score
    const allChecks = Object.values(checks);
    const passedChecks = allChecks.filter((c) => c.passed).length;
    const totalChecks = allChecks.length;
    const score = totalChecks > 0 ? (passedChecks / totalChecks) * 100 : 0;

    // Track test count
    this.testCount = totalChecks;

    // Determine status based on score and critical checks
    const status = this.determineAssessmentStatus(score, checks);
    const explanation = this.generateExplanation(score, checks);
    const recommendations = this.generateRecommendations(checks);

    this.logger.info(
      `Protocol conformance: ${passedChecks}/${totalChecks} checks passed (${score.toFixed(1)}%)`,
    );

    return {
      checks,
      score,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Check 1: Error Response Format
   * Validates that error responses follow MCP protocol structure
   *
   * Tests multiple tools (up to 3) for representative coverage.
   * Based on conformance's ToolsCallErrorScenario:
   * - isError flag must be true
   * - content must be an array
   * - content items must have type: "text" and text field
   */
  private async checkErrorResponseFormat(
    context: AssessmentContext,
  ): Promise<ProtocolCheck> {
    const testTools = this.selectToolsForTesting(context.tools, 3);

    if (testTools.length === 0) {
      return {
        passed: false,
        confidence: "low",
        evidence: "No tools available to test error response format",
        specReference: this.getSpecLifecycleUrl(),
        warnings: ["Cannot validate error format without tools"],
      };
    }

    // Test each selected tool and collect results
    const results: Array<{
      toolName: string;
      passed: boolean;
      isErrorResponse: boolean;
      validations?: Record<string, boolean>;
      error?: string;
    }> = [];

    for (const testTool of testTools) {
      try {
        // Call with parameters designed to cause an error
        const result = await this.executeWithTimeout(
          context.callTool(testTool.name, {
            __test_invalid_param__: "should_cause_error",
          }),
          this.config.testTimeout,
        );

        // Validate MCP error response structure
        const contentArray = Array.isArray(result.content)
          ? result.content
          : [];
        const validations = {
          hasIsErrorFlag: result.isError === true,
          hasContentArray: Array.isArray(result.content),
          contentNotEmpty: contentArray.length > 0,
          firstContentHasType: contentArray[0]?.type !== undefined,
          firstContentIsTextOrResource:
            contentArray[0]?.type === "text" ||
            contentArray[0]?.type === "resource",
          hasErrorMessage:
            typeof contentArray[0]?.text === "string" &&
            contentArray[0].text.length > 0,
        };

        // Tool did not return error - might have accepted params
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
        // Tool threw exception instead of returning error response
        this.logger.debug(
          `Tool ${testTool.name} threw exception instead of error response`,
          {
            error: error instanceof Error ? error.message : String(error),
          },
        );
        results.push({
          toolName: testTool.name,
          passed: false,
          isErrorResponse: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Aggregate results
    const errorResponseResults = results.filter((r) => r.isErrorResponse);
    const passedCount = results.filter((r) => r.passed).length;
    const allPassed = passedCount === results.length;

    // Determine confidence based on error response coverage
    let confidence: "high" | "medium" | "low";
    if (errorResponseResults.length === 0) {
      // No tools returned errors - all accepted invalid params
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
      specReference: this.getSpecLifecycleUrl(),
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
   * Check 2: Content Type Support
   * Validates that tool responses use valid MCP content types
   *
   * Valid content types: text, image, audio, resource, resource_link
   */
  private async checkContentTypeSupport(
    context: AssessmentContext,
  ): Promise<ProtocolCheck> {
    try {
      const testTool = context.tools[0];
      if (!testTool) {
        return {
          passed: false,
          confidence: "low",
          evidence: "No tools available to test content types",
          specReference: this.getSpecToolsUrl(),
        };
      }

      // Check if tool has required params - if so, we can't easily test
      const schema = testTool.inputSchema;
      const hasRequiredParams =
        schema?.required &&
        Array.isArray(schema.required) &&
        schema.required.length > 0;

      if (hasRequiredParams) {
        return {
          passed: true,
          confidence: "low",
          evidence:
            "Cannot test content types without knowing valid parameters - tool has required params",
          specReference: this.getSpecToolsUrl(),
          warnings: [
            "Content type validation requires valid tool parameters",
            "Consider adding a tool without required params for protocol testing",
          ],
        };
      }

      // Call with empty params
      const result = await this.executeWithTimeout(
        context.callTool(testTool.name, {}),
        this.config.testTimeout,
      );

      // Validate content structure
      const contentArray = Array.isArray(result.content) ? result.content : [];
      const validations = {
        hasContentArray: Array.isArray(result.content),
        contentNotEmpty: contentArray.length > 0,
        allContentHasType: (contentArray as ContentItem[]).every(
          (c) => c.type !== undefined,
        ),
        validContentTypes: (contentArray as ContentItem[]).every((c) =>
          VALID_CONTENT_TYPES.includes(
            c.type as (typeof VALID_CONTENT_TYPES)[number],
          ),
        ),
      };

      const passedValidations = Object.values(validations).filter((v) => v);
      const allPassed =
        passedValidations.length === Object.keys(validations).length;

      // Get detected content types for evidence
      const detectedTypes = (contentArray as ContentItem[]).map((c) => c.type);
      const invalidTypes = detectedTypes.filter(
        (t) =>
          !VALID_CONTENT_TYPES.includes(
            t as (typeof VALID_CONTENT_TYPES)[number],
          ),
      );

      return {
        passed: allPassed,
        confidence: allPassed ? "high" : "medium",
        evidence: `${passedValidations.length}/${Object.keys(validations).length} content type checks passed`,
        specReference: this.getSpecToolsUrl(),
        details: {
          validations,
          detectedContentTypes: detectedTypes,
          invalidContentTypes:
            invalidTypes.length > 0 ? invalidTypes : undefined,
        },
        warnings:
          invalidTypes.length > 0
            ? [`Invalid content types found: ${invalidTypes.join(", ")}`]
            : undefined,
      };
    } catch (error) {
      this.logger.error("Content type validation failed", { error });
      return {
        passed: false,
        confidence: "medium",
        evidence: "Could not test content types due to error",
        specReference: this.getSpecToolsUrl(),
        details: {
          error: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }

  /**
   * Check 3: Initialization Handshake
   * Validates that server completed proper initialization
   *
   * Based on conformance's ServerInitializeScenario:
   * - Server must provide name
   * - Server should provide version
   * - Server should declare capabilities
   */
  private async checkInitializationHandshake(
    context: AssessmentContext,
  ): Promise<ProtocolCheck> {
    const serverInfo = context.serverInfo;
    const serverCapabilities = context.serverCapabilities;

    const validations = {
      hasServerInfo: serverInfo !== undefined && serverInfo !== null,
      hasServerName:
        typeof serverInfo?.name === "string" && serverInfo.name.length > 0,
      hasServerVersion:
        typeof serverInfo?.version === "string" &&
        serverInfo.version.length > 0,
      hasCapabilities: serverCapabilities !== undefined,
    };

    const passedValidations = Object.values(validations).filter((v) => v);
    const allPassed =
      passedValidations.length === Object.keys(validations).length;

    // Missing version is a warning, not a failure
    const hasMinimumInfo =
      validations.hasServerInfo && validations.hasServerName;

    return {
      passed: hasMinimumInfo,
      confidence: allPassed ? "high" : "medium",
      evidence: `${passedValidations.length}/${Object.keys(validations).length} initialization checks passed`,
      specReference: this.getSpecLifecycleUrl(),
      details: {
        validations,
        serverInfo: {
          name: serverInfo?.name,
          version: serverInfo?.version,
          hasCapabilities: !!serverCapabilities,
        },
      },
      warnings: !allPassed
        ? ([
            !validations.hasServerVersion
              ? "Server should provide version for better compatibility tracking"
              : undefined,
            !validations.hasCapabilities
              ? "Server should declare capabilities for feature negotiation"
              : undefined,
          ].filter(Boolean) as string[])
        : undefined,
    };
  }

  /**
   * Determine overall assessment status based on score and critical check failures
   */
  private determineAssessmentStatus(
    score: number,
    checks: Record<string, ProtocolCheck>,
  ): AssessmentStatus {
    // Critical checks that must pass
    const criticalChecks = [
      checks.errorResponseFormat,
      checks.initializationHandshake,
    ];

    // If any critical check fails with high confidence, FAIL
    const criticalFailure = criticalChecks.some(
      (c) => !c.passed && c.confidence === "high",
    );

    if (criticalFailure) {
      return "FAIL";
    }

    // Score-based determination
    if (score >= 90) {
      return "PASS";
    } else if (score >= 70) {
      return "NEED_MORE_INFO";
    } else {
      return "FAIL";
    }
  }

  /**
   * Generate human-readable explanation of assessment results
   */
  private generateExplanation(
    score: number,
    checks: Record<string, ProtocolCheck>,
  ): string {
    const passedCount = Object.values(checks).filter((c) => c.passed).length;
    const totalCount = Object.keys(checks).length;

    let explanation = `Protocol conformance assessment: ${passedCount}/${totalCount} checks passed (${score.toFixed(1)}% compliance).\n\n`;

    // Add details for failed checks
    const failedChecks = Object.entries(checks).filter(
      ([_, check]) => !check.passed,
    );

    if (failedChecks.length > 0) {
      explanation += "Failed checks:\n";
      failedChecks.forEach(([name, check]) => {
        const readableName = name
          .replace(/([A-Z])/g, " $1")
          .replace(/^./, (s) => s.toUpperCase());
        explanation += `• ${readableName}: ${check.evidence}\n`;
        if (check.warnings) {
          check.warnings.forEach((w) => {
            explanation += `  ⚠️ ${w}\n`;
          });
        }
      });
    } else {
      explanation +=
        "All protocol conformance checks passed. Server follows MCP specification correctly.";
    }

    return explanation;
  }

  /**
   * Generate recommendations for improving protocol conformance
   */
  private generateRecommendations(
    checks: Record<string, ProtocolCheck>,
  ): string[] {
    const recommendations: string[] = [];

    if (!checks.errorResponseFormat.passed) {
      recommendations.push(
        "Ensure error responses include 'isError: true' flag and properly formatted content array",
      );
      recommendations.push(
        "Error messages should be returned in content array with type 'text', not thrown as exceptions",
      );
    }

    if (!checks.contentTypeSupport.passed) {
      recommendations.push(
        "Validate that all tool responses include a content array with properly typed items",
      );
      recommendations.push(
        "Use only valid content types: text, image, audio, resource, resource_link",
      );
    }

    if (!checks.initializationHandshake.passed) {
      recommendations.push(
        "Ensure server provides name and version during initialization",
      );
      recommendations.push(
        "Declare server capabilities for proper feature negotiation",
      );
    }

    // General recommendations
    if (recommendations.length === 0) {
      recommendations.push(
        "Protocol conformance is good. Consider testing with official @modelcontextprotocol/conformance suite for comprehensive validation.",
      );
    } else {
      recommendations.push(
        `Review MCP specification: ${this.getSpecBaseUrl()}/`,
      );
    }

    return recommendations;
  }
}
