/**
 * Unified Protocol Compliance Assessor
 *
 * Merges protocol compliance and error handling into a single Phase 2 module.
 * Produces both `mcpSpecCompliance` (or `protocolCompliance`) and `errorHandling` results.
 *
 * @module assessment/modules/ProtocolComplianceAssessor
 * @see GitHub Issue #188
 */

import {
  MCPSpecComplianceAssessment,
  AssessmentStatus,
  ErrorHandlingAssessment,
  ErrorTestDetail,
  ProtocolChecks,
} from "@/lib/assessmentTypes";
import type { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type { ValidationSummaryProgress } from "@/lib/assessment/progressTypes";
import { BaseAssessor } from "../BaseAssessor";
import { AssessmentContext } from "../../AssessmentOrchestrator";
import { createConcurrencyLimit } from "../../lib/concurrencyLimit";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Protocol check sub-modules
import { JsonRpcChecker } from "./protocolChecks/JsonRpcChecker";
import { SchemaChecker } from "./protocolChecks/SchemaChecker";
import { ServerInfoChecker } from "./protocolChecks/ServerInfoChecker";
import { CapabilitiesChecker } from "./protocolChecks/CapabilitiesChecker";
import { ErrorResponseChecker } from "./protocolChecks/ErrorResponseChecker";
import { ContentTypeChecker } from "./protocolChecks/ContentTypeChecker";
import { InitializationChecker } from "./protocolChecks/InitializationChecker";
import { OutputSchemaAnalyzer } from "./protocolChecks/OutputSchemaAnalyzer";
import { MetadataExtractor } from "./protocolChecks/MetadataExtractor";

// Error handling sub-modules
import { InputValidationTester } from "./errorHandling/InputValidationTester";
import { ErrorHandlingScorer } from "./errorHandling/ErrorHandlingScorer";
import { ErrorHandlingReporter } from "./errorHandling/ErrorHandlingReporter";

/**
 * Unified Protocol Compliance Assessment Result
 * Contains both protocol compliance and error handling results.
 */
export interface UnifiedProtocolComplianceAssessment extends MCPSpecComplianceAssessment {
  /** Error handling results for backward compatibility */
  errorHandling: ErrorHandlingAssessment;
}

/**
 * Unified Protocol Compliance Assessor
 *
 * Combines:
 * - Protocol compliance checks (JSON-RPC, schema, capabilities, etc.)
 * - Error handling tests (missing params, wrong types, invalid values, etc.)
 */
export class ProtocolComplianceAssessor extends BaseAssessor<UnifiedProtocolComplianceAssessment> {
  // Protocol checkers
  private jsonRpcChecker: JsonRpcChecker;
  private schemaChecker: SchemaChecker;
  private serverInfoChecker: ServerInfoChecker;
  private capabilitiesChecker: CapabilitiesChecker;
  private errorResponseChecker: ErrorResponseChecker;
  private contentTypeChecker: ContentTypeChecker;
  private initializationChecker: InitializationChecker;
  private outputSchemaAnalyzer: OutputSchemaAnalyzer;
  private metadataExtractor: MetadataExtractor;

  // Error handling components
  private inputValidationTester: InputValidationTester;
  private errorHandlingScorer: ErrorHandlingScorer;
  private errorHandlingReporter: ErrorHandlingReporter;

  constructor(config: AssessmentConfiguration) {
    super(config);

    // Initialize protocol checkers
    this.jsonRpcChecker = new JsonRpcChecker(config, this.logger);
    this.schemaChecker = new SchemaChecker(config, this.logger);
    this.serverInfoChecker = new ServerInfoChecker(config, this.logger);
    this.capabilitiesChecker = new CapabilitiesChecker(config, this.logger);
    this.errorResponseChecker = new ErrorResponseChecker(config, this.logger);
    this.contentTypeChecker = new ContentTypeChecker(config, this.logger);
    this.initializationChecker = new InitializationChecker(config, this.logger);
    this.outputSchemaAnalyzer = new OutputSchemaAnalyzer(config, this.logger);
    this.metadataExtractor = new MetadataExtractor(config, this.logger);

    // Initialize error handling components
    this.inputValidationTester = new InputValidationTester(config, this.logger);
    this.errorHandlingScorer = new ErrorHandlingScorer(config, this.logger);
    this.errorHandlingReporter = new ErrorHandlingReporter(config, this.logger);
  }

  // Note: getSpecVersion reserved for future use with dynamic version detection

  /**
   * Unified assessment combining protocol compliance and error handling.
   */
  async assess(
    context: AssessmentContext,
  ): Promise<UnifiedProtocolComplianceAssessment> {
    this.logger.info(
      "Starting unified protocol compliance and error handling assessment",
    );

    // Run protocol compliance checks
    const protocolResult = await this.runProtocolChecks(context);

    // Run error handling tests
    const errorHandlingResult = await this.runErrorHandlingTests(context);

    // Combine test counts
    this.testCount = protocolResult.testCount + errorHandlingResult.testCount;

    // Return unified result
    return {
      ...protocolResult.assessment,
      errorHandling: errorHandlingResult.assessment,
    };
  }

  /**
   * Run all protocol compliance checks.
   */
  private async runProtocolChecks(context: AssessmentContext): Promise<{
    assessment: MCPSpecComplianceAssessment;
    testCount: number;
  }> {
    const protocolVersion = this.extractProtocolVersion(context);
    const tools = context.tools;
    const callTool = context.callTool;

    // Run protocol checks
    const schemaCheck = this.schemaChecker.check(tools);
    const jsonRpcCheck = await this.jsonRpcChecker.check(callTool);
    const errorCheck = await this.errorResponseChecker.checkBasic(
      tools,
      callTool,
    );
    const capabilitiesCheck = this.capabilitiesChecker.check(context);
    const serverInfoCheck = this.serverInfoChecker.check(context.serverInfo);

    const protocolChecks: ProtocolChecks = {
      jsonRpcCompliance: {
        passed: jsonRpcCheck.passed,
        confidence: "high",
        evidence: jsonRpcCheck.evidence || "Verified via actual tool call",
        rawResponse: jsonRpcCheck.rawResponse,
      },
      serverInfoValidity: {
        passed: serverInfoCheck.passed,
        confidence: serverInfoCheck.confidence,
        evidence: serverInfoCheck.evidence || "Validated server info structure",
        rawResponse: serverInfoCheck.rawResponse,
      },
      schemaCompliance: {
        passed: schemaCheck.passed,
        confidence: schemaCheck.confidence,
        warnings: schemaCheck.warnings,
        rawResponse: tools.map((t) => ({
          name: t.name,
          inputSchema: t.inputSchema,
        })),
      },
      errorResponseCompliance: {
        passed: errorCheck.passed,
        confidence: "high",
        evidence:
          errorCheck.evidence ||
          "Tested error handling with invalid parameters",
        rawResponse: errorCheck.rawResponse,
      },
      structuredOutputSupport: (() => {
        const { coverage, toolResults } =
          this.outputSchemaAnalyzer.analyze(tools);
        return {
          passed: coverage.withOutputSchema > 0,
          confidence: "high" as const,
          evidence: `${coverage.withOutputSchema}/${coverage.totalTools} tools have outputSchema (${coverage.coveragePercent}%)`,
          coverage,
          toolResults,
          rawResponse: tools.map((t) => ({
            name: t.name,
            hasOutputSchema: !!t.outputSchema,
            outputSchema: t.outputSchema,
          })),
        };
      })(),
      capabilitiesCompliance: {
        passed: capabilitiesCheck.passed,
        confidence: capabilitiesCheck.confidence,
        evidence: capabilitiesCheck.evidence,
        warnings: capabilitiesCheck.warnings,
        rawResponse: capabilitiesCheck.rawResponse,
      },
    };

    // Run conformance checks
    const conformanceChecks = {
      errorResponseFormat: await this.errorResponseChecker.checkFormat(context),
      contentTypeSupport: await this.contentTypeChecker.check(context),
      initializationHandshake: this.initializationChecker.check(context),
    };

    // Extract metadata hints (LOW CONFIDENCE)
    const metadataHints = this.metadataExtractor.extractHints(context);

    // Calculate score
    const allChecks = [
      ...Object.values(protocolChecks),
      ...Object.values(conformanceChecks),
    ];
    const passedCount = allChecks.filter((c) => c.passed).length;
    const totalChecks = allChecks.length;
    const complianceScore = (passedCount / totalChecks) * 100;

    this.logger.info(
      `Protocol Compliance: ${passedCount}/${totalChecks} checks passed (${complianceScore.toFixed(1)}%)`,
    );

    // Determine status
    let status: AssessmentStatus;
    if (!protocolChecks.serverInfoValidity.passed) {
      status = "FAIL";
    } else if (complianceScore >= 90) {
      status = "PASS";
    } else if (complianceScore >= 70) {
      status = "NEED_MORE_INFO";
    } else {
      status = "FAIL";
    }

    const explanation = this.generateProtocolExplanation(
      complianceScore,
      protocolChecks,
      conformanceChecks,
    );
    const recommendations = this.generateProtocolRecommendations(
      protocolChecks,
      conformanceChecks,
      metadataHints,
    );

    // Legacy fields for backward compatibility
    const transportCompliance =
      this.metadataExtractor.assessTransportCompliance(context);
    const oauthImplementation =
      this.metadataExtractor.assessOAuthCompliance(context);
    const annotationSupport =
      this.metadataExtractor.assessAnnotationSupport(context);
    const streamingSupport =
      this.metadataExtractor.assessStreamingSupport(context);

    return {
      assessment: {
        protocolVersion,
        protocolChecks,
        // conformanceChecks are used internally but not exposed in the type
        metadataHints,
        status,
        complianceScore,
        explanation,
        recommendations,
        transportCompliance,
        oauthImplementation,
        annotationSupport,
        streamingSupport,
      },
      testCount: totalChecks + capabilitiesCheck.testCount,
    };
  }

  /**
   * Run error handling tests.
   */
  private async runErrorHandlingTests(context: AssessmentContext): Promise<{
    assessment: ErrorHandlingAssessment;
    testCount: number;
  }> {
    this.logger.info("Starting error handling assessment");

    const testDetails: ErrorTestDetail[] = [];
    let passedTests = 0;

    // Select tools for testing
    const toolsToTest = this.selectToolsForErrorTesting(context.tools);

    // Parallel tool testing with concurrency limit
    const concurrency = this.config.maxParallelTests ?? 5;
    const limit = createConcurrencyLimit(concurrency, this.logger);

    this.logger.info(
      `Testing ${toolsToTest.length} tools for error handling with concurrency limit of ${concurrency}`,
    );

    const allToolTests = await Promise.all(
      toolsToTest.map((tool) =>
        limit(async () => {
          // Check if tool depends on external API
          const isExternalAPI =
            context.externalAPIDependencies?.toolsWithExternalAPIDependency.has(
              tool.name,
            ) ?? false;

          const toolTests = await this.inputValidationTester.testTool(
            tool,
            context.callTool,
            isExternalAPI,
          );

          // Emit per-tool validation summary for auditor UI
          if (context.onProgress) {
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
              extraParams: 0,
              nullValues: 0,
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

    // Post-process results
    for (const toolTests of allToolTests) {
      testDetails.push(...toolTests);
      passedTests += toolTests.filter((t) => t.passed).length;
    }

    // Calculate metrics and status
    const connectionErrorTests = testDetails.filter((t) => t.isConnectionError);
    const connectionErrorCount = connectionErrorTests.length;
    const validTestsCompleted = testDetails.length - connectionErrorCount;
    const totalTestsAttempted = testDetails.length;
    const testCoveragePercent =
      totalTestsAttempted > 0
        ? Math.round((validTestsCompleted / totalTestsAttempted) * 100)
        : 0;

    const metrics = this.errorHandlingScorer.calculateMetrics(
      testDetails,
      passedTests,
    );
    const status = this.errorHandlingScorer.determineStatus(
      metrics,
      testDetails.length,
    );
    const explanation = this.errorHandlingReporter.generateExplanation(
      metrics,
      testDetails,
    );
    const recommendations = this.errorHandlingReporter.generateRecommendations(
      metrics,
      testDetails,
    );

    return {
      assessment: {
        metrics,
        errorTests: testDetails,
        status,
        score: Math.round(metrics.mcpComplianceScore),
        explanation,
        recommendations,
        testExecutionMetadata: {
          totalTestsAttempted,
          validTestsCompleted,
          connectionErrorCount,
          testCoveragePercent,
        },
      },
      testCount: testDetails.length,
    };
  }

  /**
   * Select tools for error handling testing.
   */
  private selectToolsForErrorTesting(tools: Tool[]): Tool[] {
    // Prefer new selectedToolsForTesting configuration
    if (this.config.selectedToolsForTesting !== undefined) {
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

      if (this.config.selectedToolsForTesting.length === 0) {
        this.logger.info(
          `User selected 0 tools for error handling - skipping tests`,
        );
        return [];
      }

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

    if (configLimit === -1) {
      this.logger.info(`Testing all ${tools.length} tools for error handling`);
      return tools;
    }

    const maxTools = Math.min(configLimit ?? 5, tools.length);
    this.logger.info(
      `Testing ${maxTools} out of ${tools.length} tools for error handling`,
    );
    return tools.slice(0, maxTools);
  }

  /**
   * Extract protocol version from context.
   */
  private extractProtocolVersion(context: AssessmentContext): string {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const protocolVersion = metadata?.protocolVersion as string | undefined;
    if (protocolVersion) {
      this.logger.info(
        `Using protocol version from metadata: ${protocolVersion}`,
      );
      return protocolVersion;
    }

    if (context.serverInfo?.version) {
      this.logger.info(
        `Using server version as protocol version: ${context.serverInfo.version}`,
      );
      return context.serverInfo.version;
    }

    this.logger.info(
      "No protocol version information available, using default",
    );
    return "2025-06-18";
  }

  /**
   * Generate explanation for protocol compliance results.
   */
  private generateProtocolExplanation(
    complianceScore: number,
    protocolChecks: ProtocolChecks,
    conformanceChecks: { [key: string]: { passed: boolean } },
  ): string {
    const failedChecks: string[] = [];

    if (!protocolChecks.jsonRpcCompliance.passed)
      failedChecks.push("JSON-RPC compliance");
    if (!protocolChecks.serverInfoValidity.passed)
      failedChecks.push("server info validity");
    if (!protocolChecks.schemaCompliance.passed)
      failedChecks.push("schema compliance");
    if (!protocolChecks.errorResponseCompliance.passed)
      failedChecks.push("error response compliance");

    Object.entries(conformanceChecks).forEach(([name, check]) => {
      if (!check.passed) {
        failedChecks.push(
          name
            .replace(/([A-Z])/g, " $1")
            .toLowerCase()
            .trim(),
        );
      }
    });

    if (complianceScore >= 90) {
      return "Excellent MCP protocol compliance. Server meets all critical requirements verified through protocol testing.";
    } else if (complianceScore >= 70) {
      return `Good MCP compliance with minor issues: ${failedChecks.join(", ")}. Review recommended before directory submission.`;
    } else {
      return `Poor MCP compliance detected. Critical issues: ${failedChecks.join(", ")}. Must fix before directory approval.`;
    }
  }

  /**
   * Generate recommendations for protocol compliance.
   */
  private generateProtocolRecommendations(
    protocolChecks: ProtocolChecks,
    conformanceChecks: { [key: string]: { passed: boolean } },
    metadataHints?: { requiresManualVerification?: boolean },
  ): string[] {
    const recommendations: string[] = [];

    if (!protocolChecks.jsonRpcCompliance.passed) {
      recommendations.push(
        "Ensure all requests/responses follow JSON-RPC 2.0 format with proper jsonrpc, id, method/result fields.",
      );
    }

    if (!protocolChecks.serverInfoValidity.passed) {
      recommendations.push(
        "Fix serverInfo structure to include valid name and metadata fields.",
      );
    }

    if (!protocolChecks.schemaCompliance.passed) {
      if (protocolChecks.schemaCompliance.confidence === "low") {
        recommendations.push(
          "Schema validation warnings detected (may be false positives from Zod/TypeBox conversion).",
        );
      } else {
        recommendations.push(
          "Review tool schemas and ensure they follow JSON Schema specification.",
        );
      }
    }

    if (!conformanceChecks.errorResponseFormat?.passed) {
      recommendations.push(
        "Ensure error responses include 'isError: true' flag and properly formatted content array.",
      );
    }

    if (!conformanceChecks.contentTypeSupport?.passed) {
      recommendations.push(
        "Use only valid content types: text, image, audio, resource, resource_link.",
      );
    }

    if (!conformanceChecks.initializationHandshake?.passed) {
      recommendations.push(
        "Ensure server provides name and version during initialization.",
      );
    }

    if (!protocolChecks.structuredOutputSupport.passed) {
      recommendations.push(
        "Consider adding outputSchema to tools for type-safe responses (optional MCP 2025-06-18 feature).",
      );
    }

    if (metadataHints?.requiresManualVerification) {
      recommendations.push(
        "Transport/OAuth/Streaming features require manual verification (metadata-based detection only).",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Excellent MCP compliance! All protocol checks passed. Server is ready for directory submission.",
      );
    }

    return recommendations;
  }
}
