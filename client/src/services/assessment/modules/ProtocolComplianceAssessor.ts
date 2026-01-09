/**
 * Protocol Compliance Assessor Module
 *
 * Unified module for MCP protocol compliance validation.
 * Merges MCPSpecComplianceAssessor and ProtocolConformanceAssessor functionality.
 *
 * Protocol Checks:
 * 1. JSON-RPC 2.0 Compliance - Validates request/response structure
 * 2. Server Info Validity - Validates initialization handshake
 * 3. Schema Compliance - Validates tool input schemas
 * 4. Error Response Format - Validates isError flag, content array structure
 * 5. Content Type Support - Validates valid content types (text, image, audio, resource)
 * 6. Structured Output Support - Checks for outputSchema usage
 * 7. Capabilities Compliance - Validates declared vs actual capabilities
 *
 * @module assessment/modules/ProtocolComplianceAssessor
 */

import {
  MCPSpecComplianceAssessment,
  AssessmentStatus,
  TransportComplianceMetrics,
  OAuthComplianceMetrics,
  AnnotationSupportMetrics,
  StreamingSupportMetrics,
  AssessmentConfiguration,
  ProtocolChecks,
  MetadataHints,
  OutputSchemaCoverage,
  ToolOutputSchemaResult,
} from "@/lib/assessmentTypes";
import type { ProtocolCheck } from "@/lib/assessment/extendedTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import Ajv from "ajv";
import type { Ajv as AjvInstance } from "ajv";
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
 * Protocol Compliance Assessment Result
 * Unified output type for protocol compliance checks
 */
export interface ProtocolComplianceAssessment extends MCPSpecComplianceAssessment {
  /** Additional conformance-style checks from ProtocolConformanceAssessor */
  conformanceChecks?: {
    errorResponseFormat: ProtocolCheck;
    contentTypeSupport: ProtocolCheck;
    initializationHandshake: ProtocolCheck;
  };
}

export class ProtocolComplianceAssessor extends BaseAssessor<ProtocolComplianceAssessment> {
  private ajv: AjvInstance;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.ajv = new Ajv({ allErrors: true });
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
   * Assess MCP Protocol Compliance - Unified Approach
   * Combines MCPSpecComplianceAssessor and ProtocolConformanceAssessor functionality
   */
  async assess(
    context: AssessmentContext,
  ): Promise<ProtocolComplianceAssessment> {
    const protocolVersion = this.extractProtocolVersion(context);
    const tools = context.tools;
    const callTool = context.callTool;

    // SECTION 1: Protocol Checks (from MCPSpecComplianceAssessor)
    const schemaCheck = this.checkSchemaCompliance(tools);
    const jsonRpcCheck = await this.checkJsonRpcCompliance(callTool);
    const errorCheck = await this.checkErrorResponses(tools, callTool);
    const capabilitiesCheck = this.checkCapabilitiesCompliance(context);

    const protocolChecks: ProtocolChecks = {
      jsonRpcCompliance: {
        passed: jsonRpcCheck.passed,
        confidence: "high",
        evidence: "Verified via actual tool call",
        rawResponse: jsonRpcCheck.rawResponse,
      },
      serverInfoValidity: {
        passed: this.checkServerInfoValidity(context.serverInfo),
        confidence: "high",
        evidence: "Validated server info structure",
        rawResponse: context.serverInfo,
      },
      schemaCompliance: {
        passed: schemaCheck.passed,
        confidence: schemaCheck.confidence as "high" | "medium" | "low",
        warnings: schemaCheck.details ? [schemaCheck.details] : undefined,
        rawResponse: tools.map((t) => ({
          name: t.name,
          inputSchema: t.inputSchema,
        })),
      },
      errorResponseCompliance: {
        passed: errorCheck.passed,
        confidence: "high",
        evidence: "Tested error handling with invalid parameters",
        rawResponse: errorCheck.rawResponse,
      },
      structuredOutputSupport: (() => {
        const { coverage, toolResults } =
          this.analyzeOutputSchemaCoverage(tools);
        return {
          passed: coverage.withOutputSchema > 0,
          confidence: "high" as const,
          evidence: `${coverage.withOutputSchema}/${coverage.totalTools} tools have outputSchema (${coverage.coveragePercent}%)`,
          coverage, // Issue #64: Detailed coverage metrics
          toolResults, // Issue #64: Per-tool analysis
          rawResponse: tools.map((t) => ({
            name: t.name,
            hasOutputSchema: !!t.outputSchema,
            outputSchema: t.outputSchema,
          })),
        };
      })(),
      capabilitiesCompliance: {
        passed: capabilitiesCheck.passed,
        confidence: capabilitiesCheck.confidence as "high" | "medium" | "low",
        evidence: capabilitiesCheck.evidence,
        warnings: capabilitiesCheck.warnings,
        rawResponse: capabilitiesCheck.rawResponse,
      },
    };

    // SECTION 2: Conformance Checks (from ProtocolConformanceAssessor)
    const conformanceChecks = {
      errorResponseFormat: await this.checkErrorResponseFormat(context),
      contentTypeSupport: await this.checkContentTypeSupport(context),
      initializationHandshake: await this.checkInitializationHandshake(context),
    };

    // SECTION 3: Metadata Hints (LOW CONFIDENCE - not tested, just parsed)
    const metadataHints = this.extractMetadataHints(context);

    // Calculate score based on all protocol checks (reliable)
    const allChecks = [
      ...Object.values(protocolChecks),
      ...Object.values(conformanceChecks),
    ];
    const passedCount = allChecks.filter((c) => c.passed).length;
    const totalChecks = allChecks.length;
    const complianceScore = (passedCount / totalChecks) * 100;

    // Track test count
    this.testCount = totalChecks;

    // Log score/check consistency for debugging
    this.log(
      `Protocol Compliance: ${passedCount}/${totalChecks} checks passed (${complianceScore.toFixed(1)}%)`,
    );

    // Determine status based on protocol checks only
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

    const explanation = this.generateExplanation(
      complianceScore,
      protocolChecks,
      conformanceChecks,
    );
    const recommendations = this.generateRecommendations(
      protocolChecks,
      conformanceChecks,
      metadataHints,
    );

    // Legacy fields for backward compatibility
    const transportCompliance = this.assessTransportCompliance(context);
    const oauthImplementation = this.assessOAuthCompliance(context);
    const annotationSupport = this.assessAnnotationSupport(context);
    const streamingSupport = this.assessStreamingSupport(context);

    return {
      protocolVersion,
      protocolChecks,
      conformanceChecks,
      metadataHints,
      status,
      complianceScore,
      explanation,
      recommendations,
      // Legacy fields (deprecated but maintained for backward compatibility)
      transportCompliance,
      oauthImplementation,
      annotationSupport,
      streamingSupport,
    };
  }

  /**
   * Extract protocol version from context
   */
  private extractProtocolVersion(context: AssessmentContext): string {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const protocolVersion = metadata?.protocolVersion as string | undefined;
    if (protocolVersion) {
      this.log(`Using protocol version from metadata: ${protocolVersion}`);
      return protocolVersion;
    }

    if (context.serverInfo?.version) {
      this.log(
        `Using server version as protocol version: ${context.serverInfo.version}`,
      );
      return context.serverInfo.version;
    }

    this.log("No protocol version information available, using default");
    return "2025-06-18";
  }

  /**
   * Check JSON-RPC 2.0 compliance
   */
  private async checkJsonRpcCompliance(
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<{ passed: boolean; rawResponse: unknown }> {
    try {
      const result = await callTool("list", {});
      const hasValidStructure =
        result !== null &&
        (Array.isArray(result.content) || result.isError !== undefined);
      return { passed: hasValidStructure, rawResponse: result };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      const isStructuredError =
        errorMessage.includes("MCP error") ||
        errorMessage.includes("jsonrpc") ||
        errorMessage.includes("-32");
      return { passed: isStructuredError, rawResponse: error };
    }
  }

  /**
   * Check if server info is valid and properly formatted
   */
  private checkServerInfoValidity(serverInfo: any): boolean {
    if (!serverInfo) {
      return true; // No server info is acceptable (optional)
    }

    if (serverInfo.name !== undefined && serverInfo.name !== null) {
      if (typeof serverInfo.name !== "string") {
        this.log("Server info name is not a string");
        return false;
      }
    }

    if (serverInfo.metadata !== undefined && serverInfo.metadata !== null) {
      if (typeof serverInfo.metadata !== "object") {
        this.log("Server info metadata is not an object");
        return false;
      }
    }

    return true;
  }

  /**
   * Check schema compliance for all tools
   */
  private checkSchemaCompliance(tools: Tool[]): {
    passed: boolean;
    confidence: "high" | "medium" | "low";
    details?: string;
  } {
    try {
      let hasErrors = false;
      const errors: string[] = [];

      for (const tool of tools) {
        if (tool.inputSchema) {
          const isValid = this.ajv.validateSchema(tool.inputSchema);
          if (!isValid) {
            hasErrors = true;
            const errorMsg = `${tool.name}: ${JSON.stringify(this.ajv.errors)}`;
            errors.push(errorMsg);
            this.logger.warn(`Invalid schema for tool ${tool.name}`, {
              errors: this.ajv.errors,
            });
          }
        }
      }

      return {
        passed: !hasErrors,
        confidence: hasErrors ? "low" : "high",
        details: hasErrors ? errors.join("; ") : undefined,
      };
    } catch (error) {
      this.logger.error("Schema compliance check failed", {
        error: String(error),
      });
      return {
        passed: false,
        confidence: "low",
        details: String(error),
      };
    }
  }

  /**
   * Check error response compliance (basic check from MCPSpec)
   */
  private async checkErrorResponses(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<{ passed: boolean; rawResponse: unknown }> {
    try {
      if (tools.length === 0)
        return { passed: true, rawResponse: "No tools to test" };

      const testTool = tools[0];
      try {
        const result = await callTool(testTool.name, { invalid_param: "test" });
        const isErrorResponse = result.isError === true;
        const hasContent = Array.isArray(result.content);
        const passed =
          (isErrorResponse && hasContent) || (!isErrorResponse && hasContent);
        return { passed, rawResponse: result };
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const isStructuredError =
          errorMessage.includes("MCP error") ||
          errorMessage.includes("-32") ||
          errorMessage.includes("jsonrpc");
        return { passed: isStructuredError, rawResponse: error };
      }
    } catch (error) {
      return { passed: false, rawResponse: error };
    }
  }

  /**
   * Analyze outputSchema coverage across all tools (Issue #64)
   * Returns detailed coverage metrics instead of just a boolean
   */
  private analyzeOutputSchemaCoverage(tools: Tool[]): {
    coverage: OutputSchemaCoverage;
    toolResults: ToolOutputSchemaResult[];
  } {
    const toolResults: ToolOutputSchemaResult[] = [];
    const toolsWithoutSchema: string[] = [];
    let withOutputSchema = 0;
    let withoutOutputSchema = 0;

    for (const tool of tools) {
      const hasOutputSchema = !!tool.outputSchema;

      if (hasOutputSchema) {
        withOutputSchema++;
      } else {
        withoutOutputSchema++;
        toolsWithoutSchema.push(tool.name);
      }

      toolResults.push({
        toolName: tool.name,
        hasOutputSchema,
        outputSchema: tool.outputSchema as Record<string, unknown> | undefined,
      });
    }

    const totalTools = tools.length;
    const coveragePercent =
      totalTools > 0 ? Math.round((withOutputSchema / totalTools) * 100) : 0;

    this.log(
      `Structured output support: ${withOutputSchema}/${totalTools} tools (${coveragePercent}%)`,
    );

    const coverage: OutputSchemaCoverage = {
      totalTools,
      withOutputSchema,
      withoutOutputSchema,
      coveragePercent,
      toolsWithoutSchema,
      status: coveragePercent === 100 ? "PASS" : "INFO",
      recommendation:
        coveragePercent < 100
          ? "Add outputSchema to tools for client-side response validation"
          : undefined,
    };

    return { coverage, toolResults };
  }
  /**
   * Check capabilities compliance
   */
  private checkCapabilitiesCompliance(context: AssessmentContext): {
    passed: boolean;
    confidence: string;
    evidence: string;
    warnings?: string[];
    rawResponse?: unknown;
  } {
    const warnings: string[] = [];
    const capabilities = context.serverCapabilities;

    if (!capabilities) {
      return {
        passed: true,
        confidence: "medium",
        evidence: "No server capabilities declared (optional)",
        rawResponse: undefined,
      };
    }

    if (capabilities.tools) {
      if (context.tools.length === 0) {
        warnings.push("Declared tools capability but no tools registered");
      }
      this.testCount++;
    }

    if (capabilities.resources) {
      if (!context.resources || context.resources.length === 0) {
        if (!context.readResource) {
          warnings.push(
            "Declared resources capability but no resources data provided for validation",
          );
        }
      }
      this.testCount++;
    }

    if (capabilities.prompts) {
      if (!context.prompts || context.prompts.length === 0) {
        if (!context.getPrompt) {
          warnings.push(
            "Declared prompts capability but no prompts data provided for validation",
          );
        }
      }
      this.testCount++;
    }

    const passed = warnings.length === 0;
    const confidence = warnings.length === 0 ? "high" : "medium";

    return {
      passed,
      confidence,
      evidence: passed
        ? "All declared capabilities have corresponding implementations"
        : `Capability validation issues: ${warnings.join("; ")}`,
      warnings: warnings.length > 0 ? warnings : undefined,
      rawResponse: capabilities,
    };
  }

  // ============================================================================
  // Conformance-style checks (from ProtocolConformanceAssessor)
  // ============================================================================

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
   * Check Error Response Format (conformance-style with multi-tool testing)
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
        specReference: `${this.getSpecBaseUrl()}/basic/lifecycle`,
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
          this.config.testTimeout,
        );

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
      specReference: `${this.getSpecBaseUrl()}/basic/lifecycle`,
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
   * Check Content Type Support
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
          specReference: `${this.getSpecBaseUrl()}/server/tools`,
        };
      }

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
          specReference: `${this.getSpecBaseUrl()}/server/tools`,
          warnings: ["Content type validation requires valid tool parameters"],
        };
      }

      const result = await this.executeWithTimeout(
        context.callTool(testTool.name, {}),
        this.config.testTimeout,
      );

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
        specReference: `${this.getSpecBaseUrl()}/server/tools`,
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
      return {
        passed: false,
        confidence: "medium",
        evidence: "Could not test content types due to error",
        specReference: `${this.getSpecBaseUrl()}/server/tools`,
        details: {
          error: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }

  /**
   * Check Initialization Handshake
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
    const hasMinimumInfo =
      validations.hasServerInfo && validations.hasServerName;

    return {
      passed: hasMinimumInfo,
      confidence: allPassed ? "high" : "medium",
      evidence: `${passedValidations.length}/${Object.keys(validations).length} initialization checks passed`,
      specReference: `${this.getSpecBaseUrl()}/basic/lifecycle`,
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

  // ============================================================================
  // Legacy compatibility methods (from MCPSpecComplianceAssessor)
  // ============================================================================

  private assessTransportCompliance(
    context: AssessmentContext,
  ): TransportComplianceMetrics {
    if (!context.serverInfo) {
      return {
        supportsStreamableHTTP: false,
        deprecatedSSE: false,
        transportValidation: "failed",
        supportsStdio: false,
        supportsSSE: false,
        confidence: "low",
        detectionMethod: "manual-required",
        requiresManualCheck: true,
        manualVerificationSteps: [
          "Test STDIO: Run `npm start`, send JSON-RPC initialize request",
          "Test HTTP: Set HTTP_STREAMABLE_SERVER=true, run `npm start`, test /health endpoint",
          "Check if framework handles transports internally",
        ],
      };
    }

    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const transport = metadata?.transport as string | undefined;
    const hasTransportMetadata = !!transport;

    const supportsStreamableHTTP =
      transport === "streamable-http" ||
      transport === "http" ||
      (!transport && !!context.serverInfo);
    const deprecatedSSE = transport === "sse";

    let transportValidation: "passed" | "failed" | "partial" = "passed";
    if (deprecatedSSE) {
      transportValidation = "partial";
    } else if (
      transport &&
      transport !== "streamable-http" &&
      transport !== "http" &&
      transport !== "stdio"
    ) {
      transportValidation = "failed";
    }

    const confidence = hasTransportMetadata ? "medium" : "low";
    const requiresManualCheck = !hasTransportMetadata;

    return {
      supportsStreamableHTTP,
      deprecatedSSE,
      transportValidation,
      supportsStdio: transport === "stdio" || !transport,
      supportsSSE: deprecatedSSE,
      confidence,
      detectionMethod: hasTransportMetadata ? "automated" : "manual-required",
      requiresManualCheck,
      manualVerificationSteps: requiresManualCheck
        ? [
            "Test STDIO: Run `npm start`, send JSON-RPC initialize request via stdin",
            "Test HTTP: Set HTTP_STREAMABLE_SERVER=true, run `npm start`, curl http://localhost:3000/health",
          ]
        : undefined,
    };
  }

  private assessAnnotationSupport(
    context: AssessmentContext,
  ): AnnotationSupportMetrics {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const annotations = metadata?.annotations as
      | Record<string, unknown>
      | undefined;
    const supportsAnnotations = (annotations?.supported as boolean) || false;
    const customAnnotations = (annotations?.types as string[]) || [];

    return {
      supportsReadOnlyHint: supportsAnnotations,
      supportsDestructiveHint: supportsAnnotations,
      supportsTitleAnnotation: supportsAnnotations,
      customAnnotations:
        customAnnotations.length > 0 ? customAnnotations : undefined,
    };
  }

  private assessStreamingSupport(
    context: AssessmentContext,
  ): StreamingSupportMetrics {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const streaming = metadata?.streaming as
      | Record<string, unknown>
      | undefined;
    const supportsStreaming = (streaming?.supported as boolean) || false;
    const protocol = streaming?.protocol as string | undefined;

    const validProtocols = ["http-streaming", "sse", "websocket"];
    const streamingProtocol =
      protocol && validProtocols.includes(protocol)
        ? (protocol as "http-streaming" | "sse" | "websocket")
        : supportsStreaming
          ? "http-streaming"
          : undefined;

    return {
      supportsStreaming,
      streamingProtocol,
    };
  }

  private assessOAuthCompliance(
    context: AssessmentContext,
  ): OAuthComplianceMetrics | undefined {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const oauthConfig = metadata?.oauth as Record<string, unknown> | undefined;

    if (!oauthConfig || !oauthConfig.enabled) {
      return undefined;
    }

    const resourceIndicators: string[] = [];
    if (oauthConfig.resourceIndicators) {
      const indicators = oauthConfig.resourceIndicators as string[];
      resourceIndicators.push(...indicators);
    }
    if (oauthConfig.resourceServer) {
      resourceIndicators.push(oauthConfig.resourceServer as string);
    }

    return {
      implementsResourceServer: oauthConfig.enabled === true,
      supportsRFC8707: (oauthConfig.supportsRFC8707 as boolean) || false,
      resourceIndicators,
      tokenValidation: oauthConfig.tokenValidation !== false,
      scopeEnforcement: oauthConfig.scopeEnforcement !== false,
      supportsOAuth: oauthConfig.enabled === true,
      supportsPKCE: (oauthConfig.supportsPKCE as boolean) || false,
    };
  }

  private extractMetadataHints(
    context: AssessmentContext,
  ): MetadataHints | undefined {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;

    if (!metadata && !context.serverInfo) {
      return undefined;
    }

    const transport = metadata?.transport as string | undefined;
    const transportHints = {
      detectedTransport: transport,
      supportsStdio: transport === "stdio" || !transport,
      supportsHTTP:
        transport === "http" ||
        transport === "streamable-http" ||
        (!transport && !!context.serverInfo),
      supportsSSE: transport === "sse",
      detectionMethod: (transport ? "metadata" : "assumed") as
        | "metadata"
        | "assumed",
    };

    const oauthConfig = metadata?.oauth as Record<string, unknown> | undefined;
    const oauthHints = oauthConfig
      ? {
          hasOAuthConfig: true,
          supportsOAuth: oauthConfig.enabled === true,
          supportsPKCE: (oauthConfig.supportsPKCE as boolean) || false,
          resourceIndicators: oauthConfig.resourceIndicators
            ? (oauthConfig.resourceIndicators as string[])
            : undefined,
        }
      : undefined;

    const annotations = metadata?.annotations as
      | Record<string, unknown>
      | undefined;
    const annotationHints = {
      supportsReadOnlyHint: (annotations?.supported as boolean) || false,
      supportsDestructiveHint: (annotations?.supported as boolean) || false,
      supportsTitleAnnotation: (annotations?.supported as boolean) || false,
      customAnnotations: annotations?.types
        ? (annotations.types as string[])
        : undefined,
    };

    const streaming = metadata?.streaming as
      | Record<string, unknown>
      | undefined;
    const streamingHints = {
      supportsStreaming: (streaming?.supported as boolean) || false,
      streamingProtocol:
        streaming?.protocol &&
        ["http-streaming", "sse", "websocket"].includes(
          streaming.protocol as string,
        )
          ? (streaming.protocol as "http-streaming" | "sse" | "websocket")
          : undefined,
    };

    return {
      confidence: "low",
      requiresManualVerification: true,
      transportHints,
      oauthHints,
      annotationHints,
      streamingHints,
      manualVerificationSteps: [
        "Test STDIO transport: Run `npm start`, send JSON-RPC initialize request via stdin",
        "Test HTTP transport: Set HTTP_STREAMABLE_SERVER=true, run `npm start`, curl http://localhost:3000/health",
        "Verify OAuth endpoints if configured",
      ],
    };
  }

  /**
   * Generate explanation based on all protocol checks
   */
  private generateExplanation(
    complianceScore: number,
    protocolChecks: ProtocolChecks,
    conformanceChecks: { [key: string]: ProtocolCheck },
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
   * Generate recommendations based on all checks
   */
  private generateRecommendations(
    protocolChecks: ProtocolChecks,
    conformanceChecks: { [key: string]: ProtocolCheck },
    metadataHints?: MetadataHints,
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

    if (!conformanceChecks.errorResponseFormat.passed) {
      recommendations.push(
        "Ensure error responses include 'isError: true' flag and properly formatted content array.",
      );
    }

    if (!conformanceChecks.contentTypeSupport.passed) {
      recommendations.push(
        "Use only valid content types: text, image, audio, resource, resource_link.",
      );
    }

    if (!conformanceChecks.initializationHandshake.passed) {
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
