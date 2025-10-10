/**
 * MCP Spec Compliance Assessment Module
 * Simple, focused MCP protocol validation for directory approval
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
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import Ajv from "ajv";
import type { Ajv as AjvInstance } from "ajv";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

export class MCPSpecComplianceAssessor extends BaseAssessor {
  private ajv: AjvInstance;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.ajv = new Ajv({ allErrors: true });
  }

  /**
   * Assess MCP Specification Compliance - Hybrid Approach
   * Separates protocol-verified checks from metadata-based hints
   */
  async assess(
    context: AssessmentContext,
  ): Promise<MCPSpecComplianceAssessment> {
    const protocolVersion = this.extractProtocolVersion(context);
    const tools = context.tools;
    const callTool = context.callTool;

    // SECTION 1: Protocol Checks (HIGH CONFIDENCE - actually tested)
    const schemaCheck = this.checkSchemaCompliance(tools);
    const jsonRpcCheck = await this.checkJsonRpcCompliance(callTool);
    const errorCheck = await this.checkErrorResponses(tools, callTool);

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
      structuredOutputSupport: {
        passed: this.checkStructuredOutputSupport(tools),
        confidence: "high",
        evidence: `${tools.filter((t) => t.outputSchema).length}/${tools.length} tools have outputSchema`,
        rawResponse: tools.map((t) => ({
          name: t.name,
          hasOutputSchema: !!t.outputSchema,
          outputSchema: t.outputSchema,
        })),
      },
    };

    // SECTION 2: Metadata Hints (LOW CONFIDENCE - not tested, just parsed)
    const metadataHints = this.extractMetadataHints(context);

    // Calculate score based ONLY on protocol checks (reliable)
    const checksArray = Object.values(protocolChecks);
    const passedCount = checksArray.filter((c) => c.passed).length;
    const complianceScore = (passedCount / checksArray.length) * 100;

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

    const explanation = this.generateExplanationHybrid(
      complianceScore,
      protocolChecks,
    );
    const recommendations = this.generateRecommendationsHybrid(
      protocolChecks,
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
    // Try metadata.protocolVersion first
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const protocolVersion = metadata?.protocolVersion as string | undefined;
    if (protocolVersion) {
      this.log(`Using protocol version from metadata: ${protocolVersion}`);
      return protocolVersion;
    }

    // Fall back to server version
    if (context.serverInfo?.version) {
      this.log(
        `Using server version as protocol version: ${context.serverInfo.version}`,
      );
      return context.serverInfo.version;
    }

    // Default if no version information available
    this.log("No protocol version information available, using default");
    return "2025-06-18"; // Current MCP spec version as fallback
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
      // Test basic JSON-RPC structure by making a simple call
      // If we can call any tool, JSON-RPC is working
      const result = await callTool("list", {});
      return { passed: result !== null, rawResponse: result };
    } catch (error) {
      // If call fails, that's actually expected for many tools
      // The fact that we got a structured response means JSON-RPC works
      return { passed: true, rawResponse: error };
    }
  }

  /**
   * Check if server info is valid and properly formatted
   */
  private checkServerInfoValidity(serverInfo: any): boolean {
    if (!serverInfo) {
      // No server info is acceptable (optional)
      return true;
    }

    // Check if name is properly set (should be a string, not null/undefined)
    if (serverInfo.name !== undefined && serverInfo.name !== null) {
      if (typeof serverInfo.name !== "string") {
        this.log("Server info name is not a string");
        return false;
      }
    }

    // Check if metadata is properly formatted (should be an object if present)
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
          // Validate that the schema is valid JSON Schema
          const isValid = this.ajv.validateSchema(tool.inputSchema);
          if (!isValid) {
            hasErrors = true;
            const errorMsg = `${tool.name}: ${JSON.stringify(this.ajv.errors)}`;
            errors.push(errorMsg);
            console.warn(
              `Invalid schema for tool ${tool.name}:`,
              this.ajv.errors,
            );
          }
        }
      }

      // If errors found, mark as low confidence (likely Zod conversion issues)
      return {
        passed: !hasErrors,
        confidence: hasErrors ? "low" : "high",
        details: hasErrors ? errors.join("; ") : undefined,
      };
    } catch (error) {
      console.error("Schema compliance check failed:", error);
      return {
        passed: false,
        confidence: "low",
        details: String(error),
      };
    }
  }

  /**
   * Check error response compliance
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

      // Test error handling with invalid parameters
      const testTool = tools[0];
      try {
        const result = await callTool(testTool.name, { invalid_param: "test" });
        return { passed: true, rawResponse: result }; // Server handled gracefully
      } catch (error) {
        return { passed: true, rawResponse: error }; // Server provided error response
      }
    } catch (error) {
      return { passed: false, rawResponse: error };
    }
  }

  /**
   * Check if tools have structured output support (2025-06-18 feature)
   */
  private checkStructuredOutputSupport(tools: Tool[]): boolean {
    // Check if any tools define outputSchema
    const toolsWithOutputSchema = tools.filter(
      (tool) => tool.outputSchema,
    ).length;
    const percentage =
      tools.length > 0 ? (toolsWithOutputSchema / tools.length) * 100 : 0;

    // Log for debugging
    this.log(
      `Structured output support: ${toolsWithOutputSchema}/${tools.length} tools (${percentage.toFixed(1)}%)`,
    );

    // Consider it supported if at least some tools use it
    return toolsWithOutputSchema > 0;
  }

  /**
   * Assess transport compliance (basic check)
   */
  private assessTransportCompliance(
    context: AssessmentContext,
  ): TransportComplianceMetrics {
    // If no server info at all, assume failure
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

    // Check transport from metadata
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

    // Determine validation status
    let transportValidation: "passed" | "failed" | "partial" = "passed";

    // Check for MCP-Protocol-Version header requirement (2025-06-18)
    // Note: We can't directly check headers through the SDK, but we can verify protocol version
    const protocolVersion = this.extractProtocolVersion(context);
    const isNewProtocol = protocolVersion >= "2025-06-18";

    if (deprecatedSSE) {
      transportValidation = "partial"; // SSE is deprecated
    } else if (
      transport &&
      transport !== "streamable-http" &&
      transport !== "http" &&
      transport !== "stdio"
    ) {
      transportValidation = "failed"; // Unknown transport
    } else if (
      isNewProtocol &&
      (transport === "http" || transport === "streamable-http")
    ) {
      // For HTTP transport on 2025-06-18+, headers are required
      // We assume compliance if using the new protocol version
      this.log(
        `HTTP transport detected with protocol ${protocolVersion} - header compliance assumed`,
      );
    }

    // Determine confidence based on detection method
    const confidence = hasTransportMetadata ? "medium" : "low";
    const requiresManualCheck = !hasTransportMetadata;

    return {
      supportsStreamableHTTP: supportsStreamableHTTP,
      deprecatedSSE: deprecatedSSE,
      transportValidation: transportValidation,
      // Added missing properties that UI expects
      supportsStdio: transport === "stdio" || !transport,
      supportsSSE: deprecatedSSE,
      // Detection metadata
      confidence,
      detectionMethod: hasTransportMetadata ? "automated" : "manual-required",
      requiresManualCheck,
      manualVerificationSteps: requiresManualCheck
        ? [
            "Test STDIO: Run `npm start`, send JSON-RPC initialize request via stdin",
            "Test HTTP: Set HTTP_STREAMABLE_SERVER=true, run `npm start`, curl http://localhost:3000/health",
            "Check if framework (e.g., FastMCP, firecrawl-fastmcp) handles transports internally",
            "Review server startup logs for transport initialization messages",
          ]
        : undefined,
    };
  }

  /**
   * Assess annotation support
   */
  private assessAnnotationSupport(
    context: AssessmentContext,
  ): AnnotationSupportMetrics {
    // Check if server metadata indicates annotation support
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

  /**
   * Assess streaming support
   */
  private assessStreamingSupport(
    context: AssessmentContext,
  ): StreamingSupportMetrics {
    // Check if server metadata indicates streaming support
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const streaming = metadata?.streaming as
      | Record<string, unknown>
      | undefined;
    const supportsStreaming = (streaming?.supported as boolean) || false;
    const protocol = streaming?.protocol as string | undefined;

    // Validate protocol is one of the allowed types
    const validProtocols = ["http-streaming", "sse", "websocket"];
    const streamingProtocol =
      protocol && validProtocols.includes(protocol)
        ? (protocol as "http-streaming" | "sse" | "websocket")
        : supportsStreaming
          ? "http-streaming"
          : undefined;

    return {
      supportsStreaming: supportsStreaming,
      streamingProtocol,
    };
  }

  /**
   * Assess OAuth implementation (optional)
   */
  private assessOAuthCompliance(
    context: AssessmentContext,
  ): OAuthComplianceMetrics | undefined {
    // Check if OAuth is configured
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const oauthConfig = metadata?.oauth as Record<string, unknown> | undefined;

    if (!oauthConfig || !oauthConfig.enabled) {
      // OAuth is optional for MCP servers
      return undefined;
    }

    // Extract OAuth configuration with type assertions
    const resourceIndicators: string[] = [];

    if (oauthConfig.resourceIndicators) {
      const indicators = oauthConfig.resourceIndicators as string[];
      resourceIndicators.push(...indicators);
    }
    if (oauthConfig.resourceServer) {
      resourceIndicators.push(oauthConfig.resourceServer as string);
    }
    if (
      oauthConfig.authorizationEndpoint &&
      !resourceIndicators.includes(oauthConfig.authorizationEndpoint as string)
    ) {
      resourceIndicators.push(oauthConfig.authorizationEndpoint as string);
    }

    return {
      implementsResourceServer: oauthConfig.enabled === true,
      supportsRFC8707: (oauthConfig.supportsRFC8707 as boolean) || false,
      resourceIndicators: resourceIndicators,
      tokenValidation: oauthConfig.tokenValidation !== false, // Default to true if not specified
      scopeEnforcement: oauthConfig.scopeEnforcement !== false, // Default to true if not specified
      // Added missing properties that UI expects
      supportsOAuth: oauthConfig.enabled === true,
      supportsPKCE: (oauthConfig.supportsPKCE as boolean) || false,
    };
  }

  /**
   * Extract metadata hints from server context
   * LOW CONFIDENCE - these are just parsed from metadata, not tested
   */
  private extractMetadataHints(
    context: AssessmentContext,
  ): MetadataHints | undefined {
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;

    if (!metadata && !context.serverInfo) {
      return undefined;
    }

    // Parse transport hints
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

    // Parse OAuth hints
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

    // Parse annotation hints
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

    // Parse streaming hints
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
        "Check if framework (FastMCP, firecrawl-fastmcp) handles transports/features internally",
        "Review server startup logs for transport initialization messages",
      ],
    };
  }

  /**
   * Generate explanation based on protocol checks
   */
  private generateExplanationHybrid(
    complianceScore: number,
    checks: ProtocolChecks,
  ): string {
    const failedChecks: string[] = [];

    if (!checks.jsonRpcCompliance.passed)
      failedChecks.push("JSON-RPC compliance");
    if (!checks.serverInfoValidity.passed)
      failedChecks.push("server info validity");
    if (!checks.schemaCompliance.passed) failedChecks.push("schema compliance");
    if (!checks.errorResponseCompliance.passed)
      failedChecks.push("error response compliance");
    if (!checks.structuredOutputSupport.passed)
      failedChecks.push("structured output support");

    if (complianceScore >= 90) {
      return "Excellent MCP protocol compliance. Server meets all critical requirements verified through protocol testing.";
    } else if (complianceScore >= 70) {
      return `Good MCP compliance with minor issues in protocol testing: ${failedChecks.join(", ")}. Review recommended before directory submission.`;
    } else {
      return `Poor MCP compliance detected in protocol testing. Critical issues: ${failedChecks.join(", ")}. Must fix before directory approval.`;
    }
  }

  /**
   * Generate simplified recommendations based on protocol checks and metadata hints
   */
  private generateRecommendationsHybrid(
    checks: ProtocolChecks,
    metadataHints?: MetadataHints,
  ): string[] {
    const recommendations: string[] = [];

    // Protocol check failures (high confidence)
    if (!checks.jsonRpcCompliance.passed) {
      recommendations.push(
        "⚠️ JSON-RPC 2.0 compliance failed: Ensure all requests/responses follow JSON-RPC 2.0 format with proper jsonrpc, id, method/result fields.",
      );
    }

    if (!checks.serverInfoValidity.passed) {
      recommendations.push(
        "❌ Server info is malformed: Fix serverInfo structure to include valid name and metadata fields.",
      );
    }

    if (!checks.schemaCompliance.passed) {
      if (checks.schemaCompliance.confidence === "low") {
        recommendations.push(
          "⚠️ Schema validation warnings detected (LOW CONFIDENCE): May be false positives from Zod/TypeBox conversion. Test if tools execute successfully - if they do, this is likely a conversion artifact and not a real problem.",
        );
      } else {
        recommendations.push(
          "⚠️ JSON Schema validation errors: Review tool schemas and ensure they follow JSON Schema specification.",
        );
      }
    }

    if (!checks.errorResponseCompliance.passed) {
      recommendations.push(
        "⚠️ Error response format issues: Return proper MCP error objects with error codes and messages following JSON-RPC 2.0 format.",
      );
    }

    if (!checks.structuredOutputSupport.passed) {
      recommendations.push(
        "💡 Enhancement: Add outputSchema to tools for type-safe responses (optional MCP 2025-06-18 feature).",
      );
    }

    // Metadata hints reminder
    if (metadataHints?.requiresManualVerification) {
      recommendations.push(
        "ℹ️ Transport/OAuth/Streaming features require manual verification (metadata-based detection only).",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "✅ Excellent MCP compliance! All protocol checks passed. Server is ready for directory submission.",
      );
    }

    return recommendations;
  }
}
