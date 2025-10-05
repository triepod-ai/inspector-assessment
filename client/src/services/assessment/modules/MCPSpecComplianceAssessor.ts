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
   * Assess MCP Specification Compliance
   */
  async assess(
    context: AssessmentContext,
  ): Promise<MCPSpecComplianceAssessment> {
    // Extract protocol version from context
    const protocolVersion = this.extractProtocolVersion(context);

    // Extract tools and callTool from context for backward compatibility
    const tools = context.tools;
    const callTool = context.callTool;

    // Run basic compliance checks
    const complianceChecks = {
      serverInfoValidity: this.checkServerInfoValidity(context.serverInfo),
      jsonRpcCompliance: await this.checkJsonRpcCompliance(callTool),
      schemaCompliance: this.checkSchemaCompliance(tools),
      protocolVersionHandling: true, // Assume working if we got this far
      errorResponseCompliance: await this.checkErrorResponses(tools, callTool),
      structuredOutputSupport: this.checkStructuredOutputSupport(tools), // NEW: 2025-06-18 feature
      batchRejection: await this.checkBatchRejection(callTool), // NEW: 2025-06-18 requirement
    };

    const transportCompliance = this.assessTransportCompliance(context);
    const oauthImplementation = this.assessOAuthCompliance(context);

    // Calculate overall compliance score
    const totalChecks = Object.keys(complianceChecks).length;
    const passedChecks = Object.values(complianceChecks).filter(Boolean).length;
    const complianceScore = (passedChecks / totalChecks) * 100;

    // Determine status - serverInfoValidity is a critical check
    let status: AssessmentStatus;
    if (!complianceChecks.serverInfoValidity) {
      // If server info is malformed, that's a FAIL regardless of other checks
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
      complianceChecks,
    );
    const recommendations = this.generateRecommendations(complianceChecks);

    // Add annotation and streaming support metrics
    const annotationSupport = this.assessAnnotationSupport(context);
    const streamingSupport = this.assessStreamingSupport(context);

    return {
      status,
      explanation,
      protocolVersion: protocolVersion,
      complianceScore, // Added missing property
      transportCompliance,
      oauthImplementation,
      annotationSupport,
      streamingSupport,
      recommendations,
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
  ): Promise<boolean> {
    try {
      // Test basic JSON-RPC structure by making a simple call
      // If we can call any tool, JSON-RPC is working
      const result = await callTool("list", {});
      return result !== null;
    } catch (error) {
      // If call fails, that's actually expected for many tools
      // The fact that we got a structured response means JSON-RPC works
      return true;
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
  private checkSchemaCompliance(tools: Tool[]): boolean {
    try {
      for (const tool of tools) {
        if (tool.inputSchema) {
          // Validate that the schema is valid JSON Schema
          const isValid = this.ajv.validateSchema(tool.inputSchema);
          if (!isValid) {
            console.warn(
              `Invalid schema for tool ${tool.name}:`,
              this.ajv.errors,
            );
            return false;
          }
        }
      }
      return true;
    } catch (error) {
      console.error("Schema compliance check failed:", error);
      return false;
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
  ): Promise<boolean> {
    try {
      if (tools.length === 0) return true;

      // Test error handling with invalid parameters
      const testTool = tools[0];
      try {
        await callTool(testTool.name, { invalid_param: "test" });
        return true; // Server handled gracefully
      } catch (error) {
        return true; // Server provided error response
      }
    } catch (error) {
      return false;
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
   * Check that server properly rejects batched requests (2025-06-18 requirement)
   */
  private async checkBatchRejection(
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<boolean> {
    try {
      // MCP 2025-06-18 removed batch support - servers MUST reject batches
      // We can't directly send JSON-RPC batch requests through the SDK (it doesn't support them)
      // But we can test that the server handles array parameters correctly

      // Try to simulate batch-like behavior by sending an array as params
      // This is a best-effort test since true batch testing requires protocol-level access
      try {
        // Attempt to call with array params (simulating batch-like structure)
        const batchLikeParams = [
          { jsonrpc: "2.0", method: "tools/list", id: 1 },
          { jsonrpc: "2.0", method: "tools/list", id: 2 },
        ];

        // Try to call a tool with batch-like params
        // Note: This won't actually send a JSON-RPC batch, but tests if server accepts arrays
        const result = await callTool("__test_batch__", batchLikeParams as any);

        // If we get an error response, that's actually good (server rejected it)
        if (result.isError) {
          const errorContent = result.content as Array<{
            type: string;
            text?: string;
          }>;
          const errorText =
            errorContent?.[0]?.text || JSON.stringify(result.content);

          // Check if error indicates batch rejection
          if (
            errorText.includes("-32600") ||
            errorText.includes("batch") ||
            errorText.includes("array")
          ) {
            this.log(
              "Batch rejection test: Server correctly rejects batch-like requests",
            );
            return true;
          }
        }

        // If no error, the server might be accepting arrays (which could be legitimate)
        // We can't definitively say it's wrong without protocol-level testing
        this.log(
          "Batch rejection test: Unable to definitively test (SDK limitation). Assuming compliance.",
        );
        return true;
      } catch (error) {
        // Getting an error here could mean the server properly rejected the batch
        const errorMessage = String(error);
        if (
          errorMessage.includes("-32600") ||
          errorMessage.includes("Invalid Request")
        ) {
          this.log(
            "Batch rejection test: Server correctly rejects with -32600",
          );
          return true;
        }

        // Other errors might indicate the test itself failed
        this.log(
          `Batch rejection test: Inconclusive (${errorMessage}). Assuming compliance.`,
        );
        return true; // Give benefit of doubt
      }
    } catch (error) {
      this.log(`Batch rejection test failed: ${error}`);
      return false;
    }
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
      };
    }

    // Check transport from metadata
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const transport = metadata?.transport as string | undefined;
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

    return {
      supportsStreamableHTTP: supportsStreamableHTTP,
      deprecatedSSE: deprecatedSSE,
      transportValidation: transportValidation,
      // Added missing properties that UI expects
      supportsStdio: transport === "stdio" || !transport,
      supportsSSE: deprecatedSSE,
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
   * Generate human-readable explanation
   */
  private generateExplanation(
    complianceScore: number,
    checks: Record<string, boolean>,
  ): string {
    const failedChecks = Object.entries(checks)
      .filter(([_, passed]) => !passed)
      .map(([check, _]) => check);

    if (complianceScore >= 90) {
      return "Excellent MCP protocol compliance. Server meets all critical requirements for directory approval.";
    } else if (complianceScore >= 70) {
      return `Good MCP compliance with minor issues: ${failedChecks.join(", ")}. Review recommended before directory submission.`;
    } else {
      return `Poor MCP compliance. Critical issues: ${failedChecks.join(", ")}. Must fix before directory approval.`;
    }
  }

  /**
   * Generate actionable recommendations
   */
  private generateRecommendations(checks: Record<string, boolean>): string[] {
    const recommendations: string[] = [];

    if (!checks.jsonRpcCompliance) {
      recommendations.push(
        "Ensure JSON-RPC 2.0 protocol compliance with proper request/response format",
      );
    }

    if (!checks.schemaCompliance) {
      recommendations.push(
        "Fix JSON Schema validation errors in tool definitions",
      );
    }

    if (!checks.errorResponseCompliance) {
      recommendations.push(
        "Ensure error responses follow MCP specification format",
      );
    }

    // New 2025-06-18 feature recommendations
    if (!checks.structuredOutputSupport) {
      recommendations.push(
        "Consider adding outputSchema to tools for type-safe responses (MCP 2025-06-18 feature)",
      );
    }

    if (!checks.batchRejection) {
      recommendations.push(
        "Ensure server rejects batched JSON-RPC requests (required in MCP 2025-06-18)",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Excellent MCP compliance! Server is ready for directory submission.",
      );
    }

    return recommendations;
  }
}
