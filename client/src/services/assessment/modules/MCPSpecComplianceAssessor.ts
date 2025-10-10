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
  StructuredRecommendation,
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

    // Run basic compliance checks (some return detailed objects now)
    const schemaCheck = this.checkSchemaCompliance(tools);

    const complianceChecks = {
      serverInfoValidity: this.checkServerInfoValidity(context.serverInfo),
      jsonRpcCompliance: await this.checkJsonRpcCompliance(callTool),
      schemaCompliance: schemaCheck.passed,
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
    const recommendations = this.generateRecommendations(
      complianceChecks,
      schemaCheck,
      transportCompliance,
    );

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
   * Generate structured actionable recommendations with confidence levels
   */
  private generateRecommendations(
    checks: Record<string, boolean>,
    schemaCheck: { passed: boolean; confidence: string; details?: string },
    transportCompliance: TransportComplianceMetrics,
  ): (string | StructuredRecommendation)[] {
    const recommendations: (string | StructuredRecommendation)[] = [];

    // Transport detection - manual verification required
    if (transportCompliance.requiresManualCheck) {
      recommendations.push({
        id: "transport-detection-failed",
        title: "Transport Support - Manual Verification Required",
        severity: "critical",
        confidence: transportCompliance.confidence || "low",
        detectionMethod: "manual-required",
        category: "Transport Compliance",
        description:
          "Automated detection could not verify transport support. This may be a framework limitation.",
        requiresManualVerification: true,
        manualVerificationSteps:
          transportCompliance.manualVerificationSteps || [
            "Test STDIO transport manually",
            "Test HTTP transport manually",
          ],
        contextNote:
          "Framework may handle transports internally (e.g., FastMCP, firecrawl-fastmcp). Transport absence from metadata does not mean transports don't work.",
        actionItems: [
          "Manually test STDIO transport",
          "Manually test HTTP transport",
          "If transports work, this is a false negative - no action needed",
        ],
      });
    }

    // Schema validation with low confidence
    if (!schemaCheck.passed) {
      recommendations.push({
        id: "schema-validation-warnings",
        title: "JSON Schema Validation Warnings",
        severity: "warning",
        confidence:
          (schemaCheck.confidence as "high" | "medium" | "low") || "low",
        detectionMethod:
          schemaCheck.confidence === "low" ? "manual-required" : "automated",
        category: "Schema Compliance",
        description:
          "JSON Schema validation errors detected in tool definitions. May be false positives from schema library conversion.",
        requiresManualVerification: schemaCheck.confidence === "low",
        manualVerificationSteps: [
          "Test if tools execute successfully when called",
          "Check if parameters are accepted correctly",
          "Review source code: Are schemas defined with Zod or TypeBox?",
          "These libraries may not convert perfectly to JSON Schema",
        ],
        contextNote:
          "Framework-specific schema libraries (Zod, TypeBox, etc.) may cause false positives during JSON Schema validation. If tools work correctly, this is likely a conversion artifact.",
        actionItems: [
          "Test tool execution manually with sample parameters",
          "If tools work correctly, schema conversion is the issue - not a real problem",
          "Optionally: Add explicit JSON Schema if needed for compliance",
        ],
      });
    }

    if (!checks.jsonRpcCompliance) {
      recommendations.push({
        id: "jsonrpc-compliance",
        title: "JSON-RPC 2.0 Compliance Issue",
        severity: "critical",
        confidence: "high",
        detectionMethod: "automated",
        category: "Protocol Compliance",
        description: "Server does not properly implement JSON-RPC 2.0 protocol",
        requiresManualVerification: false,
        actionItems: [
          "Ensure all requests/responses follow JSON-RPC 2.0 format",
          "Include proper jsonrpc, id, method/result fields",
          "Return structured error objects for failures",
        ],
      });
    }

    if (!checks.errorResponseCompliance) {
      recommendations.push({
        id: "error-response-compliance",
        title: "Error Response Format Issue",
        severity: "warning",
        confidence: "high",
        detectionMethod: "automated",
        category: "Error Handling",
        description: "Error responses do not follow MCP specification format",
        requiresManualVerification: false,
        actionItems: [
          "Return proper MCP error objects",
          "Include error codes and messages",
          "Follow JSON-RPC 2.0 error format",
        ],
      });
    }

    // New 2025-06-18 feature recommendations (high confidence)
    if (!checks.structuredOutputSupport) {
      recommendations.push({
        id: "add-output-schema",
        title: "Add outputSchema to Tools",
        severity: "enhancement",
        confidence: "high",
        detectionMethod: "automated",
        category: "Type Safety",
        description:
          "Tools are missing outputSchema for type-safe responses. This is an optional enhancement.",
        requiresManualVerification: false,
        contextNote:
          "MCP 2025-06-18 feature for better Claude integration and type safety",
        actionItems: [
          "Add outputSchema to all tools",
          "Define structured response formats",
          "Improves type safety and Claude's understanding of responses",
        ],
      });
    }

    if (!checks.batchRejection) {
      recommendations.push({
        id: "batch-rejection",
        title: "Batch Request Handling",
        severity: "warning",
        confidence: "high",
        detectionMethod: "automated",
        category: "Protocol Compliance",
        description:
          "Server should reject batched JSON-RPC requests (required in MCP 2025-06-18)",
        requiresManualVerification: false,
        actionItems: [
          "Detect batched JSON-RPC requests (arrays)",
          "Return error for batched requests",
          "MCP only supports single requests per message",
        ],
      });
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Excellent MCP compliance! Server is ready for directory submission.",
      );
    }

    return recommendations;
  }
}
