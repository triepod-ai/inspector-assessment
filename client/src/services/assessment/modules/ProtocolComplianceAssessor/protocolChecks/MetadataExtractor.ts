/**
 * Metadata Hints Extractor
 *
 * Extracts metadata hints for transport, OAuth, annotations, and streaming.
 * LOW CONFIDENCE - not tested, just parsed from serverInfo.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/MetadataExtractor
 * @see GitHub Issue #188
 */

import type {
  MetadataHints,
  TransportComplianceMetrics,
  OAuthComplianceMetrics,
  AnnotationSupportMetrics,
  StreamingSupportMetrics,
} from "@/lib/assessmentTypes";
import type { AssessmentContext } from "../../../AssessmentOrchestrator";
import type { Logger, AssessmentConfiguration } from "../types";

/**
 * Extracts and parses metadata hints from server info.
 */
export class MetadataExtractor {
  constructor(_config: AssessmentConfiguration, _logger: Logger) {}

  /**
   * Extract all metadata hints from context.
   */
  extractHints(context: AssessmentContext): MetadataHints | undefined {
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
   * Assess transport compliance (legacy compatibility).
   */
  assessTransportCompliance(
    context: AssessmentContext,
  ): TransportComplianceMetrics {
    // Issue #172: Check source-based transport detection first
    if (context.transportDetection?.supportsStdio) {
      return {
        supportsStreamableHTTP: context.transportDetection.supportsHTTP,
        deprecatedSSE: context.transportDetection.supportsSSE,
        transportValidation: "passed",
        supportsStdio: true,
        supportsSSE: context.transportDetection.supportsSSE,
        confidence: context.transportDetection.confidence,
        detectionMethod: "source-code-analysis",
        requiresManualCheck: false,
        transportEvidence: context.transportDetection.evidence.map(
          (e) => `${e.source}: ${e.detail}`,
        ),
      };
    }

    // HTTP-only detection
    if (
      context.transportDetection?.supportsHTTP &&
      !context.transportDetection?.supportsStdio
    ) {
      return {
        supportsStreamableHTTP: true,
        deprecatedSSE: context.transportDetection.supportsSSE,
        transportValidation: "passed",
        supportsStdio: false,
        supportsSSE: context.transportDetection.supportsSSE,
        confidence: context.transportDetection.confidence,
        detectionMethod: "source-code-analysis",
        requiresManualCheck: false,
        transportEvidence: context.transportDetection.evidence.map(
          (e) => `${e.source}: ${e.detail}`,
        ),
      };
    }

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

  /**
   * Assess OAuth compliance (legacy compatibility).
   */
  assessOAuthCompliance(
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
      resourceIndicators.push(...(oauthConfig.resourceIndicators as string[]));
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

  /**
   * Assess annotation support (legacy compatibility).
   */
  assessAnnotationSupport(
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

  /**
   * Assess streaming support (legacy compatibility).
   */
  assessStreamingSupport(context: AssessmentContext): StreamingSupportMetrics {
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
}
