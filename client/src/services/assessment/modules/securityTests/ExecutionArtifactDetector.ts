/**
 * Execution Artifact Detector
 * Detects evidence of actual code/command execution in tool responses
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Handles: execution evidence detection, artifact detection, injection payload echoing
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  EXECUTION_INDICATORS,
  EXECUTION_ARTIFACT_PATTERNS,
  ECHOED_PAYLOAD_PATTERNS,
  FALLBACK_EXECUTION_PATTERNS,
  matchesAny,
} from "./SecurityPatternLibrary";

/**
 * Result of response analysis
 */
export interface AnalysisResult {
  isVulnerable: boolean;
  evidence?: string;
}

/**
 * Detects execution artifacts in tool responses
 */
export class ExecutionArtifactDetector {
  /**
   * Check if response contains evidence of actual execution
   * Used to distinguish between safe reflection and actual command/code execution
   */
  hasExecutionEvidence(responseText: string): boolean {
    return matchesAny(EXECUTION_INDICATORS, responseText);
  }

  /**
   * Detect execution artifacts in response
   * Two-tier detection: unambiguous artifacts + context-sensitive patterns
   */
  detectExecutionArtifacts(responseText: string): boolean {
    const containsEchoedPayload =
      this.containsEchoedInjectionPayload(responseText);

    // Check always-execution patterns
    if (matchesAny(EXECUTION_ARTIFACT_PATTERNS.alwaysExecution, responseText)) {
      return true;
    }

    // Context-sensitive patterns only count if no echoed payload present
    if (!containsEchoedPayload) {
      if (
        matchesAny(EXECUTION_ARTIFACT_PATTERNS.contextSensitive, responseText)
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if response contains echoed injection payload patterns
   * These indicate the payload was stored/reflected, not executed
   */
  containsEchoedInjectionPayload(responseText: string): boolean {
    return matchesAny(ECHOED_PAYLOAD_PATTERNS, responseText);
  }

  /**
   * Analyze injection response (fallback logic)
   * Used when primary detection methods are inconclusive
   *
   * @param responseText The response text to analyze
   * @param isReflectionCheck Function to check if response is reflection
   * @returns Analysis result with vulnerability status
   */
  analyzeInjectionResponse(
    responseText: string,
    isReflectionCheck: (text: string) => boolean,
  ): AnalysisResult {
    const hasExecution = matchesAny(FALLBACK_EXECUTION_PATTERNS, responseText);

    if (hasExecution && !isReflectionCheck(responseText)) {
      return {
        isVulnerable: true,
        evidence: "Tool executed instruction: found execution keywords",
      };
    }

    return { isVulnerable: false };
  }

  /**
   * Extract response content from MCP response
   */
  extractResponseContent(response: CompatibilityCallToolResult): string {
    if (response.content && Array.isArray(response.content)) {
      return response.content
        .map((c: { type: string; text?: string }) =>
          c.type === "text" ? c.text : "",
        )
        .join(" ");
    }
    return String(response.content || "");
  }
}
