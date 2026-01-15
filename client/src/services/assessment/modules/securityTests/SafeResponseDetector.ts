/**
 * Safe Response Detector
 * Detects safe (non-vulnerable) response patterns
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Handles: MCP validation, HTTP errors, reflection detection, validation rejection
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  VALIDATION_ERROR_PATTERNS,
  STATUS_PATTERNS,
  REFLECTION_PATTERNS,
  SEARCH_RESULT_PATTERNS,
  CREATION_PATTERNS,
  TEXT_REJECTION_PATTERNS,
  RESULT_REJECTION_PATTERNS,
  isHttpError,
  matchesAny,
  hasLLMInjectionMarkers,
  hasOutputInjectionVulnerability,
  isAppleScriptSyntaxError as isAppleScriptSyntaxErrorPattern,
} from "./SecurityPatternLibrary";
import { ExecutionArtifactDetector } from "./ExecutionArtifactDetector";

/**
 * Error info extracted from response
 */
export interface ErrorInfo {
  code?: string | number;
  message?: string;
}

/**
 * Result of safe response check
 */
export interface SafeResponseResult {
  isSafe: boolean;
  reason?: string;
}

/**
 * Detects safe response patterns indicating proper tool behavior
 */
export class SafeResponseDetector {
  private executionDetector: ExecutionArtifactDetector;

  constructor() {
    this.executionDetector = new ExecutionArtifactDetector();
  }

  /**
   * Check if response is an MCP validation error (safe rejection)
   */
  isMCPValidationError(errorInfo: ErrorInfo, responseText: string): boolean {
    if (errorInfo.code === -32602 || errorInfo.code === "-32602") {
      return true;
    }

    return matchesAny(VALIDATION_ERROR_PATTERNS, responseText);
  }

  /**
   * Check if response is an HTTP error (Issue #26)
   */
  isHttpErrorResponse(responseText: string): boolean {
    return isHttpError(responseText);
  }

  /**
   * Check if response is an AppleScript syntax error (Issue #175)
   * These errors should not be flagged as XXE vulnerabilities even when
   * the XXE payload is echoed back in the error message.
   */
  isAppleScriptSyntaxError(responseText: string): boolean {
    return isAppleScriptSyntaxErrorPattern(responseText);
  }

  /**
   * Check if response is just reflection (safe)
   * Two-layer defense: Match reflection patterns, verify NO execution evidence
   *
   * Issue #110, Challenge #8: Also checks for LLM injection markers and
   * output injection vulnerability metadata before declaring response safe.
   */
  isReflectionResponse(responseText: string): boolean {
    // Issue #110: Check for LLM injection markers BEFORE reflection check
    // If response contains <IMPORTANT>, [INST], or similar markers, it's not safe
    if (hasLLMInjectionMarkers(responseText)) {
      return false; // Not safe - contains potential LLM injection
    }

    // Issue #110: Check for output injection vulnerability metadata
    // If tool self-reports raw_content_included or injection risk, it's not safe
    if (hasOutputInjectionVulnerability(responseText)) {
      return false; // Not safe - tool reports output injection vulnerability
    }

    // Combine status patterns and reflection patterns
    const allReflectionPatterns = [...STATUS_PATTERNS, ...REFLECTION_PATTERNS];

    const hasReflection = matchesAny(allReflectionPatterns, responseText);

    if (hasReflection) {
      try {
        const parsed = JSON.parse(responseText);
        const resultText = String(parsed.result || "");
        const outputFields = [
          parsed.stdout,
          parsed.stderr,
          parsed.output,
          parsed.contents,
          parsed.execution_log,
          parsed.command_output,
        ]
          .filter(Boolean)
          .join(" ");

        const resultIsStatusOnly = matchesAny(STATUS_PATTERNS, resultText);

        const hasExecutionInOutput = resultIsStatusOnly
          ? this.executionDetector.detectExecutionArtifacts(outputFields)
          : this.executionDetector.detectExecutionArtifacts(resultText) ||
            this.executionDetector.detectExecutionArtifacts(outputFields);

        if (hasExecutionInOutput) {
          return false;
        }
        return true;
      } catch {
        const hasExecution =
          this.executionDetector.detectExecutionArtifacts(responseText);

        if (hasExecution) {
          return false;
        }
        return true;
      }
    }

    // Check for JSON status patterns
    try {
      const parsed = JSON.parse(responseText);

      if (parsed.action === "test" || parsed.action === "placeholder") {
        const resultText = String(parsed.result || "");
        if (!this.executionDetector.detectExecutionArtifacts(resultText)) {
          return true;
        }
      }

      if (parsed.status && /(completed|success|ok|done)/.test(parsed.status)) {
        if (!this.executionDetector.detectExecutionArtifacts(responseText)) {
          return true;
        }
      }
    } catch {
      // Not JSON
    }

    return false;
  }

  /**
   * Check if response is returning search results
   */
  isSearchResultResponse(responseText: string): boolean {
    return matchesAny(SEARCH_RESULT_PATTERNS, responseText);
  }

  /**
   * Check if response is from a creation/modification operation
   */
  isCreationResponse(responseText: string): boolean {
    return matchesAny(CREATION_PATTERNS, responseText);
  }

  /**
   * Check if tool explicitly rejected input with validation error (SAFE)
   */
  isValidationRejection(response: CompatibilityCallToolResult): boolean {
    const responseText = this.extractResponseContent(response);

    try {
      const parsed = JSON.parse(responseText);

      if (
        parsed.valid === false ||
        parsed.error === true ||
        parsed.error === "true" ||
        (parsed.error && parsed.error !== false) ||
        parsed.status === "rejected" ||
        parsed.status === "invalid" ||
        parsed.status === "failed"
      ) {
        return true;
      }

      if (
        parsed.errors &&
        Array.isArray(parsed.errors) &&
        parsed.errors.length > 0
      ) {
        return true;
      }

      if (parsed.error && typeof parsed.error === "string") {
        return true;
      }

      if (typeof parsed.result === "string") {
        if (matchesAny(RESULT_REJECTION_PATTERNS, parsed.result)) {
          return true;
        }
      }
    } catch {
      // Not JSON, check text patterns
    }

    return matchesAny(TEXT_REJECTION_PATTERNS, responseText);
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
