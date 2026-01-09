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
   * Check if response is just reflection (safe)
   * Two-layer defense: Match reflection patterns, verify NO execution evidence
   */
  isReflectionResponse(responseText: string): boolean {
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
