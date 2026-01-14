/**
 * Error Classifier
 * Classifies and analyzes error responses for security testing
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Handles: connection error detection, error classification, error info extraction
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  CONNECTION_ERROR_PATTERNS,
  ERROR_CLASSIFICATION_PATTERNS,
  matchesAny,
  hasMcpErrorPrefix,
  isTransientErrorPattern,
} from "./SecurityPatternLibrary";

/**
 * Error classification types
 */
export type ErrorClassification = "connection" | "server" | "protocol";

/**
 * Extracted error information from response
 */
export interface ErrorInfo {
  code?: string | number;
  message?: string;
}

/**
 * Classifies errors from tool responses and exceptions
 */
export class ErrorClassifier {
  /**
   * Check if response indicates connection/server failure
   */
  isConnectionError(response: CompatibilityCallToolResult): boolean {
    const text = this.extractResponseContent(response).toLowerCase();
    return this.isConnectionErrorFromText(text);
  }

  /**
   * Check if caught exception indicates connection/server failure
   */
  isConnectionErrorFromException(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return this.isConnectionErrorFromText(message);
    }
    return false;
  }

  /**
   * Check if response indicates transient error worth retrying.
   * Transient errors (ECONNREFUSED, ETIMEDOUT, etc.) may resolve on retry.
   * Permanent errors (unknown tool, unauthorized) will not.
   *
   * @see https://github.com/triepod-ai/inspector-assessment/issues/157
   */
  isTransientError(response: CompatibilityCallToolResult): boolean {
    const text = this.extractResponseContent(response).toLowerCase();
    return isTransientErrorPattern(text);
  }

  /**
   * Check if caught exception indicates transient error worth retrying.
   *
   * @see https://github.com/triepod-ai/inspector-assessment/issues/157
   */
  isTransientErrorFromException(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return isTransientErrorPattern(message);
    }
    return false;
  }

  /**
   * Internal: Check if text indicates connection/server failure
   */
  private isConnectionErrorFromText(text: string): boolean {
    // Check unambiguous patterns first
    if (matchesAny(CONNECTION_ERROR_PATTERNS.unambiguous, text)) {
      return true;
    }

    // Check contextual patterns only if text has MCP error prefix
    if (hasMcpErrorPrefix(text)) {
      if (matchesAny(CONNECTION_ERROR_PATTERNS.contextual, text)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Classify error type for reporting
   */
  classifyError(response: CompatibilityCallToolResult): ErrorClassification {
    const text = this.extractResponseContent(response).toLowerCase();
    return this.classifyErrorFromText(text);
  }

  /**
   * Classify error type from caught exception
   */
  classifyErrorFromException(error: unknown): ErrorClassification {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return this.classifyErrorFromText(message);
    }
    return "protocol";
  }

  /**
   * Internal: Classify error type from text
   */
  private classifyErrorFromText(text: string): ErrorClassification {
    if (ERROR_CLASSIFICATION_PATTERNS.connection.test(text)) {
      return "connection";
    }

    if (ERROR_CLASSIFICATION_PATTERNS.server.test(text)) {
      return "server";
    }

    if (ERROR_CLASSIFICATION_PATTERNS.protocol.test(text)) {
      return "protocol";
    }

    return "protocol";
  }

  /**
   * Extract error info from response
   */
  extractErrorInfo(response: CompatibilityCallToolResult): ErrorInfo {
    const content = this.extractResponseContent(response);

    try {
      const parsed = JSON.parse(content);
      if (parsed.error) {
        return {
          code: parsed.error.code || parsed.code,
          message: parsed.error.message || parsed.message,
        };
      }
      return { code: parsed.code, message: parsed.message };
    } catch {
      // Check for MCP error format in text
      const mcpMatch = content.match(/MCP error (-?\d+):\s*(.*)/i);
      if (mcpMatch) {
        return { code: parseInt(mcpMatch[1]), message: mcpMatch[2] };
      }
      return {};
    }
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
