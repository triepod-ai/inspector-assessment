/**
 * Assessment Error Types
 *
 * Provides standardized error handling across all assessment modules.
 * See docs/ERROR_HANDLING_CONVENTIONS.md for usage guidelines.
 */

/**
 * Error categories for classification and debugging
 */
export enum ErrorCategory {
  /** Network connectivity issues (ECONNREFUSED, DNS failures, etc.) */
  CONNECTION = "CONNECTION",
  /** MCP protocol violations or unexpected responses */
  PROTOCOL = "PROTOCOL",
  /** Input validation failures (invalid parameters, missing fields) */
  VALIDATION = "VALIDATION",
  /** Operation exceeded time limit */
  TIMEOUT = "TIMEOUT",
  /** JSON or data parsing failures */
  PARSE = "PARSE",
  /** Unclassified errors */
  UNKNOWN = "UNKNOWN",
}

/**
 * Custom error class for assessment operations
 *
 * @example
 * throw new AssessmentError(
 *   'Failed to connect to MCP server',
 *   ErrorCategory.CONNECTION,
 *   false, // not recoverable
 *   { url: 'http://localhost:3000', attempt: 3 }
 * );
 */
export class AssessmentError extends Error {
  constructor(
    message: string,
    public readonly code: ErrorCategory,
    public readonly recoverable: boolean = true,
    public readonly context?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AssessmentError";
    // Maintains proper stack trace in V8 environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AssessmentError);
    }
  }

  /**
   * Create a structured object for serialization
   */
  toJSON(): ErrorInfo {
    return {
      message: this.message,
      code: this.code,
      recoverable: this.recoverable,
      stack: this.stack,
      context: this.context,
    };
  }
}

/**
 * Structured error information for result objects
 */
export interface ErrorInfo {
  /** Human-readable error message */
  message: string;
  /** Error category for classification */
  code: ErrorCategory;
  /** Whether the operation can be retried */
  recoverable: boolean;
  /** Stack trace (optional, for debugging) */
  stack?: string;
  /** Additional context about the error */
  context?: Record<string, unknown>;
}

/**
 * Interface for result objects that may contain errors
 *
 * @example
 * interface ToolTestResult extends ErrorResult {
 *   toolName: string;
 *   passed: boolean;
 * }
 */
export interface ErrorResult {
  error?: ErrorInfo;
}

/**
 * Type guard to check if a value is an AssessmentError
 */
export function isAssessmentError(error: unknown): error is AssessmentError {
  return error instanceof AssessmentError;
}

/**
 * Categorize an error based on its message content
 *
 * @param error - The error to categorize
 * @returns The appropriate ErrorCategory
 */
export function categorizeError(error: unknown): ErrorCategory {
  const message = extractErrorMessage(error).toLowerCase();

  if (message.includes("timeout") || message.includes("timed out")) {
    return ErrorCategory.TIMEOUT;
  }
  if (
    message.includes("connection") ||
    message.includes("econnrefused") ||
    message.includes("enotfound") ||
    message.includes("network")
  ) {
    return ErrorCategory.CONNECTION;
  }
  if (
    message.includes("parse") ||
    message.includes("json") ||
    message.includes("syntax")
  ) {
    return ErrorCategory.PARSE;
  }
  if (
    message.includes("protocol") ||
    message.includes("mcp") ||
    message.includes("invalid response")
  ) {
    return ErrorCategory.PROTOCOL;
  }
  if (
    message.includes("invalid") ||
    message.includes("required") ||
    message.includes("missing") ||
    message.includes("validation")
  ) {
    return ErrorCategory.VALIDATION;
  }

  return ErrorCategory.UNKNOWN;
}

/**
 * Extract error message from various error types
 *
 * @param error - The error to extract message from
 * @returns A string error message
 */
export function extractErrorMessage(error: unknown): string {
  if (typeof error === "string") {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  if (error && typeof error === "object") {
    const err = error as Record<string, unknown>;
    if (typeof err.message === "string") {
      return err.message;
    }
    if (typeof err.error === "string") {
      return err.error;
    }
    if (err.error && typeof err.error === "object") {
      return extractErrorMessage(err.error);
    }
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}
