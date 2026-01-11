/**
 * Zod Error Formatting Utilities
 *
 * CLI-friendly error message formatting for Zod validation errors.
 *
 * @module cli/lib/zodErrorFormatter
 */

import { ZodError, ZodIssue } from "zod";

/**
 * Format a single Zod issue into a readable string.
 *
 * @param issue - Zod validation issue
 * @returns Formatted error message
 */
export function formatZodIssue(issue: ZodIssue): string {
  const path = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
  return `${path}${issue.message}`;
}

/**
 * Format a ZodError into a readable string.
 * Detects union validation failures and extracts the most specific error messages.
 *
 * @param error - Zod validation error
 * @returns Formatted error messages joined by newlines
 */
export function formatZodError(error: ZodError): string {
  // Check if this is a union validation error (code: invalid_union)
  const unionErrors = error.errors.filter((e) => e.code === "invalid_union");

  if (unionErrors.length > 0) {
    // Extract detailed errors from union attempts
    const detailedErrors: string[] = [];

    for (const unionError of unionErrors) {
      // Union errors have unionErrors property with detailed failures
      if (
        "unionErrors" in unionError &&
        Array.isArray(unionError.unionErrors)
      ) {
        for (const subError of unionError.unionErrors as ZodError[]) {
          // Find the most specific error message (not "Required")
          const specificErrors = subError.errors.filter(
            (e) => e.message !== "Required" && e.code !== "invalid_type",
          );

          if (specificErrors.length > 0) {
            detailedErrors.push(...specificErrors.map(formatZodIssue));
          } else {
            // Fallback to any error from this branch
            detailedErrors.push(...subError.errors.map(formatZodIssue));
          }
        }
      }
    }

    // If we found detailed errors, use them; otherwise fall back to generic message
    if (detailedErrors.length > 0) {
      // Deduplicate errors and return all unique errors
      const uniqueErrors = Array.from(new Set(detailedErrors));
      return uniqueErrors.join("\n");
    }
  }

  // Standard formatting for non-union errors
  return error.errors.map(formatZodIssue).join("\n");
}

/**
 * Format a ZodError with indentation for CLI output.
 *
 * @param error - Zod validation error
 * @param indent - Indentation string (default: "  ")
 * @returns Formatted error messages with indentation
 */
export function formatZodErrorIndented(
  error: ZodError,
  indent: string = "  ",
): string {
  return error.errors.map((e) => `${indent}${formatZodIssue(e)}`).join("\n");
}

/**
 * Print a formatted Zod error to stderr with context.
 *
 * @param error - Zod validation error
 * @param context - Context description (e.g., "config file", "CLI arguments")
 */
export function printZodErrorForCli(error: ZodError, context?: string): void {
  const prefix = context ? `Error in ${context}:\n` : "Validation error:\n";
  console.error(prefix + formatZodErrorIndented(error));
}

/**
 * Convert ZodError to an array of error strings.
 * Useful for accumulating errors in a validation result.
 *
 * @param error - Zod validation error
 * @returns Array of formatted error strings
 */
export function zodErrorToArray(error: ZodError): string[] {
  return error.errors.map(formatZodIssue);
}

/**
 * Format validation errors for JSON output.
 *
 * @param error - Zod validation error
 * @returns Object with structured error information
 */
export function formatZodErrorForJson(error: ZodError): {
  message: string;
  errors: Array<{
    path: (string | number)[];
    message: string;
    code: string;
  }>;
} {
  return {
    message: "Validation failed",
    errors: error.errors.map((e) => ({
      path: e.path,
      message: e.message,
      code: e.code,
    })),
  };
}

/**
 * Create a user-friendly error message for common validation issues.
 *
 * @param error - Zod validation error
 * @param fieldLabels - Optional map of field names to user-friendly labels
 * @returns User-friendly error message
 */
export function formatUserFriendlyError(
  error: ZodError,
  fieldLabels?: Record<string, string>,
): string {
  const messages = error.errors.map((issue) => {
    const fieldPath = issue.path.join(".");
    const label = fieldLabels?.[fieldPath] || fieldPath;
    const prefix = label ? `${label}: ` : "";
    return `${prefix}${issue.message}`;
  });

  if (messages.length === 1) {
    return messages[0];
  }

  return `Multiple validation errors:\n${messages.map((m) => `  - ${m}`).join("\n")}`;
}
