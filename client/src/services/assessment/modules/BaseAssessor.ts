/**
 * Base Assessor Class
 * Provides common functionality for all assessment modules
 */

import {
  AssessmentConfiguration,
  AssessmentStatus,
  MCPContent,
} from "@/lib/assessmentTypes";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Logger, createLogger, DEFAULT_LOGGING_CONFIG } from "../lib/logger";

export abstract class BaseAssessor<T = unknown> {
  protected config: AssessmentConfiguration;
  protected logger: Logger;
  protected testCount: number = 0;

  constructor(config: AssessmentConfiguration) {
    this.config = config;
    // Create logger from config, using class name as prefix
    this.logger = createLogger(
      this.constructor.name,
      config.logging ?? DEFAULT_LOGGING_CONFIG,
    );
  }

  /**
   * Abstract method that each assessor must implement
   */
  abstract assess(context: AssessmentContext): Promise<T>;

  /**
   * Common method to determine status based on pass rate
   */
  protected determineStatus(
    passed: number,
    total: number,
    threshold: number = 0.8,
  ): AssessmentStatus {
    if (total === 0) return "NEED_MORE_INFO";

    const passRate = passed / total;

    if (passRate >= threshold) return "PASS";
    if (passRate >= threshold * 0.5) return "NEED_MORE_INFO";
    return "FAIL";
  }

  /**
   * Log assessment progress
   * @deprecated Use this.logger.info() directly for structured logging with context
   */
  protected log(message: string): void {
    this.logger.info(message);
  }

  /**
   * Log error
   * @deprecated Use this.logger.error() directly for structured logging with context
   */
  protected logError(message: string, error?: unknown): void {
    this.logger.error(message, error ? { error: String(error) } : undefined);
  }

  /**
   * Get test count for this assessor
   */
  getTestCount(): number {
    return this.testCount;
  }

  /**
   * Reset test count
   */
  resetTestCount(): void {
    this.testCount = 0;
  }

  /**
   * Check if a feature is enabled in configuration
   */
  protected isFeatureEnabled(
    feature: keyof AssessmentConfiguration["assessmentCategories"],
  ): boolean {
    return this.config.assessmentCategories?.[feature] ?? false;
  }

  /**
   * Sleep for specified milliseconds (useful for rate limiting)
   */
  protected async sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Execute with timeout
   */
  protected async executeWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number = this.config.testTimeout,
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new Error(`Operation timed out after ${timeoutMs}ms`)),
        timeoutMs,
      );
    });

    return Promise.race([promise, timeoutPromise]);
  }

  /**
   * Safe JSON parse with error handling
   */
  protected safeJsonParse(text: string): unknown {
    try {
      return JSON.parse(text);
    } catch (error) {
      this.logError(`Failed to parse JSON: ${text}`, error);
      return null;
    }
  }

  /**
   * Extract error message from various error types
   */
  protected extractErrorMessage(error: unknown): string {
    if (typeof error === "string") return error;
    if (error && typeof error === "object") {
      const err = error as Record<string, unknown>;
      if (err.message && typeof err.message === "string") return err.message;
      if (err.error) return this.extractErrorMessage(err.error);
      if (err.content) {
        if (Array.isArray(err.content)) {
          return err.content.map((c: MCPContent) => c.text || "").join(" ");
        }
        if (typeof err.content === "string") return err.content;
      }
    }
    return JSON.stringify(error);
  }

  /**
   * Check if a response indicates an error
   * Handles various MCP response formats
   *
   * @param response - The response to check
   * @param strictMode - If true, only check explicit error indicators (default: false)
   */
  protected isErrorResponse(
    response: unknown,
    strictMode: boolean = false,
  ): boolean {
    if (!response || typeof response !== "object") return false;
    const resp = response as Record<string, unknown>;

    // Check explicit error flag first (always check these)
    if (resp.isError === true || resp.error !== undefined) {
      return true;
    }

    // In strict mode, only rely on explicit error indicators
    // Used by FunctionalityAssessor where we expect valid responses
    if (strictMode) {
      return false;
    }

    // In non-strict mode, also check content for error patterns
    // Used by ErrorHandlingAssessor where we're deliberately triggering errors
    if (resp.content) {
      if (typeof resp.content === "string") {
        const lower = resp.content.toLowerCase();
        // Only flag if error appears at start or with strong indicators
        return (
          lower.startsWith("error:") ||
          lower.startsWith("error ") ||
          lower.includes("error occurred") ||
          lower.includes("failed to") ||
          lower.includes("exception:")
        );
      } else if (Array.isArray(resp.content)) {
        // Check if any text content starts with error indicators
        return resp.content.some((c: MCPContent) => {
          if (c.type !== "text" || !c.text) return false;
          const lower = c.text.toLowerCase();
          return (
            lower.startsWith("error:") ||
            lower.startsWith("error ") ||
            lower.includes("error occurred") ||
            lower.includes("failed to") ||
            lower.includes("exception:")
          );
        });
      }
    }

    return false;
  }

  /**
   * Extract error information from a response
   */
  protected extractErrorInfo(response: unknown): {
    code?: string | number;
    message?: string;
  } {
    if (!response || typeof response !== "object") return {};
    const resp = response as Record<string, unknown>;

    // Extract text from content array if present
    let contentText: string | undefined;
    if (Array.isArray(resp.content)) {
      const textContent = resp.content.find(
        (c: MCPContent) => c.type === "text",
      );
      contentText = textContent?.text;
    } else if (typeof resp.content === "string") {
      contentText = resp.content;
    }

    const error = resp.error as Record<string, unknown> | undefined;
    return {
      code: (resp.errorCode ?? resp.code ?? error?.code) as
        | string
        | number
        | undefined,
      message:
        ((resp.errorMessage ?? resp.message ?? error?.message) as
          | string
          | undefined) || contentText,
    };
  }
}
