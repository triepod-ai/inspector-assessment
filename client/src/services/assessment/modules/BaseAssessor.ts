/**
 * Base Assessor Class
 * Provides common functionality for all assessment modules
 */

import {
  AssessmentConfiguration,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { AssessmentContext } from "../AssessmentOrchestrator";

export abstract class BaseAssessor {
  protected config: AssessmentConfiguration;
  protected testCount: number = 0;

  constructor(config: AssessmentConfiguration) {
    this.config = config;
  }

  /**
   * Abstract method that each assessor must implement
   */
  abstract assess(context: AssessmentContext): Promise<any>;

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
   */
  protected log(message: string): void {
    console.log(`[${this.constructor.name}] ${message}`);
  }

  /**
   * Log error
   */
  protected logError(message: string, error?: any): void {
    console.error(`[${this.constructor.name}] ${message}`, error);
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
  protected safeJsonParse(text: string): any {
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
  protected extractErrorMessage(error: any): string {
    if (typeof error === "string") return error;
    if (error?.message) return error.message;
    if (error?.error) return this.extractErrorMessage(error.error);
    if (error?.content) {
      if (Array.isArray(error.content)) {
        return error.content
          .map((c: any) => c.text || c.content || "")
          .join(" ");
      }
      return error.content;
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
    response: any,
    strictMode: boolean = false,
  ): boolean {
    if (!response) return false;

    // Check explicit error flag first (always check these)
    if (response.isError === true || response.error !== undefined) {
      return true;
    }

    // In strict mode, only rely on explicit error indicators
    // Used by FunctionalityAssessor where we expect valid responses
    if (strictMode) {
      return false;
    }

    // In non-strict mode, also check content for error patterns
    // Used by ErrorHandlingAssessor where we're deliberately triggering errors
    if (response.content) {
      if (typeof response.content === "string") {
        const lower = response.content.toLowerCase();
        // Only flag if error appears at start or with strong indicators
        return (
          lower.startsWith("error:") ||
          lower.startsWith("error ") ||
          lower.includes("error occurred") ||
          lower.includes("failed to") ||
          lower.includes("exception:")
        );
      } else if (Array.isArray(response.content)) {
        // Check if any text content starts with error indicators
        return response.content.some((c: any) => {
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
  protected extractErrorInfo(response: any): {
    code?: string | number;
    message?: string;
  } {
    if (!response) return {};

    // Extract text from content array if present
    let contentText: string | undefined;
    if (Array.isArray(response.content)) {
      const textContent = response.content.find((c: any) => c.type === "text");
      contentText = textContent?.text;
    } else if (typeof response.content === "string") {
      contentText = response.content;
    }

    return {
      code: response.errorCode || response.code || response.error?.code,
      message:
        response.errorMessage ||
        response.message ||
        response.error?.message ||
        contentText,
    };
  }
}
