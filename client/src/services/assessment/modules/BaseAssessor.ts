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
}
