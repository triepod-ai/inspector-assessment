/**
 * Token Estimation Utilities
 *
 * Provides token counting and threshold detection for tiered output strategy.
 * Uses industry-standard approximation of ~4 characters per token.
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @module assessment/summarizer/tokenEstimator
 */

import type { MCPDirectoryAssessment } from "../resultTypes";
import { DEFAULT_SUMMARIZER_CONFIG } from "./types";

// ============================================================================
// Constants
// ============================================================================

/**
 * Average characters per token for modern LLMs (GPT, Claude).
 * This is an approximation; actual tokenization varies by model and content.
 */
const CHARS_PER_TOKEN = 4;

/**
 * Buffer factor to account for JSON formatting overhead.
 * Pretty-printed JSON adds whitespace that increases character count.
 */
const JSON_FORMAT_BUFFER = 1.1;

// ============================================================================
// Token Estimation Functions
// ============================================================================

/**
 * Estimate the number of tokens for any content.
 *
 * Uses the industry-standard approximation of ~4 characters per token.
 * For JSON content, applies a buffer for formatting overhead.
 *
 * @param content - Content to estimate (string, object, or array)
 * @returns Estimated token count
 *
 * @example
 * ```typescript
 * // String content
 * estimateTokens("Hello world"); // ~3 tokens
 *
 * // Object content (will be JSON stringified)
 * estimateTokens({ name: "test", value: 123 }); // ~10 tokens
 *
 * // Large assessment results
 * estimateTokens(assessmentResults); // ~50,000+ tokens
 * ```
 */
export function estimateTokens(content: unknown): number {
  let charCount: number;

  if (typeof content === "string") {
    charCount = content.length;
  } else if (content === null || content === undefined) {
    return 0;
  } else {
    // JSON stringify for objects/arrays
    try {
      const json = JSON.stringify(content, null, 2);
      charCount = Math.ceil(json.length * JSON_FORMAT_BUFFER);
    } catch {
      // Fallback for circular references or other stringify issues
      return 0;
    }
  }

  return Math.ceil(charCount / CHARS_PER_TOKEN);
}

/**
 * Estimate tokens for a JSON file that would be written.
 * Accounts for pretty-printing with indent=2.
 *
 * @param content - Content that would be JSON.stringify'd
 * @returns Estimated token count
 */
export function estimateJsonFileTokens(content: unknown): number {
  if (content === null || content === undefined) {
    return 0;
  }

  try {
    const json = JSON.stringify(content, null, 2);
    return Math.ceil(json.length / CHARS_PER_TOKEN);
  } catch {
    return 0;
  }
}

/**
 * Determine if assessment results should automatically use tiered output.
 *
 * Returns true when estimated token count exceeds the threshold,
 * indicating the full output would not fit in typical LLM context windows.
 *
 * @param results - Full assessment results
 * @param threshold - Token threshold (default: 100,000)
 * @returns true if results should be tiered
 *
 * @example
 * ```typescript
 * const results = await runAssessment(server);
 *
 * if (shouldAutoTier(results)) {
 *   // Use tiered output
 *   saveTieredResults(serverName, results, options);
 * } else {
 *   // Use standard full output
 *   saveResults(serverName, results, options);
 * }
 * ```
 */
export function shouldAutoTier(
  results: MCPDirectoryAssessment,
  threshold: number = DEFAULT_SUMMARIZER_CONFIG.autoTierThreshold,
): boolean {
  const estimated = estimateTokens(results);
  return estimated > threshold;
}

/**
 * Get a human-readable token estimate with size category.
 *
 * @param tokenCount - Number of tokens
 * @returns Object with formatted token count and size category
 *
 * @example
 * ```typescript
 * formatTokenEstimate(5000);
 * // { tokens: "5,000", category: "small", fitsContext: true }
 *
 * formatTokenEstimate(500000);
 * // { tokens: "500,000", category: "very-large", fitsContext: false }
 * ```
 */
export function formatTokenEstimate(tokenCount: number): {
  tokens: string;
  category: "small" | "medium" | "large" | "very-large" | "oversized";
  fitsContext: boolean;
  recommendation: string;
} {
  const formatted = tokenCount.toLocaleString();

  let category: "small" | "medium" | "large" | "very-large" | "oversized";
  let fitsContext: boolean;
  let recommendation: string;

  if (tokenCount <= 10_000) {
    category = "small";
    fitsContext = true;
    recommendation = "Full output recommended";
  } else if (tokenCount <= 50_000) {
    category = "medium";
    fitsContext = true;
    recommendation = "Full output should fit most contexts";
  } else if (tokenCount <= 100_000) {
    category = "large";
    fitsContext = true;
    recommendation = "Consider tiered output for smaller context windows";
  } else if (tokenCount <= 200_000) {
    category = "very-large";
    fitsContext = false;
    recommendation = "Tiered output recommended";
  } else {
    category = "oversized";
    fitsContext = false;
    recommendation = "Tiered output required";
  }

  return { tokens: formatted, category, fitsContext, recommendation };
}

/**
 * Estimate tokens for each major section of assessment results.
 * Useful for understanding which modules contribute most to output size.
 *
 * @param results - Assessment results to analyze
 * @returns Map of section name to estimated token count
 */
export function estimateSectionTokens(
  results: MCPDirectoryAssessment,
): Record<string, number> {
  const sections: Record<string, number> = {};

  // Core assessment sections
  const sectionKeys = [
    "functionality",
    "security",
    "errorHandling",
    "aupCompliance",
    "toolAnnotations",
    "temporal",
    "resources",
    "prompts",
    "crossCapability",
    "protocolCompliance",
    "developerExperience",
    "prohibitedLibraries",
    "manifestValidation",
    "authentication",
    "portability",
    "externalAPIScanner",
  ] as const;

  for (const key of sectionKeys) {
    const section = results[key as keyof MCPDirectoryAssessment];
    if (section !== undefined) {
      sections[key] = estimateTokens(section);
    }
  }

  // Metadata and summary
  sections["metadata"] = estimateTokens({
    serverName: results.serverName,
    overallStatus: results.overallStatus,
    summary: results.summary,
    recommendations: results.recommendations,
    totalTestsRun: results.totalTestsRun,
    executionTime: results.executionTime,
  });

  // Calculate total
  sections["_total"] = Object.entries(sections)
    .filter(([key]) => !key.startsWith("_"))
    .reduce((sum, [, tokens]) => sum + tokens, 0);

  return sections;
}

/**
 * Get the top N largest sections by token count.
 *
 * @param results - Assessment results
 * @param topN - Number of sections to return (default: 5)
 * @returns Array of [sectionName, tokenCount] sorted by size descending
 */
export function getTopSections(
  results: MCPDirectoryAssessment,
  topN: number = 5,
): Array<[string, number]> {
  const sections = estimateSectionTokens(results);

  return Object.entries(sections)
    .filter(([key]) => !key.startsWith("_"))
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN);
}
