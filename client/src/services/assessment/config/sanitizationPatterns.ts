/**
 * Sanitization Library Pattern Configuration
 *
 * Detects security libraries and sanitization practices in tool metadata/descriptions.
 * Used by SanitizationDetector to reduce false positives when tools have proper
 * input sanitization in place.
 *
 * Pattern data is now externalized to JSON files for easier maintenance.
 * @see patterns/sanitization-patterns.json
 *
 * @see Issue #56: Improve security analysis granularity
 * @since v1.43.0 (Issue #200 - V2 Refactoring) - Patterns moved to JSON
 */

import {
  loadSanitizationPatterns,
  type SanitizationCategory,
} from "../patterns";

// Re-export SanitizationCategory for backward compatibility
export type { SanitizationCategory };

/**
 * Pattern definition for detecting a specific sanitization library
 */
export interface SanitizationLibraryPattern {
  /** Library name for reporting */
  name: string;
  /** Regex patterns to detect this library */
  patterns: RegExp[];
  /** Type of sanitization this library provides */
  category: SanitizationCategory;
  /** Confidence boost when detected (15-25 points) */
  confidenceBoost: number;
  /** Languages this library is typically used with */
  languageHint?: string[];
}

/**
 * Known sanitization libraries with detection patterns
 *
 * Detection is conservative - patterns match explicit mentions of libraries
 * rather than generic terms that could have other meanings.
 *
 * Pattern data is loaded from patterns/sanitization-patterns.json
 * @see patterns/sanitization-patterns.json for the actual pattern values
 */
export const SANITIZATION_LIBRARY_PATTERNS: SanitizationLibraryPattern[] =
  loadSanitizationPatterns().libraries;

/**
 * Generic sanitization keyword patterns
 *
 * These are less specific than library patterns and provide lower confidence boost.
 * Used when no specific library is detected but sanitization is mentioned.
 *
 * Pattern data is loaded from patterns/sanitization-patterns.json
 */
export const GENERIC_SANITIZATION_KEYWORDS: RegExp[] =
  loadSanitizationPatterns().genericKeywords;

/**
 * Response-time sanitization indicators
 *
 * Patterns that indicate sanitization was applied to the response.
 * These provide evidence that input was processed safely.
 *
 * Pattern data is loaded from patterns/sanitization-patterns.json
 */
export const RESPONSE_SANITIZATION_INDICATORS: RegExp[] =
  loadSanitizationPatterns().responseIndicators;

/**
 * Confidence boost values for different detection types
 *
 * Values are loaded from patterns/sanitization-patterns.json
 */
export const CONFIDENCE_BOOSTS = loadSanitizationPatterns().confidenceBoosts;
