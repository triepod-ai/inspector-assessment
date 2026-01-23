/**
 * Pattern Loader Utility
 *
 * Loads pattern configurations from JSON files and converts string patterns
 * to compiled RegExp objects at runtime.
 *
 * Benefits:
 * - Patterns can be updated without code changes
 * - JSON files are easier to review and audit
 * - Custom patterns via CLI flag (future: --patterns <path>)
 * - Smaller TypeScript bundle
 *
 * @module assessment/patterns/patternLoader
 * @since v1.43.0 (Issue #200 - V2 Refactoring)
 */

// Import JSON files directly (TypeScript resolveJsonModule)
// Node.js v22+ requires import attributes for JSON modules
import annotationPatternsJson from "./annotation-patterns.json" with { type: "json" };
import sanitizationPatternsJson from "./sanitization-patterns.json" with { type: "json" };

// ============================================================================
// Types
// ============================================================================

/**
 * Raw annotation patterns from JSON (string-based)
 */
export interface AnnotationPatternsJson {
  readOnly: string[];
  destructive: string[];
  write: string[];
  ambiguous: string[];
}

/**
 * Compiled annotation patterns (RegExp-based)
 */
export interface CompiledAnnotationPatterns {
  readOnly: RegExp[];
  destructive: RegExp[];
  write: RegExp[];
  ambiguous: RegExp[];
}

/**
 * Categories of sanitization approaches (matches config/sanitizationPatterns.ts)
 */
export type SanitizationCategory =
  | "xss" // XSS prevention (DOMPurify, xss, bleach)
  | "html" // HTML sanitization (sanitize-html)
  | "sql" // SQL injection prevention (parameterized queries)
  | "input" // General input validation (validator, Zod, Joi)
  | "encoding" // Encoding/escaping (escape-html, he)
  | "framework"; // Framework-level (Express helmet, Django CSRF)

/**
 * Raw library pattern from JSON
 */
export interface LibraryPatternJson {
  name: string;
  patterns: string[];
  category: string;
  confidenceBoost: number;
  languageHint?: string[];
}

/**
 * Compiled library pattern
 */
export interface CompiledLibraryPattern {
  name: string;
  patterns: RegExp[];
  category: SanitizationCategory;
  confidenceBoost: number;
  languageHint?: string[];
}

/**
 * Raw sanitization patterns from JSON
 */
export interface SanitizationPatternsJson {
  libraries: LibraryPatternJson[];
  genericKeywords: string[];
  responseIndicators: string[];
  confidenceBoosts: {
    SPECIFIC_LIBRARY: number;
    GENERIC_KEYWORD: number;
    RESPONSE_EVIDENCE: number;
    MAX_ADJUSTMENT: number;
  };
}

/**
 * Compiled sanitization patterns
 */
export interface CompiledSanitizationPatterns {
  libraries: CompiledLibraryPattern[];
  genericKeywords: RegExp[];
  responseIndicators: RegExp[];
  confidenceBoosts: {
    SPECIFIC_LIBRARY: number;
    GENERIC_KEYWORD: number;
    RESPONSE_EVIDENCE: number;
    MAX_ADJUSTMENT: number;
  };
}

// ============================================================================
// Pattern Compilation
// ============================================================================

/**
 * Convert a string pattern to a RegExp with case-insensitive flag.
 * Handles patterns from JSON which are stored as escaped strings.
 *
 * @param pattern - String pattern (e.g., "\\bDOMPurify\\b")
 * @returns Compiled RegExp
 */
export function stringToRegExp(pattern: string): RegExp {
  return new RegExp(pattern, "i");
}

/**
 * Convert an array of string patterns to RegExp array.
 *
 * @param patterns - Array of string patterns
 * @returns Array of compiled RegExp
 */
export function compilePatterns(patterns: string[]): RegExp[] {
  return patterns.map(stringToRegExp);
}

// ============================================================================
// Annotation Pattern Loading
// ============================================================================

// Cached compiled patterns
let cachedAnnotationPatterns: CompiledAnnotationPatterns | null = null;

/**
 * Load and compile annotation patterns from JSON.
 * Results are cached for performance.
 *
 * @returns Compiled annotation patterns
 */
export function loadAnnotationPatterns(): CompiledAnnotationPatterns {
  if (cachedAnnotationPatterns) {
    return cachedAnnotationPatterns;
  }

  const json = annotationPatternsJson as AnnotationPatternsJson;

  cachedAnnotationPatterns = {
    readOnly: json.readOnly.map(annotationPatternToRegex),
    destructive: json.destructive.map(annotationPatternToRegex),
    write: json.write.map(annotationPatternToRegex),
    ambiguous: json.ambiguous.map(annotationPatternToRegex),
  };

  return cachedAnnotationPatterns;
}

/**
 * Convert an annotation pattern string to RegExp.
 * Handles patterns like "get_" -> /^get[_-]?/i
 *
 * @param pattern - Pattern string (e.g., "get_", "delete-")
 * @returns Compiled RegExp
 */
function annotationPatternToRegex(pattern: string): RegExp {
  // Remove trailing underscore/hyphen for the base pattern
  const base = pattern.replace(/[_-]$/, "");
  // Create regex that matches pattern at start of string, with optional underscore/hyphen
  return new RegExp(`^${escapeRegex(base)}[_-]?`, "i");
}

/**
 * Escape special regex characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Get raw annotation patterns (string-based) for config files or debugging.
 */
export function getRawAnnotationPatterns(): AnnotationPatternsJson {
  return annotationPatternsJson as AnnotationPatternsJson;
}

// ============================================================================
// Sanitization Pattern Loading
// ============================================================================

// Cached compiled patterns
let cachedSanitizationPatterns: CompiledSanitizationPatterns | null = null;

/**
 * Load and compile sanitization patterns from JSON.
 * Results are cached for performance.
 *
 * @returns Compiled sanitization patterns
 */
export function loadSanitizationPatterns(): CompiledSanitizationPatterns {
  if (cachedSanitizationPatterns) {
    return cachedSanitizationPatterns;
  }

  const json = sanitizationPatternsJson as SanitizationPatternsJson;

  cachedSanitizationPatterns = {
    libraries: json.libraries.map((lib) => ({
      name: lib.name,
      patterns: compilePatterns(lib.patterns),
      category: lib.category as SanitizationCategory,
      confidenceBoost: lib.confidenceBoost,
      languageHint: lib.languageHint,
    })),
    genericKeywords: compilePatterns(json.genericKeywords),
    responseIndicators: compilePatterns(json.responseIndicators),
    confidenceBoosts: json.confidenceBoosts,
  };

  return cachedSanitizationPatterns;
}

/**
 * Get raw sanitization patterns (string-based) for config files or debugging.
 */
export function getRawSanitizationPatterns(): SanitizationPatternsJson {
  return sanitizationPatternsJson as SanitizationPatternsJson;
}

// ============================================================================
// Cache Management
// ============================================================================

/**
 * Clear all cached patterns (useful for testing or hot-reload scenarios).
 */
export function clearPatternCaches(): void {
  cachedAnnotationPatterns = null;
  cachedSanitizationPatterns = null;
}

/**
 * Check if patterns are loaded and cached.
 */
export function arePatternsLoaded(): {
  annotation: boolean;
  sanitization: boolean;
} {
  return {
    annotation: cachedAnnotationPatterns !== null,
    sanitization: cachedSanitizationPatterns !== null,
  };
}
