/**
 * Pattern Configuration Module
 *
 * Centralized pattern loading and compilation for assessment modules.
 * Patterns are stored in JSON files and compiled to RegExp at runtime.
 *
 * @module assessment/patterns
 * @since v1.43.0 (Issue #200 - V2 Refactoring)
 */

// Pattern loader utilities
export {
  loadAnnotationPatterns,
  loadSanitizationPatterns,
  getRawAnnotationPatterns,
  getRawSanitizationPatterns,
  stringToRegExp,
  compilePatterns,
  clearPatternCaches,
  arePatternsLoaded,
} from "./patternLoader";

// Types
export type {
  AnnotationPatternsJson,
  CompiledAnnotationPatterns,
  LibraryPatternJson,
  CompiledLibraryPattern,
  SanitizationPatternsJson,
  CompiledSanitizationPatterns,
  SanitizationCategory,
} from "./patternLoader";
