/**
 * Resource Content Analyzer Module
 *
 * Provides content analysis functions for detecting sensitive data patterns,
 * prompt injection, and MIME type validation in resource content.
 *
 * @module assessment/resources/contentAnalyzer
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import {
  SENSITIVE_CONTENT_PATTERNS,
  SENSITIVE_PATTERN_DEFINITIONS,
  PROMPT_INJECTION_PATTERNS,
  MIME_MAGIC_BYTES,
} from "./ResourcePatterns";

/**
 * Result of sensitive pattern detection
 */
export interface SensitivePatternResult {
  pattern: string;
  severity: "critical" | "high" | "medium";
  detected: boolean;
}

/**
 * Result of MIME type validation
 */
export interface MimeValidationResult {
  valid: boolean;
  expectedMimeType?: string;
  mismatch: boolean;
}

/**
 * Detect sensitive patterns with severity for enrichment (Issue #9)
 */
export function detectSensitivePatterns(
  content: string,
): SensitivePatternResult[] {
  return SENSITIVE_PATTERN_DEFINITIONS.map((def) => ({
    pattern: def.name,
    severity: def.severity,
    detected: def.pattern.test(content),
  }));
}

/**
 * Check if content contains any sensitive data patterns
 */
export function containsSensitiveContent(content: string): boolean {
  return SENSITIVE_CONTENT_PATTERNS.some((pattern) => pattern.test(content));
}

/**
 * Detect prompt injection patterns in resource content.
 * Returns array of matched pattern descriptions.
 */
export function detectPromptInjection(content: string): string[] {
  const matches: string[] = [];

  for (const { pattern, description } of PROMPT_INJECTION_PATTERNS) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(content)) {
      matches.push(description);
    }
  }

  return matches;
}

/**
 * Issue #127, Challenge #24: Validate MIME type matches actual content
 * Detects content-type confusion (CWE-436)
 */
export function validateMimeType(
  content: string | Uint8Array,
  declaredMimeType: string | undefined,
): MimeValidationResult {
  if (!declaredMimeType) {
    return { valid: true, mismatch: false };
  }

  const bytes =
    typeof content === "string"
      ? stringToBytes(content)
      : new Uint8Array(content);

  for (const [mimeType, info] of Object.entries(MIME_MAGIC_BYTES)) {
    if (startsWithBytes(bytes, info.bytes)) {
      const mismatch =
        declaredMimeType.toLowerCase() !== mimeType.toLowerCase();
      return {
        valid: !mismatch,
        expectedMimeType: mimeType,
        mismatch,
      };
    }
  }

  // No magic bytes matched - could be text or unknown binary
  return { valid: true, mismatch: false };
}

/**
 * Issue #127: Format bytes as human-readable string
 */
export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${bytes}B`;
}

/**
 * Issue #127: Convert string to bytes for magic byte comparison
 */
export function stringToBytes(str: string): Uint8Array {
  // Use raw char codes, not UTF-8 encoding, for magic byte detection
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i) & 0xff;
  }
  return bytes;
}

/**
 * Issue #127: Check if content starts with expected magic bytes
 */
export function startsWithBytes(
  content: Uint8Array,
  pattern: number[],
): boolean {
  if (content.length < pattern.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (content[i] !== pattern[i]) return false;
  }
  return true;
}
