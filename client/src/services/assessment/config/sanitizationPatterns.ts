/**
 * Sanitization Library Pattern Configuration
 *
 * Detects security libraries and sanitization practices in tool metadata/descriptions.
 * Used by SanitizationDetector to reduce false positives when tools have proper
 * input sanitization in place.
 *
 * @see Issue #56: Improve security analysis granularity
 */

/**
 * Categories of sanitization approaches
 */
export type SanitizationCategory =
  | "xss" // XSS prevention (DOMPurify, xss, bleach)
  | "html" // HTML sanitization (sanitize-html)
  | "sql" // SQL injection prevention (parameterized queries)
  | "input" // General input validation (validator, Zod, Joi)
  | "encoding" // Encoding/escaping (escape-html, he)
  | "framework"; // Framework-level (Express helmet, Django CSRF)

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
 */
export const SANITIZATION_LIBRARY_PATTERNS: SanitizationLibraryPattern[] = [
  // XSS Prevention Libraries
  {
    name: "DOMPurify",
    patterns: [/\bDOMPurify\b/i, /\bdom[-_]?purify\b/i],
    category: "xss",
    confidenceBoost: 25,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "xss",
    patterns: [
      /\bxss\s*\(/i,
      /require\s*\(\s*['"]xss['"]\s*\)/i,
      /import.*from\s+['"]xss['"]/i,
      /xss\s+library/i,
    ],
    category: "xss",
    confidenceBoost: 25,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "bleach",
    patterns: [/\bbleach\b/i, /bleach\.clean/i, /import\s+bleach/i],
    category: "xss",
    confidenceBoost: 25,
    languageHint: ["python"],
  },

  // HTML Sanitization
  {
    name: "sanitize-html",
    patterns: [
      /\bsanitize[-_]?html\b/i,
      /sanitizeHtml\s*\(/i,
      /require\s*\(\s*['"]sanitize-html['"]\s*\)/i,
    ],
    category: "html",
    confidenceBoost: 20,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "escape-html",
    patterns: [
      /\bescape[-_]?html\b/i,
      /escapeHtml\s*\(/i,
      /require\s*\(\s*['"]escape-html['"]\s*\)/i,
    ],
    category: "encoding",
    confidenceBoost: 15,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "he",
    patterns: [
      /\bhe\.encode/i,
      /\bhe\.escape/i,
      /require\s*\(\s*['"]he['"]\s*\)/i,
    ],
    category: "encoding",
    confidenceBoost: 15,
    languageHint: ["javascript", "typescript"],
  },

  // Input Validation Libraries
  {
    name: "validator",
    patterns: [
      /validator\.js/i,
      /\bvalidatorjs\b/i,
      /validator\.(isEmail|escape|sanitize|isURL|isAlphanumeric)/i,
      /require\s*\(\s*['"]validator['"]\s*\)/i,
    ],
    category: "input",
    confidenceBoost: 20,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "Zod",
    patterns: [
      /\bz\.string\s*\(\)/i,
      /\bz\.object\s*\(/i,
      /\bzod\b/i,
      /\.safeParse\s*\(/i,
      /import.*from\s+['"]zod['"]/i,
    ],
    category: "input",
    confidenceBoost: 15,
    languageHint: ["typescript"],
  },
  {
    name: "Joi",
    patterns: [
      /\bJoi\b/i,
      /Joi\.string\s*\(\)/i,
      /Joi\.object\s*\(/i,
      /\.validate\s*\(/i,
      /require\s*\(\s*['"]joi['"]\s*\)/i,
    ],
    category: "input",
    confidenceBoost: 15,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "yup",
    patterns: [
      /\byup\b/i,
      /yup\.string\s*\(\)/i,
      /yup\.object\s*\(/i,
      /import.*from\s+['"]yup['"]/i,
    ],
    category: "input",
    confidenceBoost: 15,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "pydantic",
    patterns: [
      /\bpydantic\b/i,
      /from\s+pydantic\s+import/i,
      /BaseModel/i,
      /Field\s*\(/i,
    ],
    category: "input",
    confidenceBoost: 15,
    languageHint: ["python"],
  },

  // SQL Injection Prevention
  {
    name: "parameterized-queries",
    patterns: [
      /prepared[\s_]?statement/i,
      /parameterized[\s_]?quer/i,
      /\$\d+\s/i, // PostgreSQL style $1, $2
      /:\w+\s/i, // Named parameters :name
      /\?\s/i, // Positional parameters ?
    ],
    category: "sql",
    confidenceBoost: 20,
    languageHint: ["sql"],
  },

  // Framework-level Protection
  {
    name: "helmet",
    patterns: [
      /\bhelmet\b/i,
      /helmet\s*\(\)/i,
      /require\s*\(\s*['"]helmet['"]\s*\)/i,
    ],
    category: "framework",
    confidenceBoost: 10,
    languageHint: ["javascript", "typescript"],
  },
  {
    name: "django-csrf",
    patterns: [/csrf_token/i, /CsrfViewMiddleware/i, /@csrf_protect/i],
    category: "framework",
    confidenceBoost: 10,
    languageHint: ["python"],
  },
];

/**
 * Generic sanitization keyword patterns
 *
 * These are less specific than library patterns and provide lower confidence boost.
 * Used when no specific library is detected but sanitization is mentioned.
 */
export const GENERIC_SANITIZATION_KEYWORDS: RegExp[] = [
  /\bsanitiz(e|ed|es|ing|ation)\b/i,
  /\bescap(e|ed|es|ing)\b/i,
  /\bencod(e|ed|es|ing)\b/i,
  /\bvalidat(e|ed|es|ing|ion)\b/i,
  /\bfilter(ed|s|ing)?\b/i,
  /\bclean(ed|s|ing)?\b/i,
  /\bpurif(y|ied|ies|ying)\b/i,
  /\bnormaliz(e|ed|es|ing)\b/i,
  /\bstrip(ped|s|ping)?\b/i,
  /\btrim(med|s|ming)?\b/i,
];

/**
 * Response-time sanitization indicators
 *
 * Patterns that indicate sanitization was applied to the response.
 * These provide evidence that input was processed safely.
 */
export const RESPONSE_SANITIZATION_INDICATORS: RegExp[] = [
  /\[sanitized\]/i,
  /\[filtered\]/i,
  /\[redacted\]/i,
  /\[removed\]/i,
  /\[cleaned\]/i,
  /\[escaped\]/i,
  /input.*sanitized/i,
  /content.*filtered/i,
  /value.*cleaned/i,
  /data.*validated/i,
];

/**
 * Confidence boost values for different detection types
 */
export const CONFIDENCE_BOOSTS = {
  /** Specific library detected (e.g., DOMPurify) */
  SPECIFIC_LIBRARY: 25,
  /** Generic sanitization keyword detected */
  GENERIC_KEYWORD: 8,
  /** Response-time sanitization evidence */
  RESPONSE_EVIDENCE: 10,
  /** Maximum total adjustment (cap) */
  MAX_ADJUSTMENT: 50,
} as const;
