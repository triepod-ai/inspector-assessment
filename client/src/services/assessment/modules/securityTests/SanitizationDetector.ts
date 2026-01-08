/**
 * Sanitization Detector
 *
 * Detects sanitization libraries and practices from tool metadata/descriptions.
 * Used to reduce false positives when tools have proper input sanitization in place.
 *
 * @see Issue #56: Improve security analysis granularity
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  SANITIZATION_LIBRARY_PATTERNS,
  GENERIC_SANITIZATION_KEYWORDS,
  RESPONSE_SANITIZATION_INDICATORS,
  CONFIDENCE_BOOSTS,
  SanitizationCategory,
  SanitizationLibraryPattern,
} from "../../config/sanitizationPatterns";

/**
 * Result of sanitization detection analysis
 */
export interface SanitizationDetectionResult {
  /** Whether any sanitization was detected */
  detected: boolean;
  /** Specific libraries detected by name */
  libraries: string[];
  /** Categories of sanitization detected */
  categories: SanitizationCategory[];
  /** Generic sanitization keywords found */
  genericPatterns: string[];
  /** Total confidence adjustment (0-50 capped) */
  totalConfidenceAdjustment: number;
  /** Evidence strings for what was detected */
  evidence: string[];
}

/**
 * Result of input reflection analysis
 */
export interface ReflectionAnalysis {
  /** Whether the input was reflected in the response */
  reflected: boolean;
  /** Type of reflection detected */
  reflectionType: "exact" | "partial" | "transformed" | "none";
  /** Specific parts that were matched (for partial reflection) */
  partialMatches: string[];
  /** Confidence reduction based on reflection analysis */
  confidenceReduction: number;
}

/**
 * Detects sanitization patterns in tool descriptions, metadata, and responses.
 * Uses pattern matching to identify known security libraries and generic
 * sanitization practices.
 */
export class SanitizationDetector {
  /**
   * Detect sanitization from tool description and metadata
   *
   * @param tool - MCP Tool object with name, description, and inputSchema
   * @returns Detection result with libraries, categories, and confidence adjustment
   */
  detect(tool: Tool): SanitizationDetectionResult {
    // Gather all text to analyze from the tool
    const textSources = this.extractToolText(tool);
    const fullText = textSources.join(" ");

    return this.analyzeText(fullText);
  }

  /**
   * Detect sanitization from arbitrary text (e.g., prompt descriptions)
   *
   * @param text - Text content to analyze
   * @returns Detection result
   */
  detectFromText(text: string): SanitizationDetectionResult {
    return this.analyzeText(text);
  }

  /**
   * Detect sanitization indicators in tool response content
   *
   * @param responseText - Response text from tool execution
   * @returns Detection result focusing on response-time evidence
   */
  detectInResponse(responseText: string): SanitizationDetectionResult {
    const result = this.createEmptyResult();

    // Check for response-time sanitization indicators
    for (const pattern of RESPONSE_SANITIZATION_INDICATORS) {
      if (pattern.test(responseText)) {
        result.detected = true;
        const match = responseText.match(pattern);
        if (match) {
          result.genericPatterns.push(match[0]);
          result.evidence.push(
            `Response contains sanitization indicator: "${match[0]}"`,
          );
        }
      }
    }

    // Calculate adjustment for response evidence
    if (result.genericPatterns.length > 0) {
      result.totalConfidenceAdjustment = Math.min(
        result.genericPatterns.length * CONFIDENCE_BOOSTS.RESPONSE_EVIDENCE,
        CONFIDENCE_BOOSTS.MAX_ADJUSTMENT,
      );
    }

    return result;
  }

  /**
   * Merge multiple detection results into one
   *
   * @param results - Array of detection results to merge
   * @returns Combined result with deduplicated values
   */
  mergeResults(
    ...results: SanitizationDetectionResult[]
  ): SanitizationDetectionResult {
    const merged = this.createEmptyResult();

    for (const result of results) {
      if (result.detected) {
        merged.detected = true;
      }

      // Deduplicate arrays
      for (const lib of result.libraries) {
        if (!merged.libraries.includes(lib)) {
          merged.libraries.push(lib);
        }
      }

      for (const cat of result.categories) {
        if (!merged.categories.includes(cat)) {
          merged.categories.push(cat);
        }
      }

      for (const pattern of result.genericPatterns) {
        if (!merged.genericPatterns.includes(pattern)) {
          merged.genericPatterns.push(pattern);
        }
      }

      for (const ev of result.evidence) {
        if (!merged.evidence.includes(ev)) {
          merged.evidence.push(ev);
        }
      }
    }

    // Recalculate total adjustment
    merged.totalConfidenceAdjustment = this.calculateTotalAdjustment(merged);

    return merged;
  }

  /**
   * Analyze whether input payload was reflected in the response
   *
   * @param payload - Original payload that was sent
   * @param responseText - Response text to check for reflection
   * @returns Reflection analysis with type and confidence reduction
   */
  detectInputReflection(
    payload: string,
    responseText: string,
  ): ReflectionAnalysis {
    const payloadLower = payload.toLowerCase();
    const responseLower = responseText.toLowerCase();

    // Check for exact match (case insensitive)
    const exactMatch = responseLower.includes(payloadLower);

    if (exactMatch) {
      return {
        reflected: true,
        reflectionType: "exact",
        partialMatches: [payload],
        confidenceReduction: 0, // Exact reflection doesn't reduce confidence
      };
    }

    // Check for partial matches on key payload parts
    const keyParts = this.extractKeyPayloadParts(payload);
    const partialMatches = keyParts.filter((part) =>
      responseLower.includes(part.toLowerCase()),
    );

    if (partialMatches.length > 0) {
      return {
        reflected: true,
        reflectionType: "partial",
        partialMatches,
        confidenceReduction: 10, // Partial reflection has some reduction
      };
    }

    // Check for transformed reflection (encoded/escaped)
    const transformedMatch = this.checkTransformedReflection(
      payload,
      responseText,
    );
    if (transformedMatch) {
      return {
        reflected: true,
        reflectionType: "transformed",
        partialMatches: [],
        confidenceReduction: 15, // Transformed suggests sanitization applied
      };
    }

    // No reflection detected - tool likely blocked/processed input safely
    return {
      reflected: false,
      reflectionType: "none",
      partialMatches: [],
      confidenceReduction: 20, // No reflection = highest confidence reduction
    };
  }

  // ========== Private Helper Methods ==========

  /**
   * Extract all analyzable text from a tool definition
   */
  private extractToolText(tool: Tool): string[] {
    const texts: string[] = [];

    // Tool name (less useful but might contain library names)
    if (tool.name) {
      texts.push(tool.name);
    }

    // Tool description (primary source)
    if (tool.description) {
      texts.push(tool.description);
    }

    // Input schema descriptions
    if (tool.inputSchema) {
      texts.push(...this.extractSchemaText(tool.inputSchema));
    }

    return texts;
  }

  /**
   * Recursively extract text from JSON schema
   */
  private extractSchemaText(schema: unknown): string[] {
    const texts: string[] = [];

    if (!schema || typeof schema !== "object") {
      return texts;
    }

    const obj = schema as Record<string, unknown>;

    // Extract description
    if (typeof obj.description === "string") {
      texts.push(obj.description);
    }

    // Extract title
    if (typeof obj.title === "string") {
      texts.push(obj.title);
    }

    // Recurse into properties
    if (obj.properties && typeof obj.properties === "object") {
      for (const prop of Object.values(
        obj.properties as Record<string, unknown>,
      )) {
        texts.push(...this.extractSchemaText(prop));
      }
    }

    // Recurse into items (for arrays)
    if (obj.items) {
      texts.push(...this.extractSchemaText(obj.items));
    }

    return texts;
  }

  /**
   * Analyze text for sanitization patterns
   */
  private analyzeText(text: string): SanitizationDetectionResult {
    const result = this.createEmptyResult();

    // Check for specific library patterns
    for (const libPattern of SANITIZATION_LIBRARY_PATTERNS) {
      if (this.matchesLibrary(text, libPattern)) {
        result.detected = true;
        result.libraries.push(libPattern.name);
        if (!result.categories.includes(libPattern.category)) {
          result.categories.push(libPattern.category);
        }
        result.evidence.push(`Library detected: ${libPattern.name}`);
      }
    }

    // Check for generic sanitization keywords (only if no specific library found)
    // This prevents double-counting when a library name includes generic terms
    for (const pattern of GENERIC_SANITIZATION_KEYWORDS) {
      if (pattern.test(text)) {
        const match = text.match(pattern);
        if (match && !this.isPartOfLibraryMatch(match[0], result.libraries)) {
          result.detected = true;
          const keyword = match[0].toLowerCase();
          if (!result.genericPatterns.includes(keyword)) {
            result.genericPatterns.push(keyword);
            result.evidence.push(`Sanitization keyword: "${keyword}"`);
          }
        }
      }
    }

    // Calculate total adjustment
    result.totalConfidenceAdjustment = this.calculateTotalAdjustment(result);

    return result;
  }

  /**
   * Check if text matches a library pattern
   */
  private matchesLibrary(
    text: string,
    libPattern: SanitizationLibraryPattern,
  ): boolean {
    return libPattern.patterns.some((pattern) => pattern.test(text));
  }

  /**
   * Check if a generic keyword match is part of an already-detected library name
   */
  private isPartOfLibraryMatch(
    keyword: string,
    detectedLibraries: string[],
  ): boolean {
    const keywordLower = keyword.toLowerCase();
    return detectedLibraries.some((lib) =>
      lib.toLowerCase().includes(keywordLower),
    );
  }

  /**
   * Calculate total confidence adjustment from detection results
   */
  private calculateTotalAdjustment(
    result: SanitizationDetectionResult,
  ): number {
    let adjustment = 0;

    // Add library-specific boosts
    for (const libName of result.libraries) {
      const libPattern = SANITIZATION_LIBRARY_PATTERNS.find(
        (p) => p.name === libName,
      );
      if (libPattern) {
        adjustment += libPattern.confidenceBoost;
      }
    }

    // Add generic keyword boosts
    adjustment +=
      result.genericPatterns.length * CONFIDENCE_BOOSTS.GENERIC_KEYWORD;

    // Cap at maximum
    return Math.min(adjustment, CONFIDENCE_BOOSTS.MAX_ADJUSTMENT);
  }

  /**
   * Extract key parts of a payload for partial matching
   *
   * Extracts significant portions that would indicate reflection:
   * - Command keywords (SELECT, DROP, rm, etc.)
   * - Injection markers (', ", --, etc.)
   * - Common payload strings
   */
  private extractKeyPayloadParts(payload: string): string[] {
    const parts: string[] = [];

    // SQL keywords
    const sqlKeywords = payload.match(
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b/gi,
    );
    if (sqlKeywords) {
      parts.push(...sqlKeywords);
    }

    // Command injection keywords
    const cmdKeywords = payload.match(
      /\b(rm|cat|ls|wget|curl|bash|sh|cmd|powershell)\b/gi,
    );
    if (cmdKeywords) {
      parts.push(...cmdKeywords);
    }

    // Prompt injection markers
    const promptMarkers = payload.match(
      /(ignore|previous|instructions|system|override|admin|root)/gi,
    );
    if (promptMarkers) {
      parts.push(...promptMarkers);
    }

    // Path traversal patterns
    const pathPatterns = payload.match(/\.\.\/|\.\.\\|\/etc\/|\/passwd/gi);
    if (pathPatterns) {
      parts.push(...pathPatterns);
    }

    // Deduplicate
    return [...new Set(parts)];
  }

  /**
   * Check if payload appears in transformed form (encoded/escaped)
   */
  private checkTransformedReflection(
    payload: string,
    responseText: string,
  ): boolean {
    // Check for URL encoding
    const urlEncoded = encodeURIComponent(payload);
    if (responseText.includes(urlEncoded)) {
      return true;
    }

    // Check for HTML entity encoding - basic (only < and >, most common)
    const htmlBasicEscaped = payload
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    if (
      responseText.includes(htmlBasicEscaped) &&
      htmlBasicEscaped !== payload
    ) {
      return true;
    }

    // Check for HTML entity encoding - full (all special characters)
    const htmlFullEscaped = payload
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
    if (responseText.includes(htmlFullEscaped) && htmlFullEscaped !== payload) {
      return true;
    }

    // Check for backslash escaping
    const backslashEscaped = payload.replace(/['"`]/g, "\\$&");
    if (
      responseText.includes(backslashEscaped) &&
      backslashEscaped !== payload
    ) {
      return true;
    }

    return false;
  }

  /**
   * Create an empty detection result
   */
  private createEmptyResult(): SanitizationDetectionResult {
    return {
      detected: false,
      libraries: [],
      categories: [],
      genericPatterns: [],
      totalConfidenceAdjustment: 0,
      evidence: [],
    };
  }
}
