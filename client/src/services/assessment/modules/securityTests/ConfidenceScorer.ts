/**
 * Confidence Scorer
 * Calculates confidence levels for vulnerability detections
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Handles: confidence calculation, structured data tool detection, validation pattern checks
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { SecurityPayload } from "@/lib/securityPatterns";
import type { SanitizationDetectionResult } from "./SanitizationDetector";

/**
 * Result of confidence calculation
 */
export interface ConfidenceResult {
  confidence: "high" | "medium" | "low";
  requiresManualReview: boolean;
  manualReviewReason?: string;
  reviewGuidance?: string;
}

/**
 * Patterns for detecting structured data tools
 */
const STRUCTURED_DATA_TOOL_PATTERNS = [
  /search/i,
  /find/i,
  /lookup/i,
  /query/i,
  /retrieve/i,
  /fetch/i,
  /get/i,
  /list/i,
  /resolve/i,
  /discover/i,
  /browse/i,
];

/**
 * Ambiguous validation patterns that may cause false positives
 */
const VALIDATION_AMBIGUOUS_PATTERNS = [
  "type.*error",
  "invalid.*type",
  "error",
  "invalid",
  "failed",
  "negative.*not.*allowed",
  "must.*be.*positive",
  "invalid.*value",
  "overflow",
  "out.*of.*range",
];

/**
 * Calculates confidence levels for security vulnerability detections
 */
export class ConfidenceScorer {
  /**
   * Calculate confidence level for a vulnerability detection
   *
   * Factors considered:
   * - Sanitization detection (Issue #56)
   * - Structured data tool context
   * - Evidence quality
   * - Response characteristics
   *
   * @param tool - The tool being tested
   * @param isVulnerable - Whether the tool was flagged as vulnerable
   * @param evidence - Evidence string from vulnerability detection
   * @param responseText - The response text from the tool
   * @param payload - The security payload used for testing
   * @param sanitizationResult - Optional sanitization detection result (Issue #56)
   * @returns Confidence result with manual review requirements
   */
  calculateConfidence(
    tool: Tool,
    isVulnerable: boolean,
    evidence: string,
    responseText: string,
    payload: SecurityPayload,
    sanitizationResult?: SanitizationDetectionResult,
  ): ConfidenceResult {
    // Issue #146: Extract execution context from evidence if present
    // This handles context classification from SecurityResponseAnalyzer
    const contextMatch = evidence.match(
      /\[Context: (CONFIRMED|LIKELY_FALSE_POSITIVE|SUSPECTED)/,
    );
    if (contextMatch) {
      const context = contextMatch[1];

      // LIKELY_FALSE_POSITIVE: Payload reflected in error message, not executed
      // Mark as low confidence requiring manual review
      if (context === "LIKELY_FALSE_POSITIVE") {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Payload reflected in error message, operation failed",
          reviewGuidance:
            "The server rejected the operation but echoed the payload in the error. " +
            "Verify if the tool actually processed the payload or just reflected it in the error message. " +
            "Check the HTTP status code and error type to confirm the operation was rejected.",
        };
      }

      // CONFIRMED: Operation succeeded, payload was executed
      // High confidence vulnerability
      if (context === "CONFIRMED") {
        return {
          confidence: "high",
          requiresManualReview: false,
        };
      }

      // SUSPECTED: Ambiguous case - continue with normal scoring but add review flag
      // Will be handled by downstream logic with medium confidence
    }

    // Issue #56: If sanitization is detected, reduce confidence for vulnerabilities
    // This helps reduce false positives on well-protected servers
    if (isVulnerable && sanitizationResult?.detected) {
      const adjustment = sanitizationResult.totalConfidenceAdjustment;

      // Strong sanitization evidence (adjustment >= 30) - downgrade to low confidence
      // This indicates the tool has specific security libraries in place
      if (adjustment >= 30) {
        const libraries = sanitizationResult.libraries.join(", ") || "general";
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            `Sanitization detected (${libraries}). ` +
            `Pattern match may be false positive due to security measures in place.`,
          reviewGuidance:
            `Tool uses sanitization libraries. Verify if the detected vulnerability ` +
            `actually bypasses the sanitization layer. Check: 1) Does the payload execute ` +
            `after sanitization? 2) Is the sanitization comprehensive for this attack type? ` +
            `3) Evidence: ${sanitizationResult.evidence.join("; ")}`,
        };
      }

      // Moderate sanitization evidence (adjustment >= 15) - downgrade high to medium
      if (adjustment >= 15) {
        const patterns =
          sanitizationResult.libraries.length > 0
            ? sanitizationResult.libraries.join(", ")
            : sanitizationResult.genericPatterns.join(", ");
        return {
          confidence: "medium",
          requiresManualReview: true,
          manualReviewReason: `Sanitization patterns detected (${patterns}). Verify actual vulnerability.`,
          reviewGuidance:
            `Tool mentions sanitization in description or shows sanitization in response. ` +
            `Verify if the detected pattern represents actual code execution or if it's ` +
            `safely handled. Evidence: ${sanitizationResult.evidence.join("; ")}`,
        };
      }
    }

    const toolDescription = (tool.description || "").toLowerCase();
    const toolName = tool.name.toLowerCase();
    const responseLower = responseText.toLowerCase();
    const payloadLower = payload.payload.toLowerCase();

    // HIGH CONFIDENCE: Clear cases
    if (
      !isVulnerable &&
      (evidence.includes("safely reflected") ||
        evidence.includes("API wrapper") ||
        evidence.includes("safe: true"))
    ) {
      return {
        confidence: "high",
        requiresManualReview: false,
      };
    }

    if (
      isVulnerable &&
      evidence.includes("executed") &&
      !this.isStructuredDataTool(toolName, toolDescription)
    ) {
      return {
        confidence: "high",
        requiresManualReview: false,
      };
    }

    // LOW CONFIDENCE: Ambiguous pattern matches in structured data
    if (isVulnerable) {
      const isDataTool = this.isStructuredDataTool(toolName, toolDescription);

      const hasStructuredData =
        /title:|name:|description:|trust score:|id:|snippets:/i.test(
          responseText,
        ) ||
        /^\s*-\s+/m.test(responseText) ||
        /"[^"]+"\s*:\s*"[^"]+"/g.test(responseText);

      const patternInInput = payload.evidence?.test(payloadLower);
      const echosInput = responseLower.includes(payloadLower);

      if (isDataTool && (hasStructuredData || echosInput) && patternInInput) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Pattern matched in structured data response. Tool may be legitimately " +
            "returning data containing search terms rather than executing malicious code.",
          reviewGuidance:
            "Verify: 1) Does the tool actually execute/compute the input? " +
            "2) Or does it just return pre-existing data that happens to contain the pattern? " +
            `3) Check if '${payload.evidence}' appears in legitimate tool output vs. execution results.`,
        };
      }

      if (
        payload.evidence &&
        /\b\d\b/.test(payload.evidence.toString()) &&
        /\b(score|count|trust|rating|id|version)\b/i.test(responseText)
      ) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Numeric pattern found in response with numeric metadata (scores, counts, etc.). " +
            "May be coincidental data rather than arithmetic execution.",
          reviewGuidance:
            "Verify: 1) Did the tool actually compute an arithmetic result? " +
            "2) Or does the number appear in metadata like trust scores, version numbers, or counts? " +
            "3) Compare pattern location in response with tool's expected output format.",
        };
      }

      if (
        /admin|role|privilege|elevated/i.test(payload.payload) &&
        /\b(library|search|documentation|api|wrapper)\b/i.test(toolDescription)
      ) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Admin-related keywords found in search/retrieval tool results. " +
            "Tool may be returning data about admin-related libraries/APIs rather than elevating privileges.",
          reviewGuidance:
            "Verify: 1) Did the tool actually change behavior or assume admin role? " +
            "2) Or did it return search results for admin-related content? " +
            "3) Test if tool behavior actually changed after this request.",
        };
      }
    }

    // MEDIUM CONFIDENCE: Execution evidence but some ambiguity
    if (isVulnerable && evidence.includes("executed")) {
      return {
        confidence: "medium",
        requiresManualReview: true,
        manualReviewReason:
          "Execution indicators found but context suggests possible ambiguity.",
        reviewGuidance:
          "Verify: 1) Review the full response to confirm actual code execution. " +
          "2) Check if tool's intended function involves execution. " +
          "3) Test with variations to confirm consistency.",
      };
    }

    // Default: HIGH confidence for clear safe cases
    return {
      confidence: "high",
      requiresManualReview: false,
    };
  }

  /**
   * Check if tool is a structured data tool (search, lookup, retrieval)
   *
   * These tools are more likely to return data containing patterns
   * that look like vulnerabilities but are actually just data.
   */
  isStructuredDataTool(toolName: string, toolDescription: string): boolean {
    const combined = `${toolName} ${toolDescription}`;
    return STRUCTURED_DATA_TOOL_PATTERNS.some((pattern) =>
      pattern.test(combined),
    );
  }

  /**
   * Check if evidence pattern is ambiguous (validation-like)
   *
   * Some patterns match both security issues AND normal validation errors.
   * These require more careful analysis.
   */
  isValidationPattern(evidencePattern: RegExp): boolean {
    const patternStr = evidencePattern.toString().toLowerCase();

    return VALIDATION_AMBIGUOUS_PATTERNS.some((ambiguous) =>
      patternStr.includes(ambiguous),
    );
  }
}
