/**
 * Invalid Values Response Analyzer
 *
 * Analyzes responses to invalid value inputs for contextual scoring.
 * Issue #99: Contextual empty string validation scoring.
 * Issue #173: Bonus points for suggestions and graceful degradation.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/errorHandling/InvalidValuesAnalyzer
 * @see GitHub Issue #99, #173, #188
 */

import type {
  ErrorTestDetail,
  InvalidValuesAnalysis,
  SuggestionDetectionResult,
  Logger,
  AssessmentConfiguration,
} from "../types";
import { ExecutionArtifactDetector } from "../../securityTests/ExecutionArtifactDetector";
import { SafeResponseDetector } from "../../securityTests/SafeResponseDetector";

/**
 * Analyzes invalid values responses for contextual scoring decisions.
 */
export class InvalidValuesAnalyzer {
  private executionDetector: ExecutionArtifactDetector;
  private safeResponseDetector: SafeResponseDetector;

  constructor(_config: AssessmentConfiguration, _logger: Logger) {
    this.executionDetector = new ExecutionArtifactDetector();
    this.safeResponseDetector = new SafeResponseDetector();
  }

  /**
   * Analyze invalid_values response to determine scoring impact.
   *
   * Classifications:
   * - safe_rejection: Tool rejected with error (no penalty)
   * - safe_reflection: Tool stored/echoed without executing (no penalty)
   * - defensive_programming: Tool handled gracefully (no penalty)
   * - graceful_degradation: Optional param handled with neutral response (no penalty + bonus)
   * - execution_detected: Tool executed input (penalty)
   * - unknown: Cannot determine (partial penalty)
   */
  analyze(test: ErrorTestDetail): InvalidValuesAnalysis {
    const responseText = this.extractResponseTextSafe(
      test.actualResponse.rawResponse,
    );

    // Case 1: Tool rejected with error - best case (no penalty)
    if (test.actualResponse.isError) {
      // Issue #173: Check for suggestions bonus
      const suggestionBonus = test.hasSuggestions ? 10 : 0;
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_rejection",
        reason: "Tool properly rejected invalid input",
        bonusPoints: suggestionBonus,
      };
    }

    // Issue #173 Case 2: Graceful degradation for OPTIONAL parameters
    if (
      test.parameterIsRequired === false &&
      this.isNeutralGracefulResponse(responseText)
    ) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "graceful_degradation",
        reason:
          "Tool handled optional empty parameter gracefully (valid behavior)",
        bonusPoints: 15, // Graceful degradation bonus
      };
    }

    // Case 3: Defensive programming patterns (no penalty)
    // Check BEFORE execution detection because patterns like "query returned 0"
    // might match execution indicators but are actually safe
    if (this.isDefensiveProgrammingResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "defensive_programming",
        reason: "Tool handled empty input defensively",
        bonusPoints: 0,
      };
    }

    // Case 4: Safe reflection patterns (no penalty)
    if (this.safeResponseDetector.isReflectionResponse(responseText)) {
      return {
        shouldPenalize: false,
        penaltyAmount: 0,
        classification: "safe_reflection",
        reason: "Tool safely reflected input without execution",
        bonusPoints: 0,
      };
    }

    // Case 5: Check for execution evidence - VULNERABLE (full penalty)
    if (
      this.executionDetector.hasExecutionEvidence(responseText) ||
      this.executionDetector.detectExecutionArtifacts(responseText)
    ) {
      return {
        shouldPenalize: true,
        penaltyAmount: 100,
        classification: "execution_detected",
        reason: "Tool executed input without validation",
        bonusPoints: 0,
      };
    }

    // Case 6: Unknown - partial penalty for manual review
    return {
      shouldPenalize: true,
      penaltyAmount: 25,
      classification: "unknown",
      reason: "Unable to determine safety - manual review recommended",
      bonusPoints: 0,
    };
  }

  /**
   * Safely extract response text from various response formats.
   */
  extractResponseTextSafe(rawResponse: unknown): string {
    if (typeof rawResponse === "string") return rawResponse;
    if (rawResponse && typeof rawResponse === "object") {
      const resp = rawResponse as Record<string, unknown>;
      if (resp.content && Array.isArray(resp.content)) {
        return (resp.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" ? c.text : ""))
          .join(" ");
      }
      return JSON.stringify(rawResponse);
    }
    return String(rawResponse || "");
  }

  /**
   * Check for defensive programming patterns - tool accepted but caused no harm.
   * Examples: "Deleted 0 keys", "No results found", "Query returned 0"
   */
  isDefensiveProgrammingResponse(responseText: string): boolean {
    // Patterns for safe "no-op" responses where tool handled empty input gracefully
    // Use word boundaries (\b) to avoid matching numbers like "10" or "15"
    const patterns = [
      /deleted\s+0\s+(keys?|records?|rows?|items?)/i,
      /no\s+(results?|matches?|items?)\s+found/i,
      /\b0\s+items?\s+(deleted|updated|processed)/i, // \b prevents matching "10 items"
      /nothing\s+to\s+(delete|update|process)/i,
      /empty\s+(result|response|query)/i,
      /no\s+action\s+taken/i,
      /query\s+returned\s+0\b/i, // \b prevents matching "query returned 05" etc.
    ];
    return patterns.some((p) => p.test(responseText));
  }

  /**
   * Issue #173: Detect helpful suggestion patterns in error responses.
   * Patterns like: "Did you mean: Button, Checkbox?"
   * Returns extracted suggestions for bonus scoring.
   */
  detectSuggestionPatterns(responseText: string): SuggestionDetectionResult {
    // Issue #173: ReDoS protection - limit input length before regex matching
    const truncatedText = responseText.slice(0, 2000);

    const suggestionPatterns = [
      /did\s+you\s+mean[:\s]+([^?.]+)/i,
      /perhaps\s+you\s+meant[:\s]+([^?.]+)/i,
      /similar\s+to[:\s]+([^?.]+)/i,
      /suggestions?[:\s]+([^?.]+)/i,
      /valid\s+(options?|values?)[:\s]+([^?.]+)/i,
      /available[:\s]+([^?.]+)/i,
      /\btry[:\s]+([^?.]+)/i,
      /expected\s+one\s+of[:\s]+([^?.]+)/i,
    ];

    for (const pattern of suggestionPatterns) {
      const match = truncatedText.match(pattern);
      if (match) {
        // Get the captured group (last non-undefined group)
        const suggestionText = match[match.length - 1] || match[1] || "";
        const suggestions = suggestionText
          .split(/[,;]/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0 && s.length < 50);

        if (suggestions.length > 0) {
          return { hasSuggestions: true, suggestions };
        }
      }
    }

    return { hasSuggestions: false, suggestions: [] };
  }

  /**
   * Issue #173: Check for neutral/graceful responses on optional parameters.
   * These indicate the tool handled empty/missing optional input appropriately.
   */
  isNeutralGracefulResponse(responseText: string): boolean {
    // Issue #173: ReDoS protection - limit input length before regex matching
    const truncatedText = responseText.slice(0, 2000);

    const gracefulPatterns = [
      /^\s*\[\s*\]\s*$/, // Empty JSON array (standalone)
      /^\s*\{\s*\}\s*$/, // Empty JSON object (standalone)
      /^\s*$/, // Empty/whitespace only response
      /no\s+results?\s*(found)?/i, // "No results" / "No results found"
      /^results?:\s*\[\s*\]/i, // "results: []"
      /returned\s+0\s+/i, // "returned 0 items"
      /found\s+0\s+/i, // "found 0 matches"
      /empty\s+list/i, // "empty list"
      /no\s+matching/i, // "no matching items"
      /default\s+value/i, // "using default value"
      /^null$/i, // Explicit null
      /no\s+data/i, // "no data"
      /"results"\s*:\s*\[\s*\]/, // JSON with empty results array
      /"items"\s*:\s*\[\s*\]/, // JSON with empty items array
      /"data"\s*:\s*\[\s*\]/, // JSON with empty data array
    ];

    return gracefulPatterns.some((pattern) => pattern.test(truncatedText));
  }
}
