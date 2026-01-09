/**
 * Math Analyzer
 * Detects computed math expression results (Calculator Injection)
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Handles: math computation detection, coincidental numeric detection
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { ToolClassifier, ToolCategory } from "../../ToolClassifier";
import {
  SIMPLE_MATH_PATTERN,
  COMPUTATIONAL_INDICATORS,
  STRUCTURED_DATA_FIELD_NAMES,
  READ_ONLY_TOOL_NAME_PATTERN,
  isHttpError,
  matchesAny,
} from "./SecurityPatternLibrary";

/**
 * Result of computed math analysis with confidence level (Issue #58)
 */
export interface MathResultAnalysis {
  isComputed: boolean;
  confidence: "high" | "medium" | "low";
  reason?: string;
}

/**
 * Analyzes tool responses for math computation evidence (Calculator Injection)
 */
export class MathAnalyzer {
  /**
   * Enhanced computed math result analysis with tool context (Issue #58)
   *
   * Returns a confidence level indicating how likely this is a real Calculator Injection:
   * - high: Strong evidence of computation (should flag as vulnerable)
   * - medium: Ambiguous (excluded from vulnerability count per user decision)
   * - low: Likely coincidental data (excluded from vulnerability count)
   */
  analyzeComputedMathResult(
    payload: string,
    responseText: string,
    tool?: Tool,
  ): MathResultAnalysis {
    // Skip HTTP error responses
    if (isHttpError(responseText)) {
      return {
        isComputed: false,
        confidence: "high",
        reason: "HTTP error response",
      };
    }

    // Parse math expression
    const match = payload.match(SIMPLE_MATH_PATTERN);
    if (!match) {
      return {
        isComputed: false,
        confidence: "high",
        reason: "Not a math expression",
      };
    }

    try {
      const result = this.computeExpression(match);
      if (result === null) {
        return {
          isComputed: false,
          confidence: "high",
          reason: "Invalid operator",
        };
      }

      const resultStr = result.toString();
      const hasComputedResult = responseText.includes(resultStr);
      const normalizedPayload = payload.replace(/\s+/g, "");
      const hasOriginalExpression =
        responseText.includes(payload) ||
        responseText.includes(normalizedPayload);

      // Basic detection: result present without original expression
      const basicDetection = hasComputedResult && !hasOriginalExpression;

      if (!basicDetection) {
        return {
          isComputed: false,
          confidence: "high",
          reason: "No computed result found",
        };
      }

      // Layer 1: Check if numeric appears in structured data context (Issue #58)
      if (this.isCoincidentalNumericInStructuredData(result, responseText)) {
        return {
          isComputed: false,
          confidence: "low",
          reason:
            "Numeric value appears in structured data field (e.g., count, records)",
        };
      }

      // Layer 2: Tool classification heuristics (Issue #58)
      if (tool) {
        const classifier = new ToolClassifier();
        const classification = classifier.classify(tool.name, tool.description);

        // Check for read-only/data fetcher categories
        if (
          classification.categories.includes(ToolCategory.DATA_FETCHER) ||
          classification.categories.includes(ToolCategory.API_WRAPPER) ||
          classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL)
        ) {
          return {
            isComputed: false,
            confidence: "low",
            reason: `Tool classified as ${classification.categories[0]} - unlikely to compute math`,
          };
        }

        // Check for "get_", "list_", "fetch_" patterns in tool name
        if (READ_ONLY_TOOL_NAME_PATTERN.test(tool.name)) {
          return {
            isComputed: false,
            confidence: "low",
            reason: "Tool name indicates read-only operation",
          };
        }
      }

      // Layer 3: Check for computational language in response
      const hasComputationalContext = matchesAny(
        COMPUTATIONAL_INDICATORS,
        responseText,
      );

      if (hasComputationalContext) {
        return {
          isComputed: true,
          confidence: "high",
          reason: "Response contains computational language",
        };
      }

      // Layer 4: Longer responses without computational language are likely data
      if (responseText.length > 50) {
        return {
          isComputed: false,
          confidence: "medium",
          reason:
            "Response lacks computational language, likely coincidental data",
        };
      }

      // Short response with just the number - this is suspicious
      if (responseText.trim() === resultStr) {
        return {
          isComputed: true,
          confidence: "high",
          reason: "Response is exactly the computed result",
        };
      }

      // Default: medium confidence (excluded per user decision)
      return {
        isComputed: false,
        confidence: "medium",
        reason: "Ambiguous - numeric match without computational context",
      };
    } catch {
      return { isComputed: false, confidence: "high", reason: "Parse error" };
    }
  }

  /**
   * Legacy method for backward compatibility
   * @deprecated Use analyzeComputedMathResult instead
   */
  isComputedMathResult(payload: string, responseText: string): boolean {
    const analysis = this.analyzeComputedMathResult(payload, responseText);
    return analysis.isComputed && analysis.confidence === "high";
  }

  /**
   * Check if numeric value appears in structured data context (not as computation result)
   * Distinguishes {"records": 4} from computed "4" (Issue #58)
   *
   * @param result The computed numeric result to check for
   * @param responseText The response text to analyze
   * @returns true if the number appears to be coincidental data, not a computed result
   */
  isCoincidentalNumericInStructuredData(
    result: number,
    responseText: string,
  ): boolean {
    // Try to parse as JSON
    try {
      const parsed = JSON.parse(responseText);
      return this.checkObjectForCoincidentalNumeric(parsed, result);
    } catch {
      // Not JSON - check for structured text patterns
      return this.checkTextForCoincidentalNumeric(result, responseText);
    }
  }

  /**
   * Recursively check JSON object for coincidental numeric values
   */
  private checkObjectForCoincidentalNumeric(
    obj: unknown,
    result: number,
    depth = 0,
  ): boolean {
    if (depth > 5) return false; // Prevent deep recursion
    if (typeof obj !== "object" || obj === null) return false;

    for (const [key, value] of Object.entries(obj)) {
      // Check if numeric value matches result and key is a data field
      if (value === result) {
        const keyLower = key.toLowerCase();
        if (
          STRUCTURED_DATA_FIELD_NAMES.some((pattern) =>
            keyLower.includes(pattern),
          )
        ) {
          return true;
        }
      }
      // Recurse into nested objects
      if (typeof value === "object" && value !== null) {
        if (this.checkObjectForCoincidentalNumeric(value, result, depth + 1)) {
          return true;
        }
      }
      // Check arrays
      if (Array.isArray(value)) {
        for (const item of value) {
          if (
            typeof item === "object" &&
            this.checkObjectForCoincidentalNumeric(item, result, depth + 1)
          ) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Check text for structured patterns containing coincidental numerics
   */
  private checkTextForCoincidentalNumeric(
    result: number,
    responseText: string,
  ): boolean {
    const structuredPatterns = [
      new RegExp(
        `(records|count|total|page|items|results|employees|entries|rows)[:\\s]+${result}\\b`,
        "i",
      ),
      new RegExp(
        `\\b${result}\\s+(records|items|results|entries|employees|rows)\\b`,
        "i",
      ),
      new RegExp(`page\\s+\\d+\\s+of\\s+${result}\\b`, "i"),
      new RegExp(`total[:\\s]+${result}\\b`, "i"),
      new RegExp(`found\\s+${result}\\s+(results|items|entries)`, "i"),
    ];

    return structuredPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Compute math expression from regex match
   * Returns null if invalid operator
   */
  private computeExpression(match: RegExpMatchArray): number | null {
    const num1 = parseInt(match[1], 10);
    const op1 = match[2];
    const num2 = parseInt(match[3], 10);
    const op2 = match[4];
    const num3 = match[5] ? parseInt(match[5], 10) : undefined;

    let result: number;

    switch (op1) {
      case "+":
        result = num1 + num2;
        break;
      case "-":
        result = num1 - num2;
        break;
      case "*":
        result = num1 * num2;
        break;
      case "/":
        result = Math.floor(num1 / num2);
        break;
      default:
        return null;
    }

    if (op2 && num3 !== undefined) {
      switch (op2) {
        case "+":
          result = result + num3;
          break;
        case "-":
          result = result - num3;
          break;
        case "*":
          result = result * num3;
          break;
        case "/":
          result = Math.floor(result / num3);
          break;
        default:
          return null;
      }
    }

    return result;
  }
}
