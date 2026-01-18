/**
 * Output Injection Analyzer (Issue #110, Challenge #8, Issue #191)
 * Detects indirect prompt injection via unsanitized tool output
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 * Pattern consolidation from SecurityPatternLibrary.ts (Issue #191)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SafeResponseDetector } from "../SafeResponseDetector";
import { LLM_INJECTION_MARKERS_WITH_METADATA } from "../SecurityPatternLibrary";

/**
 * Result of output injection response analysis (Issue #110, Challenge #8)
 * Detects indirect prompt injection via unsanitized tool output
 */
export interface OutputInjectionResult {
  detected: boolean;
  injectionType:
    | "LLM_INJECTION_MARKERS"
    | "RAW_CONTENT_INCLUDED"
    | "SANITIZED"
    | "UNKNOWN";
  markers?: string[];
  evidence?: string;
}

/**
 * Analyzes responses for output injection vulnerabilities
 *
 * This analyzer detects:
 * - VULNERABLE: LLM injection markers (<IMPORTANT>, [INST], etc.) in output
 * - VULNERABLE: Tool self-reports raw_content_included: true
 * - SAFE: Tool reports content_sanitized: true or uses hash references
 */
export class OutputInjectionAnalyzer {
  private safeDetector: SafeResponseDetector;

  /**
   * LLM injection marker patterns (Issue #191)
   * Imported from SecurityPatternLibrary - single source of truth
   * Expanded from 8 to 21 patterns for comprehensive detection
   */
  private static readonly MARKER_PATTERNS = LLM_INJECTION_MARKERS_WITH_METADATA;

  /**
   * Raw content vulnerability patterns
   */
  private static readonly RAW_CONTENT_PATTERNS = [
    {
      pattern: /"raw_content_included"\s*:\s*true/i,
      evidence: "raw_content_included: true (unsanitized user content)",
    },
    {
      pattern: /returns\s+unsanitized\s+user\s+content/i,
      evidence: "Tool reports returning unsanitized user content",
    },
    {
      pattern: /enables\s+indirect\s+prompt\s+injection/i,
      evidence: "Tool reports enabling indirect prompt injection",
    },
    {
      pattern: /"injection_risk_level"\s*:\s*"(HIGH|CRITICAL)"/i,
      evidence: "Tool reports HIGH/CRITICAL injection risk level",
    },
  ];

  /**
   * Safe patterns (sanitized output)
   */
  private static readonly SAFE_PATTERNS = [
    {
      pattern: /"content_sanitized"\s*:\s*true/i,
      evidence: "content_sanitized: true (secure)",
    },
    {
      pattern: /"uses_hash_reference"\s*:\s*true/i,
      evidence: "uses_hash_reference: true (secure)",
    },
    {
      pattern: /"raw_content_included"\s*:\s*false/i,
      evidence: "raw_content_included: false (secure)",
    },
  ];

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for output injection vulnerabilities (Issue #110, Challenge #8)
   *
   * @param response The tool response to analyze
   * @returns Analysis result with output injection detection status
   */
  analyze(response: CompatibilityCallToolResult): OutputInjectionResult {
    const responseText = this.safeDetector.extractResponseContent(response);

    // Check for LLM injection markers in response
    const llmMarkers: string[] = [];
    for (const { pattern, name } of OutputInjectionAnalyzer.MARKER_PATTERNS) {
      if (pattern.test(responseText)) {
        llmMarkers.push(name);
      }
    }

    if (llmMarkers.length > 0) {
      return {
        detected: true,
        injectionType: "LLM_INJECTION_MARKERS",
        markers: llmMarkers,
        evidence: `LLM injection markers detected: ${llmMarkers.join(", ")}`,
      };
    }

    // Check for raw content vulnerability metadata
    for (const {
      pattern,
      evidence,
    } of OutputInjectionAnalyzer.RAW_CONTENT_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: true,
          injectionType: "RAW_CONTENT_INCLUDED",
          evidence,
        };
      }
    }

    // Check for safe patterns (sanitized output)
    for (const { pattern, evidence } of OutputInjectionAnalyzer.SAFE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: false,
          injectionType: "SANITIZED",
          evidence,
        };
      }
    }

    return { detected: false, injectionType: "UNKNOWN" };
  }
}
