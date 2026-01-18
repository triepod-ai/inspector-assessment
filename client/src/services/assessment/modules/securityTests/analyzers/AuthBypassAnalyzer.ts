/**
 * Auth Bypass Analyzer (Issue #75)
 * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  AUTH_FAIL_OPEN_PATTERNS,
  AUTH_FAIL_CLOSED_PATTERNS,
} from "../SecurityPatternLibrary";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of auth bypass response analysis (Issue #75)
 * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
 */
export interface AuthBypassResult {
  detected: boolean;
  failureMode: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN";
  evidence?: string;
}

/**
 * Analyzes responses for authentication bypass vulnerabilities
 */
export class AuthBypassAnalyzer {
  private safeDetector: SafeResponseDetector;

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for auth bypass patterns (Issue #75)
   * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
   */
  analyze(response: CompatibilityCallToolResult): AuthBypassResult {
    const responseText = this.safeDetector.extractResponseContent(response);

    // Check for fail-open (vulnerable) patterns first
    for (const { pattern, evidence } of AUTH_FAIL_OPEN_PATTERNS) {
      if (pattern.test(responseText)) {
        return { detected: true, failureMode: "FAIL_OPEN", evidence };
      }
    }

    // Check for fail-closed (safe) patterns
    for (const { pattern, evidence } of AUTH_FAIL_CLOSED_PATTERNS) {
      if (pattern.test(responseText)) {
        return { detected: false, failureMode: "FAIL_CLOSED", evidence };
      }
    }

    return { detected: false, failureMode: "UNKNOWN" };
  }
}
