/**
 * State-Based Auth Bypass Analyzer (Issue #92, Challenge #7)
 * Detects privilege escalation via shared mutable state between tools
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  STATE_AUTH_VULNERABLE_PATTERNS,
  STATE_AUTH_SAFE_PATTERNS,
} from "../SecurityPatternLibrary";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of cross-tool state-based auth bypass analysis (Issue #92, Challenge #7)
 * Detects privilege escalation via shared mutable state between tools
 */
export interface StateBasedAuthResult {
  vulnerable: boolean;
  safe: boolean;
  stateDependency: "SHARED_STATE" | "INDEPENDENT" | "UNKNOWN";
  evidence: string;
}

/**
 * Analyzes responses for cross-tool state-based authorization bypass
 *
 * Vulnerable pattern: Tool checks shared state (e.g., config_state["admin_mode"])
 * that can be modified by another tool (e.g., config_modifier)
 *
 * Safe pattern: Tool uses independent per-request authorization,
 * indicated by shared_state_checked: false or independent_auth_required: true
 */
export class StateBasedAuthAnalyzer {
  private safeDetector: SafeResponseDetector;

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for cross-tool state-based authorization bypass (Issue #92)
   * Detects Challenge #7: Privilege escalation via shared mutable state
   */
  analyze(response: CompatibilityCallToolResult): StateBasedAuthResult {
    const responseText = this.safeDetector.extractResponseContent(response);

    // Check vulnerable patterns first (SHARED_STATE)
    for (const { pattern, evidence } of STATE_AUTH_VULNERABLE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          safe: false,
          stateDependency: "SHARED_STATE",
          evidence: `Cross-tool state dependency detected: ${evidence}`,
        };
      }
    }

    // Check safe patterns (INDEPENDENT)
    for (const { pattern, evidence } of STATE_AUTH_SAFE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: false,
          safe: true,
          stateDependency: "INDEPENDENT",
          evidence: `Independent authorization confirmed: ${evidence}`,
        };
      }
    }

    return {
      vulnerable: false,
      safe: false,
      stateDependency: "UNKNOWN",
      evidence: "",
    };
  }
}
