/**
 * Blacklist Bypass Analyzer (Issue #110, Challenge #11)
 * Detects incomplete blacklist security controls being bypassed
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of blacklist bypass response analysis (Issue #110, Challenge #11)
 * Detects incomplete blacklist security controls being bypassed
 */
export interface BlacklistBypassResult {
  detected: boolean;
  bypassType: "BLACKLIST_BYPASS" | "ALLOWLIST_BLOCKED" | "UNKNOWN";
  bypassMethod?: string;
  evidence?: string;
}

/**
 * Analyzes responses for blacklist bypass vulnerabilities
 *
 * This analyzer extracts JSON metadata from tool responses to detect:
 * - VULNERABLE: bypass_used: true, blacklist_check: "passed"
 * - SAFE: execution_blocked: true, allowlist_used: true
 */
export class BlacklistBypassAnalyzer {
  private safeDetector: SafeResponseDetector;

  /**
   * Vulnerable patterns - blacklist bypassed (Challenge #11)
   */
  private static readonly VULNERABLE_PATTERNS = [
    {
      pattern: /"bypass_used"\s*:\s*true/i,
      evidence: "bypass_used: true (blacklist bypassed)",
    },
    {
      pattern: /"blacklist_check"\s*:\s*"passed"/i,
      evidence: "blacklist_check: passed (command not blocked)",
    },
    {
      // Combined pattern: vulnerable with bypass context
      pattern:
        /"vulnerable"\s*:\s*true[^}]*"bypass_used"|"bypass_used"[^}]*"vulnerable"\s*:\s*true/i,
      evidence: "vulnerable flag with bypass context",
    },
    {
      pattern: /"bypass_method"\s*:\s*"[^"]+"/i,
      evidence: "bypass_method specified (blacklist circumvented)",
    },
    {
      pattern: /incomplete\s+blacklist\s+allowed/i,
      evidence: "evidence indicates incomplete blacklist",
    },
  ];

  /**
   * Safe patterns - allowlist enforced or execution blocked (hardened)
   */
  private static readonly SAFE_PATTERNS = [
    {
      pattern: /"execution_blocked"\s*:\s*true/i,
      evidence: "execution_blocked: true (secure)",
    },
    {
      pattern: /"allowlist_used"\s*:\s*true/i,
      evidence: "allowlist_used: true (secure pattern)",
    },
    {
      pattern: /"allowlist_enforced"\s*:\s*true/i,
      evidence: "allowlist_enforced: true (secure)",
    },
    {
      pattern: /"blacklist_used"\s*:\s*false/i,
      evidence: "blacklist_used: false (allowlist pattern)",
    },
    {
      pattern: /"status"\s*:\s*"pending_review"/i,
      evidence: "command stored for review (not executed)",
    },
    {
      pattern: /command.*stored.*not\s+executed/i,
      evidence: "command stored, not executed",
    },
  ];

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for blacklist bypass patterns (Issue #110, Challenge #11)
   *
   * @param response The tool response to analyze
   * @returns Analysis result with bypass detection status
   */
  analyze(response: CompatibilityCallToolResult): BlacklistBypassResult {
    const responseText = this.safeDetector.extractResponseContent(response);

    // Extract bypass method if present
    const bypassMethodMatch = responseText.match(
      /"bypass_method"\s*:\s*"([^"]+)"/i,
    );
    const bypassMethod = bypassMethodMatch ? bypassMethodMatch[1] : undefined;

    // Check for vulnerable patterns first
    for (const {
      pattern,
      evidence,
    } of BlacklistBypassAnalyzer.VULNERABLE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: true,
          bypassType: "BLACKLIST_BYPASS",
          bypassMethod,
          evidence,
        };
      }
    }

    // Check for safe patterns
    for (const { pattern, evidence } of BlacklistBypassAnalyzer.SAFE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: false,
          bypassType: "ALLOWLIST_BLOCKED",
          evidence,
        };
      }
    }

    return { detected: false, bypassType: "UNKNOWN" };
  }
}
