/**
 * Session Management Analyzer (Issue #111, Challenge #12)
 * Detects session management vulnerabilities from mcp-vulnerable-testbed
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of session management vulnerability analysis (Issue #111, Challenge #12)
 * Detects 5 session management CWEs from mcp-vulnerable-testbed:
 * - CWE-384: Session Fixation (accepts external session ID, no regeneration)
 * - CWE-330: Predictable Tokens (session_{user}_{timestamp}_{counter})
 * - CWE-613: No Session Timeout (expires_at: null, timeout_checked: false)
 * - CWE-200: ID Exposure in URL (session_url contains session_id=)
 */
export interface SessionManagementResult {
  detected: boolean;
  vulnerabilityType:
    | "SESSION_FIXATION"
    | "PREDICTABLE_TOKEN"
    | "NO_TIMEOUT"
    | "ID_IN_URL"
    | "NO_REGENERATION"
    | "UNKNOWN";
  cweIds: string[];
  evidence?: string;
}

/**
 * Analyzes responses for session management vulnerabilities
 *
 * Detects 5 CWEs from mcp-vulnerable-testbed:
 * - CWE-384: Session Fixation (accepts external session ID, no regeneration)
 * - CWE-330: Predictable Tokens (session_{user}_{timestamp}_{counter})
 * - CWE-613: No Session Timeout (expires_at: null, timeout_checked: false)
 * - CWE-200: ID Exposure in URL (session_url contains session_id=)
 */
export class SessionManagementAnalyzer {
  private safeDetector: SafeResponseDetector;

  /**
   * Safe patterns (hardened server)
   */
  private static readonly SAFE_PATTERNS = [
    {
      pattern: /"fixation_prevented"\s*:\s*true/i,
      name: "fixation_prevented",
    },
    { pattern: /"token_secure"\s*:\s*true/i, name: "token_secure" },
    { pattern: /"timeout_enforced"\s*:\s*true/i, name: "timeout_enforced" },
    { pattern: /"id_in_url"\s*:\s*false/i, name: "id_in_url: false" },
    {
      pattern: /"regeneration_on_auth"\s*:\s*true/i,
      name: "regeneration_on_auth",
    },
    { pattern: /"attack_blocked"\s*:\s*true/i, name: "attack_blocked" },
    { pattern: /"cwe_384_mitigated"\s*:\s*true/i, name: "cwe_384_mitigated" },
  ];

  /**
   * CWE-384: Session Fixation patterns
   */
  private static readonly FIXATION_PATTERNS = [
    {
      pattern: /"attacker_controlled"\s*:\s*true/i,
      evidence: "attacker_controlled: true (session fixation)",
    },
    {
      pattern: /"fixed"\s*:\s*true/i,
      evidence: "fixed: true (fixated session)",
    },
    {
      pattern: /session\s*fixation\s*accepted/i,
      evidence: "session fixation attack accepted",
    },
    {
      pattern: /"fixation_url"\s*:/i,
      evidence: "fixation_url present (attack vector)",
    },
  ];

  /**
   * CWE-330: Predictable Token patterns
   */
  private static readonly PREDICTABLE_PATTERNS = [
    {
      pattern:
        /"token_pattern"\s*:\s*"session_\{user\}_\{timestamp\}_\{counter\}"/i,
      evidence:
        "Predictable token pattern exposed: session_{user}_{timestamp}_{counter}",
    },
    {
      pattern: /"session_id"\s*:\s*"session_[a-z0-9]+_\d{9,}_\d+"/i,
      evidence: "Predictable session ID format detected",
    },
  ];

  /**
   * CWE-613: No Session Timeout patterns
   */
  private static readonly NO_TIMEOUT_PATTERNS = [
    {
      pattern: /"expires_at"\s*:\s*null/i,
      evidence: "expires_at: null (sessions never expire)",
    },
    {
      pattern: /"timeout_checked"\s*:\s*false/i,
      evidence: "timeout_checked: false (no expiration validation)",
    },
  ];

  /**
   * CWE-200: Session ID in URL patterns
   */
  private static readonly ID_IN_URL_PATTERNS = [
    {
      pattern: /"session_url"\s*:\s*"[^"]*[?&]session_id=/i,
      evidence: "Session ID exposed in URL query parameter",
    },
    {
      pattern: /"fixation_url"\s*:\s*"[^"]*[?&]session_id=/i,
      evidence: "Session ID exposed in fixation URL",
    },
  ];

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for session management vulnerabilities (Issue #111, Challenge #12)
   *
   * @param response The tool response to analyze
   * @returns Analysis result with session management detection status
   */
  analyze(response: CompatibilityCallToolResult): SessionManagementResult {
    const responseText = this.safeDetector.extractResponseContent(response);
    const cweIds: string[] = [];
    let vulnerabilityType: SessionManagementResult["vulnerabilityType"] =
      "UNKNOWN";
    let evidence: string | undefined;

    // Check for safe patterns first (hardened server)
    for (const { pattern, name } of SessionManagementAnalyzer.SAFE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: false,
          vulnerabilityType: "UNKNOWN",
          cweIds: [],
          evidence: `Secure session management: ${name}`,
        };
      }
    }

    // CWE-384: Session Fixation (external ID accepted)
    for (const {
      pattern,
      evidence: evidenceText,
    } of SessionManagementAnalyzer.FIXATION_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-384")) cweIds.push("CWE-384");
        vulnerabilityType = "SESSION_FIXATION";
        evidence = evidenceText;
        break;
      }
    }

    // CWE-384: No Regeneration after authentication
    if (/"session_regenerated"\s*:\s*false/i.test(responseText)) {
      if (!cweIds.includes("CWE-384")) cweIds.push("CWE-384");
      if (vulnerabilityType === "UNKNOWN") {
        vulnerabilityType = "NO_REGENERATION";
        evidence = "session_regenerated: false (CWE-384)";
      }
    }

    // CWE-330: Predictable Token Pattern
    for (const {
      pattern,
      evidence: evidenceText,
    } of SessionManagementAnalyzer.PREDICTABLE_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-330")) cweIds.push("CWE-330");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "PREDICTABLE_TOKEN";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-613: No Session Timeout
    for (const {
      pattern,
      evidence: evidenceText,
    } of SessionManagementAnalyzer.NO_TIMEOUT_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-613")) cweIds.push("CWE-613");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "NO_TIMEOUT";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-200: Session ID in URL
    for (const {
      pattern,
      evidence: evidenceText,
    } of SessionManagementAnalyzer.ID_IN_URL_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-200")) cweIds.push("CWE-200");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "ID_IN_URL";
          evidence = evidenceText;
        }
        break;
      }
    }

    return {
      detected: cweIds.length > 0,
      vulnerabilityType,
      cweIds: [...new Set(cweIds)], // Dedupe
      evidence,
    };
  }
}
