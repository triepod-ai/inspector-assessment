/**
 * Excessive Permissions Analyzer (Issue #144, Challenge #22)
 * Detects when tools exceed their declared annotation scope
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  SCOPE_VIOLATION_PATTERNS,
  SCOPE_ENFORCED_PATTERNS,
} from "../SecurityPatternLibrary";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of excessive permissions scope analysis (Issue #144, Challenge #22)
 * Detects when tools exceed their declared annotation scope:
 * - CWE-250: Execution with Unnecessary Privileges (scope violation)
 * - CWE-269: Improper Privilege Management (scope escalation)
 */
export interface ExcessivePermissionsScopeResult {
  detected: boolean;
  violationType:
    | "SCOPE_VIOLATION" // Tool performed write/delete/execute despite readOnlyHint=True
    | "SCOPE_ESCALATION" // Keyword triggered hidden admin mode
    | "SAFE" // Tool properly enforced scope restrictions
    | "UNKNOWN";
  actualScope?: string; // e.g., "write", "delete", "execute", "network"
  triggerPayload?: string; // e.g., "admin", "write_file"
  cweIds: string[];
  evidence?: string;
}

/**
 * Analyzes responses for excessive permissions scope violations
 *
 * Detects when tools exceed their declared annotation scope:
 * - scope_violation: Tool performed privileged action despite restrictive annotations
 * - scope_escalation: Keyword triggered hidden admin/privilege mode
 * - scope_enforced: Tool properly blocked the privileged action (safe)
 *
 * CWE-250: Execution with Unnecessary Privileges
 * CWE-269: Improper Privilege Management
 */
export class ExcessivePermissionsAnalyzer {
  private safeDetector: SafeResponseDetector;

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for excessive permissions scope violations (Issue #144, Challenge #22)
   */
  analyze(
    response: CompatibilityCallToolResult,
  ): ExcessivePermissionsScopeResult {
    const responseText = this.safeDetector.extractResponseContent(response);
    const cweIds: string[] = [];

    // Check for safe/hardened patterns first (scope enforced)
    for (const { pattern, evidence } of SCOPE_ENFORCED_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: false,
          violationType: "SAFE",
          cweIds: [],
          evidence,
        };
      }
    }

    // Check for scope violation patterns
    for (const { pattern, evidence } of SCOPE_VIOLATION_PATTERNS) {
      if (pattern.test(responseText)) {
        // Determine specific violation type based on pattern
        if (/"scope_escalation"\s*:\s*true/i.test(responseText)) {
          // Scope escalation - keyword-triggered privilege escalation
          cweIds.push("CWE-269");

          // Extract trigger keyword if present
          const keywordMatch = responseText.match(
            /"trigger_keyword"\s*:\s*"([^"]+)"/i,
          );
          const triggerPayload = keywordMatch?.[1];

          return {
            detected: true,
            violationType: "SCOPE_ESCALATION",
            triggerPayload,
            cweIds,
            evidence,
          };
        }

        if (/"scope_violation"\s*:\s*true/i.test(responseText)) {
          // Scope violation - action exceeded declared scope
          cweIds.push("CWE-250", "CWE-269");

          // Extract actual scope if present
          const scopeMatch = responseText.match(
            /"actual_scope"\s*:\s*"([^"]+)"/i,
          );
          const actualScope = scopeMatch?.[1];

          return {
            detected: true,
            violationType: "SCOPE_VIOLATION",
            actualScope,
            cweIds,
            evidence,
          };
        }

        // Generic detection (privileged_data, system_secrets, admin_mode_activated)
        cweIds.push("CWE-250", "CWE-269");
        return {
          detected: true,
          violationType: "SCOPE_VIOLATION",
          cweIds,
          evidence,
        };
      }
    }

    // No scope violation or enforcement detected
    return {
      detected: false,
      violationType: "UNKNOWN",
      cweIds: [],
    };
  }
}
