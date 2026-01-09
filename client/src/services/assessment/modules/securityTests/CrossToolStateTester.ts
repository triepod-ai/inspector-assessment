/**
 * Cross-Tool State Tester
 * Tests for privilege escalation by calling tools in sequence
 *
 * Issue #92, Challenge #7: Cross-tool state-based authorization bypass
 * Detects when one tool can modify shared state that affects another tool's authorization.
 *
 * Attack flow:
 * 1. Call admin_action → should get "access denied"
 * 2. Call config_modifier with "admin_mode=true"
 * 3. Call admin_action again → if now succeeds, VULNERABLE
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ProgressCallback } from "@/lib/assessment/progressTypes";

/**
 * Function type for calling MCP tools
 */
export type CallToolFunction = (
  name: string,
  params: Record<string, unknown>,
) => Promise<CompatibilityCallToolResult>;

/**
 * Result of cross-tool privilege escalation test
 */
export interface CrossToolTestResult {
  vulnerable: boolean;
  reason:
    | "privilege_escalation_confirmed"
    | "escalation_blocked"
    | "baseline_has_access"
    | "modifier_rejected"
    | "test_error";
  evidence?: {
    baseline: string;
    afterModifier: string;
    enableResult?: string;
  };
  error?: string;
}

/**
 * Identified tool pair for cross-tool testing
 */
export interface ToolPair {
  admin: Tool;
  modifier: Tool;
}

/**
 * Configuration for cross-tool state testing
 */
export interface CrossToolTestConfig {
  /** Timeout for each tool call in ms (default: 5000) */
  timeout?: number;
  /** Enable verbose logging */
  verbose?: boolean;
}

/**
 * Tests for cross-tool privilege escalation via shared mutable state
 */
export class CrossToolStateTester {
  private readonly verbose: boolean;

  constructor(config: CrossToolTestConfig = {}) {
    // Note: config.timeout is accepted but tool call timeout is handled externally
    this.verbose = config.verbose ?? false;
  }

  /**
   * Log message if verbose logging is enabled
   */
  private log(message: string): void {
    if (this.verbose) {
      console.log(`[CrossToolStateTester] ${message}`);
    }
  }

  /**
   * Identify potential cross-tool pairs for testing
   * Looks for admin_action/privileged tools and config_modifier/setting tools
   */
  identifyCrossToolPairs(tools: Tool[]): ToolPair[] {
    const pairs: ToolPair[] = [];

    // Find admin-like tools (tools that check authorization)
    const adminTools = tools.filter(
      (t) =>
        /admin[_-]?action|privileged|elevated|sensitive/i.test(t.name) ||
        /admin[_-]?action|privileged|requires\s+admin/i.test(
          t.description || "",
        ),
    );

    // Find modifier-like tools (tools that modify state/config)
    const modifierTools = tools.filter(
      (t) =>
        /config[_-]?modifier|setting|mode|enable|activate/i.test(t.name) ||
        /modify.*config|set.*mode|enable.*admin/i.test(t.description || ""),
    );

    for (const admin of adminTools) {
      for (const modifier of modifierTools) {
        if (admin.name !== modifier.name) {
          pairs.push({ admin, modifier });
        }
      }
    }

    return pairs;
  }

  /**
   * Test cross-tool privilege escalation
   *
   * Attack flow:
   * 1. Call admin_action → expect "access denied"
   * 2. Call config_modifier with "admin_mode=true"
   * 3. Call admin_action again → if now succeeds, VULNERABLE
   */
  async testPrivilegeEscalation(
    callTool: CallToolFunction,
    adminTool: Tool,
    modifierTool: Tool,
    onProgress?: ProgressCallback,
  ): Promise<CrossToolTestResult> {
    this.log(`Testing pair: ${modifierTool.name} → ${adminTool.name}`);

    try {
      // Step 1: Baseline - admin action should be denied
      this.log(`Step 1: Calling ${adminTool.name} (baseline)`);
      const baseline = await callTool(adminTool.name, {
        action: "read secrets",
      });
      const baselineText = this.extractResponseText(baseline);

      const baselineDenied =
        /access denied|unauthorized|admin.*required|permission.*denied/i.test(
          baselineText,
        );

      if (!baselineDenied) {
        // Already has access - can't test escalation (might indicate other issues)
        // Check if it's because shared_state_checked is false (hardened)
        if (/"shared_state_checked"\s*:\s*false/i.test(baselineText)) {
          return {
            vulnerable: false,
            reason: "baseline_has_access",
            evidence: {
              baseline: baselineText.slice(0, 500),
              afterModifier: "",
            },
          };
        }

        return {
          vulnerable: false,
          reason: "baseline_has_access",
          evidence: {
            baseline: baselineText.slice(0, 500),
            afterModifier: "",
          },
        };
      }

      // Step 2: Attempt to enable admin mode via config modifier
      const enableResult = await callTool(modifierTool.name, {
        setting: "admin_mode=true",
      });
      const enableText = this.extractResponseText(enableResult);

      const modeEnabled =
        /admin.*activated|elevated.*granted|admin_mode.*enabled|configuration.*updated.*admin/i.test(
          enableText,
        );

      // Check if modifier is hardened (stores without modifying)
      const modifierHardened =
        /stored.*without.*modifying|stored.*for.*review|not.*modifying.*runtime/i.test(
          enableText,
        );

      if (modifierHardened) {
        return {
          vulnerable: false,
          reason: "modifier_rejected",
          evidence: {
            baseline: baselineText.slice(0, 300),
            afterModifier: "",
            enableResult: enableText.slice(0, 300),
          },
        };
      }

      if (!modeEnabled) {
        return {
          vulnerable: false,
          reason: "modifier_rejected",
          evidence: {
            baseline: baselineText.slice(0, 300),
            afterModifier: "",
            enableResult: enableText.slice(0, 300),
          },
        };
      }

      // Step 3: Test if admin action now succeeds
      const escalated = await callTool(adminTool.name, {
        action: "read secrets",
      });
      const escalatedText = this.extractResponseText(escalated);

      // Check for successful escalation
      const escalationSucceeded =
        !/access denied|unauthorized|admin.*required|permission.*denied/i.test(
          escalatedText,
        ) &&
        /"secrets"|API_KEY|credentials|admin_mode.*true.*evidence.*cross-tool/i.test(
          escalatedText,
        );

      // Emit progress event if callback provided
      if (onProgress && escalationSucceeded) {
        onProgress({
          type: "vulnerability_found",
          tool: adminTool.name,
          pattern: "Cross-Tool State Bypass",
          confidence: "high",
          evidence: `Cross-tool privilege escalation: ${modifierTool.name} enables access to ${adminTool.name}. ${escalatedText.slice(0, 200)}`,
          riskLevel: "HIGH",
          requiresReview: false,
          payload: "admin_mode=true",
        });
      }

      return {
        vulnerable: escalationSucceeded,
        reason: escalationSucceeded
          ? "privilege_escalation_confirmed"
          : "escalation_blocked",
        evidence: {
          baseline: baselineText.slice(0, 300),
          afterModifier: escalatedText.slice(0, 300),
          enableResult: enableText.slice(0, 300),
        },
      };
    } catch (error) {
      return {
        vulnerable: false,
        reason: "test_error",
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Run sequence tests on all identified tool pairs
   */
  async runAllSequenceTests(
    tools: Tool[],
    callTool: CallToolFunction,
    onProgress?: ProgressCallback,
  ): Promise<Map<string, CrossToolTestResult>> {
    const pairs = this.identifyCrossToolPairs(tools);
    const results = new Map<string, CrossToolTestResult>();

    for (const { admin, modifier } of pairs) {
      const key = `${modifier.name} → ${admin.name}`;
      const result = await this.testPrivilegeEscalation(
        callTool,
        admin,
        modifier,
        onProgress,
      );
      results.set(key, result);
    }

    return results;
  }

  /**
   * Get summary of sequence test results
   */
  summarizeResults(results: Map<string, CrossToolTestResult>): {
    total: number;
    vulnerable: number;
    safe: number;
    errors: number;
    vulnerablePairs: string[];
  } {
    let vulnerable = 0;
    let safe = 0;
    let errors = 0;
    const vulnerablePairs: string[] = [];

    for (const [key, result] of results) {
      if (result.reason === "test_error") {
        errors++;
      } else if (result.vulnerable) {
        vulnerable++;
        vulnerablePairs.push(key);
      } else {
        safe++;
      }
    }

    return {
      total: results.size,
      vulnerable,
      safe,
      errors,
      vulnerablePairs,
    };
  }

  /**
   * Extract text content from MCP response
   */
  private extractResponseText(response: CompatibilityCallToolResult): string {
    if (!response) return "";

    // Handle content array format
    if (response.content && Array.isArray(response.content)) {
      return response.content
        .map((item) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object" && "text" in item)
            return String(item.text);
          return JSON.stringify(item);
        })
        .join("\n");
    }

    // Fallback to JSON stringify
    return JSON.stringify(response);
  }
}
