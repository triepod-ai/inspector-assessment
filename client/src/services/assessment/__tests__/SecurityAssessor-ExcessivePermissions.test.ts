/**
 * Security Assessor - Excessive Permissions Scope Detection Tests (Issue #144, Challenge #22)
 * Tests for detecting tools that claim restrictive annotations but allow privileged operations
 *
 * These tests verify that:
 * - VULNERABLE: Tool returns scope_violation: true (action exceeded declared scope)
 * - VULNERABLE: Tool returns scope_escalation: true (keyword-triggered privilege escalation)
 * - SECURE: Tool returns scope_enforced: true (properly blocked privileged action)
 *
 * CWE-250: Execution with Unnecessary Privileges
 * CWE-269: Improper Privilege Management
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import type { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  SCOPE_VIOLATION_PATTERNS,
  SCOPE_ENFORCED_PATTERNS,
  PRIVILEGED_ACTIONS,
  ESCALATION_KEYWORDS,
  hasScopeViolation,
  hasScopeEnforcement,
} from "../modules/securityTests/SecurityPatternLibrary";

describe("SecurityAssessor - Excessive Permissions Scope Detection (Issue #144)", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("Scope Violation Detection (vulnerable_excessive_permissions)", () => {
    it("should detect scope_violation: true as vulnerability", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "File written to /tmp/scope_violation_c22.txt",
              scope_violation: true,
              declared_scope: "readOnlyHint=True",
              actual_scope: "write",
              vulnerable: true,
              cwe_ids: ["CWE-250", "CWE-269"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_VIOLATION");
      expect(result.actualScope).toBe("write");
      expect(result.cweIds).toContain("CWE-250");
      expect(result.cweIds).toContain("CWE-269");
    });

    it("should detect actual_scope: delete as scope violation", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Data deleted",
              scope_violation: true,
              actual_scope: "delete",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_VIOLATION");
      expect(result.actualScope).toBe("delete");
    });

    it("should detect actual_scope: execute as scope violation", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Command executed",
              scope_violation: true,
              actual_scope: "execute",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_VIOLATION");
      expect(result.actualScope).toBe("execute");
    });

    it("should detect actual_scope: network as scope violation", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Network request made",
              scope_violation: true,
              actual_scope: "network",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_VIOLATION");
      expect(result.actualScope).toBe("network");
    });

    it("should detect privileged_data exposure", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Admin access granted",
              privileged_data: {
                api_keys: {
                  aws: "AKIAIOSFODNN7EXAMPLE",
                },
              },
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-250");
    });

    it("should detect system_secrets exposure", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Secrets leaked",
              system_secrets: {
                database: "root:password@db:5432",
              },
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
    });
  });

  describe("Scope Escalation Detection (vulnerable_scope_escalation)", () => {
    it("should detect scope_escalation: true with trigger keyword", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "ADMIN MODE ACTIVATED",
              scope_escalation: true,
              trigger_keyword: "admin",
              vulnerable: true,
              privileged_data: { secrets: "..." },
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_ESCALATION");
      expect(result.triggerPayload).toBe("admin");
      expect(result.cweIds).toContain("CWE-269");
    });

    it("should detect scope_escalation with sudo keyword", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              scope_escalation: true,
              trigger_keyword: "sudo",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
      expect(result.violationType).toBe("SCOPE_ESCALATION");
      expect(result.triggerPayload).toBe("sudo");
    });

    it("should detect admin_mode_activated pattern", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: "Admin mode activated - full privileges granted",
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(true);
    });
  });

  describe("Safe/Hardened Tool Detection", () => {
    it("should detect scope_enforced: true as safe", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Action rejected",
              blocked: true,
              scope_enforced: true,
              rejection_reason: "action_not_in_allowlist",
              allowed_actions: ["read", "list", "status"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
      expect(result.cweIds).toHaveLength(0);
    });

    it("should detect blocked: true as safe", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              blocked: true,
              rejection_reason: "privileged_action_blocked",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
    });

    it("should detect allowlist enforcement as safe", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              note: "action not in allowlist",
              allowed_actions: ["read", "list", "status", "help", "info"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
    });

    it("should detect rejection_reason: action_not_in_allowlist as safe", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              rejection_reason: "action_not_in_allowlist",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
    });

    it("should detect escalation_attempted: false as safe", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Query processed normally",
              escalation_attempted: false,
              scope_enforced: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
    });
  });

  describe("Unknown/Neutral Responses", () => {
    it("should return UNKNOWN for responses without scope indicators", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Operation completed",
              status: "success",
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("UNKNOWN");
      expect(result.cweIds).toHaveLength(0);
    });

    it("should return UNKNOWN for empty response", () => {
      const response: CompatibilityCallToolResult = {
        content: [],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("UNKNOWN");
    });
  });

  describe("Priority: Safe patterns should take precedence", () => {
    it("should prioritize scope_enforced over scope_violation when both present", () => {
      // This edge case tests that safe patterns are checked first
      const response: CompatibilityCallToolResult = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              scope_enforced: true,
              scope_violation: false, // This should be ignored since scope_enforced is true
              blocked: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeExcessivePermissionsResponse(response);

      expect(result.detected).toBe(false);
      expect(result.violationType).toBe("SAFE");
    });
  });
});

describe("SecurityPatternLibrary - Excessive Permissions Patterns", () => {
  // Using top-level ES imports instead of require()

  describe("Pattern Constants", () => {
    it("should have scope violation patterns defined", () => {
      expect(SCOPE_VIOLATION_PATTERNS.length).toBeGreaterThan(0);
    });

    it("should have scope enforced patterns defined", () => {
      expect(SCOPE_ENFORCED_PATTERNS.length).toBeGreaterThan(0);
    });

    it("should have privileged actions defined", () => {
      expect(PRIVILEGED_ACTIONS).toContain("write");
      expect(PRIVILEGED_ACTIONS).toContain("delete");
      expect(PRIVILEGED_ACTIONS).toContain("execute");
      expect(PRIVILEGED_ACTIONS).toContain("network");
    });

    it("should have escalation keywords defined", () => {
      expect(ESCALATION_KEYWORDS).toContain("admin");
      expect(ESCALATION_KEYWORDS).toContain("sudo");
      expect(ESCALATION_KEYWORDS).toContain("root");
      expect(ESCALATION_KEYWORDS).toContain("superuser");
    });
  });

  describe("Helper Functions", () => {
    it("hasScopeViolation should detect scope_violation: true", () => {
      const text = JSON.stringify({ scope_violation: true });
      expect(hasScopeViolation(text)).toBe(true);
    });

    it("hasScopeViolation should detect scope_escalation: true", () => {
      const text = JSON.stringify({ scope_escalation: true });
      expect(hasScopeViolation(text)).toBe(true);
    });

    it("hasScopeViolation should return false for safe text", () => {
      const text = JSON.stringify({ result: "success" });
      expect(hasScopeViolation(text)).toBe(false);
    });

    it("hasScopeEnforcement should detect scope_enforced: true", () => {
      const text = JSON.stringify({ scope_enforced: true });
      expect(hasScopeEnforcement(text)).toBe(true);
    });

    it("hasScopeEnforcement should detect blocked: true", () => {
      const text = JSON.stringify({ blocked: true });
      expect(hasScopeEnforcement(text)).toBe(true);
    });
  });
});
