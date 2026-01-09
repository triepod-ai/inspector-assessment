/**
 * Auth Bypass Detection - Testbed Validation Tests (Issue #79)
 *
 * Validates detection against Challenge #5 ground truth:
 * - 4 fail-open tools (MUST detect): vulnerable_auth_bypass_tool, vulnerable_system_exec_tool,
 *   vulnerable_config_modifier_tool, vulnerable_file_reader_tool
 * - 3 fail-closed tools (MUST NOT flag): vulnerable_data_leak_tool, vulnerable_fetcher_tool,
 *   safe_storage_tool_mcp
 *
 * Success criteria:
 * - 100% recall: All 4 fail-open tools detected
 * - 100% precision: 0 false positives on fail-closed tools
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import type { CompatibilityCallToolResult } from "../modules/securityTests/SecurityPayloadTester";

describe("Auth Bypass Detection - Challenge #5 Testbed Validation", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  /**
   * Helper to create mock response
   */
  function createMockResponse(
    jsonContent: Record<string, unknown>,
  ): CompatibilityCallToolResult {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(jsonContent),
        },
      ],
    } as CompatibilityCallToolResult;
  }

  describe("Fail-Open Tools (MUST detect)", () => {
    it("should detect vulnerable_auth_bypass_tool fail-open pattern", () => {
      const response = createMockResponse({
        result: "Action 'test' executed successfully",
        action_performed: "test",
        auth_status: "bypassed",
        auth_error:
          "AuthServiceTimeout: Connection to auth server timed out after 30s",
        auth_error_type: "timeout",
        auth_type: "fail-open",
        vulnerable: true,
        evidence:
          "Fail-open auth: timeout - access granted despite authentication failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
      expect(result.evidence).toContain("fail-open");
    });

    it("should detect vulnerable_system_exec_tool fail-open pattern", () => {
      const response = createMockResponse({
        result: "Command 'ls' executed despite auth failure",
        auth_status: "bypassed",
        auth_error:
          "AuthServiceException: Authentication service raised an exception",
        auth_type: "fail-open",
        vulnerable: true,
        evidence:
          "Fail-open auth: exception - access granted despite authentication failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });

    it("should detect vulnerable_config_modifier_tool fail-open pattern", () => {
      const response = createMockResponse({
        result: "Setting 'debug=true' stored despite auth failure",
        auth_status: "bypassed",
        auth_error:
          "AuthServiceNetworkError: Unable to reach authentication server",
        auth_type: "fail-open",
        vulnerable: true,
        evidence:
          "Fail-open auth: network_error - access granted despite authentication failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });

    it("should detect vulnerable_file_reader_tool fail-open pattern", () => {
      const response = createMockResponse({
        result: "Path '/etc/passwd' stored for validation despite auth failure",
        auth_status: "bypassed",
        auth_error:
          "AuthServiceCertError: TLS certificate validation failed for auth server",
        auth_type: "fail-open",
        vulnerable: true,
        evidence:
          "Fail-open auth: cert_error - access granted despite authentication failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });

    it("should detect fail-open even without vulnerable flag", () => {
      // Some fail-open implementations might not set vulnerable: true
      const response = createMockResponse({
        result: "Action executed",
        auth_status: "bypassed",
        auth_type: "fail-open",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });
  });

  describe("Fail-Closed Tools (MUST NOT flag)", () => {
    it("should NOT flag vulnerable_data_leak_tool as auth bypass", () => {
      const response = createMockResponse({
        result: "Access denied",
        auth_status: "denied",
        denial_reason:
          "AuthServiceTimeout: Connection to auth server timed out - access denied",
        auth_type: "fail-closed",
        vulnerable: false,
        note: "Fail-closed auth: Access properly denied on auth failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("FAIL_CLOSED");
      expect(result.evidence).toContain("fail-closed");
    });

    it("should NOT flag vulnerable_fetcher_tool as auth bypass", () => {
      const response = createMockResponse({
        result: "Access denied",
        auth_status: "denied",
        denial_reason:
          "AuthServiceException: Authentication service exception - access denied",
        auth_type: "fail-closed",
        vulnerable: false,
        note: "Fail-closed auth: Access properly denied on auth failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("FAIL_CLOSED");
    });

    it("should NOT flag safe_storage_tool_mcp as auth bypass", () => {
      const response = createMockResponse({
        result: "Access denied",
        auth_status: "denied",
        denial_reason:
          "AuthServiceNetworkError: Network error during authentication - access denied",
        auth_type: "fail-closed",
        vulnerable: false,
        note: "Fail-closed auth: Access properly denied on auth failure",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("FAIL_CLOSED");
    });
  });

  describe("False Positive Prevention (Issue #79)", () => {
    it("should NOT flag data leak tool with vulnerable: true but secure auth", () => {
      // This is the key false positive case from Issue #79
      // Tool is vulnerable to DATA LEAK but has SECURE fail-closed auth
      const response = createMockResponse({
        result: "Found secrets: {...}",
        vulnerable: true,
        evidence: "Tool leaked sensitive environment variables",
        // Note: NO auth_status, NO auth_type - this is a data leak, not auth bypass
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      // Should NOT detect as auth bypass because there's no auth context
      expect(result.detected).toBe(false);
    });

    it("should NOT flag SSRF-vulnerable tool with vulnerable: true but secure auth", () => {
      const response = createMockResponse({
        result: "Fetched content from internal URL",
        vulnerable: true,
        evidence: "SSRF vulnerability detected",
        // No auth context - this is SSRF, not auth bypass
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
    });

    it("should flag vulnerable: true ONLY when auth context is present", () => {
      // vulnerable: true WITH auth context should be flagged
      const response = createMockResponse({
        result: "Action executed",
        vulnerable: true,
        auth_status: "bypassed",
        auth_error: "Auth failed but access was granted",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty response", () => {
      const response = createMockResponse({});
      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("UNKNOWN");
    });

    it("should handle non-auth response", () => {
      const response = createMockResponse({
        result: "Successfully calculated: 42",
        status: "success",
      });
      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("UNKNOWN");
    });

    it("should prefer auth_type over auth_status for detection", () => {
      // auth_type is more specific than auth_status
      const response = createMockResponse({
        auth_type: "fail-open",
        auth_status: "bypassed",
      });

      const result = analyzer.analyzeAuthBypassResponse(response);
      expect(result.detected).toBe(true);
      expect(result.evidence).toContain("auth_type");
    });
  });
});
