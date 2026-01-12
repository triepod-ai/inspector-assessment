/**
 * Session Management Detection Tests (Issue #111, Challenge #12)
 * Tests for session management vulnerability detection:
 * - CWE-384: Session Fixation (accepts external session ID, no regeneration)
 * - CWE-330: Predictable Tokens (session_{user}_{timestamp}_{counter})
 * - CWE-613: No Session Timeout (expires_at: null, timeout_checked: false)
 * - CWE-200: ID Exposure in URL (session_url contains session_id=)
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";

describe("Session Management Detection (Issue #111, Challenge #12)", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("CWE-384: Session Fixation Detection", () => {
    it("should detect attacker_controlled: true as session fixation", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session fixation accepted",
              session_id: "attacker_chosen_session_12345",
              attacker_controlled: true,
              fixation_url:
                "https://example.com/login?session_id=attacker_chosen_session_12345",
              vulnerable: true,
              cwe_ids: ["CWE-384"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.vulnerabilityType).toBe("SESSION_FIXATION");
      expect(result.cweIds).toContain("CWE-384");
      expect(result.evidence).toContain("attacker_controlled");
    });

    it("should detect fixed: true as session fixation", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              session_id: "fixed_session",
              fixed: true,
              user: "victim",
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.vulnerabilityType).toBe("SESSION_FIXATION");
      expect(result.cweIds).toContain("CWE-384");
    });

    it("should detect session fixation accepted message", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: "Session fixation accepted - external session ID registered",
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.vulnerabilityType).toBe("SESSION_FIXATION");
    });
  });

  describe("CWE-384: No Session Regeneration Detection", () => {
    it("should detect session_regenerated: false after login", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "User 'alice' logged in successfully",
              session_id: "session_alice_1633024800_1",
              session_regenerated: false,
              authenticated: true,
              vulnerable: true,
              cwe_ids: ["CWE-384"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      // Could be SESSION_FIXATION or NO_REGENERATION depending on order
      expect(result.cweIds).toContain("CWE-384");
    });
  });

  describe("CWE-330: Predictable Token Detection", () => {
    it("should detect exposed token_pattern", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              session_id: "session_alice_1633024800_1",
              token_pattern: "session_{user}_{timestamp}_{counter}",
              vulnerable: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-330");
    });

    it("should detect predictable session ID format", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              session_id: "session_testuser_1633024800_42",
              created: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-330");
    });
  });

  describe("CWE-613: No Session Timeout Detection", () => {
    it("should detect expires_at: null", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              session_id: "session_123",
              expires_at: null,
              created: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-613");
    });

    it("should detect timeout_checked: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session is valid",
              session_id: "session_123",
              timeout_checked: false,
              valid: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-613");
    });
  });

  describe("CWE-200: Session ID in URL Detection", () => {
    it("should detect session_url with session_id parameter", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              session_id: "session_alice_1633024800_1",
              session_url:
                "https://example.com/app?session_id=session_alice_1633024800_1",
              created: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-200");
    });

    it("should detect fixation_url with session_id parameter", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              fixation_url:
                "https://example.com/login?session_id=attacker_session",
              attacker_controlled: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      // Should have both CWE-384 (fixation) and CWE-200 (ID in URL)
      expect(result.cweIds).toContain("CWE-384");
      expect(result.cweIds).toContain("CWE-200");
    });
  });

  describe("Multiple Vulnerability Detection", () => {
    it("should detect multiple CWEs in vulnerable session response", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session created for user 'alice'",
              session_id: "session_alice_1633024800_1",
              session_url:
                "https://example.com/app?session_id=session_alice_1633024800_1",
              expires_at: null,
              token_pattern: "session_{user}_{timestamp}_{counter}",
              vulnerable: true,
              cwe_ids: ["CWE-330", "CWE-200", "CWE-613"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(true);
      // Should detect multiple CWEs
      expect(result.cweIds.length).toBeGreaterThanOrEqual(2);
      expect(result.cweIds).toContain("CWE-330"); // Predictable token
      expect(result.cweIds).toContain("CWE-613"); // No timeout
      expect(result.cweIds).toContain("CWE-200"); // ID in URL
    });
  });

  describe("Safe Pattern Detection (Hardened Server)", () => {
    it("should NOT detect vulnerability when fixation_prevented: true", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session request stored",
              fixation_prevented: true,
              token_secure: true,
              safe: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(false);
      expect(result.cweIds.length).toBe(0);
      expect(result.evidence).toContain("Secure session management");
    });

    it("should NOT detect vulnerability when timeout_enforced: true", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session valid",
              timeout_enforced: true,
              expires_at: "2024-01-01T12:00:00Z",
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability when attack_blocked: true", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Attack blocked",
              attack_blocked: true,
              blocked_reason: "Session fixation attempt prevented",
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability when regeneration_on_auth: true", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Login successful",
              regeneration_on_auth: true,
              new_session_id: "secure_random_token_xyz",
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability for completely safe session", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Session created",
              session_id: "Ym9yZXk5ZjNhMWI0Y2Q1ZTY3", // Base64-like secure token
              expires_at: "2024-01-01T12:00:00Z",
              // No vulnerable patterns present
            }),
          },
        ],
      };

      const result = analyzer.analyzeSessionManagementResponse(response);

      // No vulnerable patterns detected
      expect(result.detected).toBe(false);
    });
  });
});
