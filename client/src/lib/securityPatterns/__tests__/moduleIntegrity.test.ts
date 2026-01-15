/**
 * Security Patterns Module Integrity Tests
 *
 * Verifies that the modularized security patterns maintain
 * the same structure, counts, and order as the original monolithic file.
 *
 * Issue #163: Modularize securityPatterns.ts by attack category
 */

import {
  SECURITY_ATTACK_PATTERNS,
  getPayloadsForAttack,
  getAllAttackPatterns,
  getPatternStatistics,
  INJECTION_PATTERNS,
  VALIDATION_PATTERNS,
  TOOL_SPECIFIC_PATTERNS,
  RESOURCE_EXHAUSTION_PATTERNS,
  AUTH_SESSION_PATTERNS,
  ADVANCED_EXPLOIT_PATTERNS,
} from "../index";

describe("Security Patterns Module Integrity", () => {
  describe("Pattern Counts", () => {
    it("should have exactly 32 attack patterns", () => {
      expect(SECURITY_ATTACK_PATTERNS.length).toBe(32);
    });

    it("should have correct pattern count per module", () => {
      expect(INJECTION_PATTERNS.length).toBe(6);
      expect(VALIDATION_PATTERNS.length).toBe(5);
      expect(TOOL_SPECIFIC_PATTERNS.length).toBe(7);
      expect(RESOURCE_EXHAUSTION_PATTERNS.length).toBe(2);
      expect(AUTH_SESSION_PATTERNS.length).toBe(5);
      expect(ADVANCED_EXPLOIT_PATTERNS.length).toBe(7);
    });

    it("should aggregate to total of 32 patterns", () => {
      const total =
        INJECTION_PATTERNS.length +
        VALIDATION_PATTERNS.length +
        TOOL_SPECIFIC_PATTERNS.length +
        RESOURCE_EXHAUSTION_PATTERNS.length +
        AUTH_SESSION_PATTERNS.length +
        ADVANCED_EXPLOIT_PATTERNS.length;
      expect(total).toBe(32);
    });
  });

  describe("Pattern Order", () => {
    it("should maintain original pattern order - first pattern is Command Injection", () => {
      expect(SECURITY_ATTACK_PATTERNS[0].attackName).toBe("Command Injection");
    });

    it("should maintain original pattern order - last pattern is Excessive Permissions Scope", () => {
      expect(SECURITY_ATTACK_PATTERNS[31].attackName).toBe(
        "Excessive Permissions Scope",
      );
    });

    it("should maintain module boundary order", () => {
      // Injection patterns first (0-5)
      expect(SECURITY_ATTACK_PATTERNS[0].attackName).toBe("Command Injection");
      expect(SECURITY_ATTACK_PATTERNS[5].attackName).toBe("NoSQL Injection");

      // Validation patterns next (6-10)
      expect(SECURITY_ATTACK_PATTERNS[6].attackName).toBe("Type Safety");
      expect(SECURITY_ATTACK_PATTERNS[10].attackName).toBe("Timeout Handling");

      // Tool-specific patterns (11-17)
      expect(SECURITY_ATTACK_PATTERNS[11].attackName).toBe(
        "Indirect Prompt Injection",
      );
      expect(SECURITY_ATTACK_PATTERNS[17].attackName).toBe("Tool Shadowing");

      // Resource exhaustion patterns (18-19)
      expect(SECURITY_ATTACK_PATTERNS[18].attackName).toBe(
        "DoS/Resource Exhaustion",
      );
      expect(SECURITY_ATTACK_PATTERNS[19].attackName).toBe(
        "Insecure Deserialization",
      );

      // Auth/Session patterns (20-24)
      expect(SECURITY_ATTACK_PATTERNS[20].attackName).toBe("Token Theft");
      expect(SECURITY_ATTACK_PATTERNS[24].attackName).toBe(
        "Session Management",
      );

      // Advanced exploit patterns (25-31)
      expect(SECURITY_ATTACK_PATTERNS[25].attackName).toBe(
        "Cross-Tool State Bypass",
      );
      expect(SECURITY_ATTACK_PATTERNS[31].attackName).toBe(
        "Excessive Permissions Scope",
      );
    });
  });

  describe("Payload Counts", () => {
    it("should have payloads in all patterns", () => {
      SECURITY_ATTACK_PATTERNS.forEach((pattern) => {
        expect(pattern.payloads.length).toBeGreaterThan(0);
      });
    });

    it("should have total payloads matching statistics", () => {
      const stats = getPatternStatistics();
      const manualCount = SECURITY_ATTACK_PATTERNS.reduce(
        (sum, pattern) => sum + pattern.payloads.length,
        0,
      );
      expect(stats.totalPayloads).toBe(manualCount);
    });

    it("should have exactly 184 total payloads", () => {
      // Explicit count assertion to catch unintended payload additions/removals
      // Issue #163: Locks in expected payload count after modularization
      const totalPayloads = SECURITY_ATTACK_PATTERNS.reduce(
        (sum, pattern) => sum + pattern.payloads.length,
        0,
      );
      expect(totalPayloads).toBe(184);
    });

    it("should have risk level distribution", () => {
      const stats = getPatternStatistics();
      expect(stats.highRiskPayloads).toBeGreaterThan(0);
      expect(stats.mediumRiskPayloads).toBeGreaterThan(0);
      expect(stats.lowRiskPayloads).toBeGreaterThan(0);
      expect(
        stats.highRiskPayloads +
          stats.mediumRiskPayloads +
          stats.lowRiskPayloads,
      ).toBe(stats.totalPayloads);
    });
  });

  describe("Utility Functions", () => {
    it("getAllAttackPatterns should return all patterns", () => {
      expect(getAllAttackPatterns().length).toBe(32);
    });

    it("getPayloadsForAttack should return payloads for known attack", () => {
      const payloads = getPayloadsForAttack("Command Injection");
      expect(payloads.length).toBe(5);
    });

    it("getPayloadsForAttack should return empty array for unknown attack", () => {
      const payloads = getPayloadsForAttack("Unknown Attack");
      expect(payloads.length).toBe(0);
    });

    it("getPayloadsForAttack should respect limit parameter", () => {
      const payloads = getPayloadsForAttack("Command Injection", 2);
      expect(payloads.length).toBe(2);
    });

    it("getPatternStatistics should return valid statistics", () => {
      const stats = getPatternStatistics();
      expect(stats.totalAttackTypes).toBe(32);
      expect(stats.averagePayloadsPerAttack).toBeGreaterThan(0);
      expect(Object.keys(stats.payloadTypeBreakdown).length).toBeGreaterThan(0);
    });
  });

  describe("Pattern Structure", () => {
    it("all patterns should have required fields", () => {
      SECURITY_ATTACK_PATTERNS.forEach((pattern) => {
        expect(pattern.attackName).toBeDefined();
        expect(pattern.description).toBeDefined();
        expect(pattern.payloads).toBeDefined();
        expect(Array.isArray(pattern.payloads)).toBe(true);
      });
    });

    it("all payloads should have required fields", () => {
      SECURITY_ATTACK_PATTERNS.forEach((pattern) => {
        pattern.payloads.forEach((payload) => {
          expect(payload.payload).toBeDefined();
          expect(payload.evidence).toBeDefined();
          expect(payload.evidence instanceof RegExp).toBe(true);
          expect(payload.riskLevel).toBeDefined();
          expect(["HIGH", "MEDIUM", "LOW"]).toContain(payload.riskLevel);
          expect(payload.description).toBeDefined();
          expect(payload.payloadType).toBeDefined();
        });
      });
    });
  });
});
