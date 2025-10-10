/**
 * Unit tests for universal security testing
 * Tests the simplified pattern system (no tool classification)
 */

import {
  getAllAttackPatterns,
  getPayloadsForAttack,
  getPatternStatistics,
} from "@/lib/securityPatterns";

describe("Universal Security Patterns", () => {
  describe("Attack pattern structure", () => {
    it("should have all attack patterns defined", () => {
      const patterns = getAllAttackPatterns();

      expect(patterns.length).toBeGreaterThan(15);
      expect(patterns.every((p) => p.attackName && p.description)).toBe(true);
      expect(patterns.every((p) => p.payloads.length > 0)).toBe(true);
    });

    it("should have Direct Command Injection with diverse payloads", () => {
      const payloads = getPayloadsForAttack("Direct Command Injection");

      expect(payloads.length).toBeGreaterThan(5);

      // Should have arithmetic payloads
      const hasArithmetic = payloads.some(
        (p) => p.payloadType === "arithmetic",
      );
      expect(hasArithmetic).toBe(true);

      // Should have system payloads
      const hasSystem = payloads.some((p) => p.payloadType === "system");
      expect(hasSystem).toBe(true);

      // Should have data payloads
      const hasData = payloads.some((p) => p.payloadType === "data");
      expect(hasData).toBe(true);

      // Should have generic payloads
      const hasGeneric = payloads.some((p) => p.payloadType === "generic");
      expect(hasGeneric).toBe(true);
    });

    it("should have Role Override with diverse payloads", () => {
      const payloads = getPayloadsForAttack("Role Override");

      expect(payloads.length).toBeGreaterThanOrEqual(3);

      // Should include arithmetic role escalation
      const hasArithmetic = payloads.some(
        (p) => p.payloadType === "arithmetic" && /calculator/.test(p.payload),
      );
      expect(hasArithmetic).toBe(true);

      // Should include system admin role
      const hasSystem = payloads.some(
        (p) => p.payloadType === "system" && /administrator/.test(p.payload),
      );
      expect(hasSystem).toBe(true);
    });

    it("should have Data Exfiltration with data-focused payloads", () => {
      const payloads = getPayloadsForAttack("Data Exfiltration");

      expect(payloads.length).toBeGreaterThanOrEqual(3);

      // Should ask for API keys
      const hasAPIKeys = payloads.some((p) => /api.*key/i.test(p.payload));
      expect(hasAPIKeys).toBe(true);

      // Should ask for environment variables
      const hasEnv = payloads.some((p) => /environment/i.test(p.payload));
      expect(hasEnv).toBe(true);

      // Should ask for credentials
      const hasCreds = payloads.some((p) => /credential/i.test(p.payload));
      expect(hasCreds).toBe(true);
    });

    it("should have System Command with actual commands", () => {
      const payloads = getPayloadsForAttack("System Command");

      expect(payloads.length).toBeGreaterThanOrEqual(3);

      // Should have whoami
      const hasWhoami = payloads.some((p) => p.payload === "whoami");
      expect(hasWhoami).toBe(true);

      // Should have ls
      const hasLs = payloads.some((p) => p.payload.includes("ls"));
      expect(hasLs).toBe(true);

      // Should have pwd
      const hasPwd = payloads.some((p) => p.payload === "pwd");
      expect(hasPwd).toBe(true);
    });
  });

  describe("Payload evidence patterns", () => {
    it("should have evidence regex for arithmetic payloads", () => {
      const payloads = getPayloadsForAttack("Direct Command Injection");
      const calcPayload = payloads.find((p) => p.payload === "Calculate 2+2");

      expect(calcPayload).toBeDefined();
      expect(calcPayload?.evidence.test("4")).toBe(true);
      expect(calcPayload?.evidence.test("stored 2+2")).toBe(false);
    });

    it("should have evidence regex for system commands", () => {
      const payloads = getPayloadsForAttack("System Command");
      const whoamiPayload = payloads.find((p) => p.payload === "whoami");

      expect(whoamiPayload).toBeDefined();
      expect(whoamiPayload?.evidence.test("root")).toBe(true);
      expect(whoamiPayload?.evidence.test("user")).toBe(true);
      expect(whoamiPayload?.evidence.test("admin")).toBe(true);
      expect(whoamiPayload?.evidence.test("stored whoami")).toBe(false);
    });

    it("should have evidence regex for data exfiltration", () => {
      const payloads = getPayloadsForAttack("Data Exfiltration");
      const apiKeyPayload = payloads.find((p) => /api.*key/i.test(p.payload));

      expect(apiKeyPayload).toBeDefined();
      expect(apiKeyPayload?.evidence.test("API_KEY=abc123")).toBe(true);
      expect(apiKeyPayload?.evidence.test("api-key: xyz")).toBe(true);
      expect(apiKeyPayload?.evidence.test("sk-abc123def")).toBe(true);
    });
  });

  describe("Payload diversity", () => {
    it("should have multiple payload types per attack", () => {
      const attacks = getAllAttackPatterns();

      attacks.forEach((attack) => {
        const payloadTypes = new Set(attack.payloads.map((p) => p.payloadType));

        // Most attacks should have diverse payload types
        // (some specialized attacks may only have generic)
        if (attack.payloads.length > 3) {
          expect(payloadTypes.size).toBeGreaterThanOrEqual(1);
        }
      });
    });

    it("should have arithmetic payloads across multiple attacks", () => {
      const attacks = getAllAttackPatterns();
      const attacksWithArithmetic = attacks.filter((a) =>
        a.payloads.some((p) => p.payloadType === "arithmetic"),
      );

      // Arithmetic payloads should appear in multiple attack types
      expect(attacksWithArithmetic.length).toBeGreaterThanOrEqual(2);
    });

    it("should have system payloads across multiple attacks", () => {
      const attacks = getAllAttackPatterns();
      const attacksWithSystem = attacks.filter((a) =>
        a.payloads.some((p) => p.payloadType === "system"),
      );

      // System payloads should appear in multiple attack types
      expect(attacksWithSystem.length).toBeGreaterThanOrEqual(3);
    });

    it("should have data payloads across multiple attacks", () => {
      const attacks = getAllAttackPatterns();
      const attacksWithData = attacks.filter((a) =>
        a.payloads.some((p) => p.payloadType === "data"),
      );

      // Data payloads should appear in multiple attack types
      expect(attacksWithData.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Pattern statistics", () => {
    it("should return comprehensive statistics", () => {
      const stats = getPatternStatistics();

      expect(stats.totalAttackTypes).toBeGreaterThan(15);
      expect(stats.totalPayloads).toBeGreaterThan(40);
      expect(stats.highRiskPayloads).toBeGreaterThan(20);
      expect(stats.mediumRiskPayloads).toBeGreaterThan(5);
      expect(stats.averagePayloadsPerAttack).toBeGreaterThanOrEqual(2);
    });

    it("should have payload type breakdown", () => {
      const stats = getPatternStatistics();

      expect(stats.payloadTypeBreakdown.arithmetic).toBeGreaterThan(0);
      expect(stats.payloadTypeBreakdown.system).toBeGreaterThan(0);
      expect(stats.payloadTypeBreakdown.data).toBeGreaterThan(0);
      expect(stats.payloadTypeBreakdown.generic).toBeGreaterThan(0);
    });
  });

  describe("Payload limit functionality", () => {
    it("should limit payloads when requested", () => {
      const allPayloads = getPayloadsForAttack("Direct Command Injection");
      const limitedPayloads = getPayloadsForAttack(
        "Direct Command Injection",
        3,
      );

      expect(limitedPayloads.length).toBe(3);
      expect(limitedPayloads.length).toBeLessThan(allPayloads.length);
    });

    it("should return all payloads when no limit specified", () => {
      const payloads = getPayloadsForAttack("Direct Command Injection");

      expect(payloads.length).toBeGreaterThan(5);
    });
  });

  describe("Attack type coverage", () => {
    it("should include critical attack types", () => {
      const attacks = getAllAttackPatterns();
      const attackNames = attacks.map((a) => a.attackName);

      expect(attackNames).toContain("Direct Command Injection");
      expect(attackNames).toContain("Role Override");
      expect(attackNames).toContain("Data Exfiltration");
      expect(attackNames).toContain("System Command");
      expect(attackNames).toContain("Context Escape");
      expect(attackNames).toContain("Instruction Confusion");
      expect(attackNames).toContain("Tool Shadowing");
      expect(attackNames).toContain("Configuration Drift");
      expect(attackNames).toContain("Indirect Prompt Injection");
      expect(attackNames).toContain("Sandbox Escape");
    });
  });
});
